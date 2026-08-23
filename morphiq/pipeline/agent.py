from __future__ import annotations
import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Optional, TypedDict

from morphiq.models import (
    LogEntry, Action, AgentDecision, LLMAssessment, AuditEvent,
    TrafficRecord, ProbeEvent, FeedbackEvent
)
from morphiq.config import Config
from morphiq.store.sqlite_store import SQLiteStore
from morphiq.llm_client import LLMClient
from morphiq.fw.firewall_controller import FirewallController

logger = logging.getLogger(__name__)

try:
    from langgraph.graph import StateGraph, END
    HAS_LANGGRAPH = True
except ImportError:
    HAS_LANGGRAPH = False

class AgentStateDict(TypedDict):
    entry: LogEntry
    traffic_history: list[TrafficRecord]
    probe_events: list[ProbeEvent]
    feedback_history: list[FeedbackEvent]
    llm_assessment: Optional[LLMAssessment]
    action: Optional[Action]
    error: Optional[str]
    node_timings: dict[str, float]

class Agent:
    def __init__(self, config: Config, store: SQLiteStore, fw: FirewallController, llm: LLMClient):
        self.config = config
        self.store = store
        self.fw = fw
        self.llm = llm
        self._graph = None

    def _build_graph(self):
        if not HAS_LANGGRAPH:
            return None
            
        workflow = StateGraph(AgentStateDict)
        workflow.add_node("investigate", self._investigate)
        workflow.add_node("reason", self._reason)
        workflow.add_node("act", self._act)
        
        workflow.set_entry_point("investigate")
        workflow.add_edge("investigate", "reason")
        workflow.add_edge("reason", "act")
        workflow.add_edge("act", END)
        
        self._graph = workflow.compile()
        return self._graph

    def _investigate(self, state: AgentStateDict) -> AgentStateDict:
        start_time = time.perf_counter()
        ip = state["entry"].effective_ip
        
        # limit via config and rules
        state["traffic_history"] = self.store.get_traffic_history(ip, limit=self.config.max_traffic_history_context)
        state["probe_events"] = self.store.get_probe_events(ip, limit=5)
        state["feedback_history"] = self.store.get_feedback_history(ip)
        
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        state["node_timings"]["investigate"] = elapsed_ms
        return state

    def _reason(self, state: AgentStateDict) -> AgentStateDict:
        start_time = time.perf_counter()
        
        if not self.llm.is_loaded:
            state["llm_assessment"] = None
            state["error"] = "LLM not loaded"
        else:
            try:
                prompt = self.llm.build_prompt(
                    state["entry"],
                    state["traffic_history"],
                    state["probe_events"],
                    state["feedback_history"]
                )
                
                try:
                    response = asyncio.run(self.llm.infer(prompt))
                except Exception as e:
                    logger.error(f"Failed inside asyncio.run for infer: {e}")
                    raise
                    
                state["llm_assessment"] = self.llm.parse_assessment(response)
                if not state["llm_assessment"]:
                    state["error"] = "Failed to parse assessment"
            except Exception as e:
                logger.error(f"Reasoning failed: {e}")
                state["llm_assessment"] = None
                state["error"] = str(e)
                
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        state["node_timings"]["reason"] = elapsed_ms
        return state

    def _act(self, state: AgentStateDict) -> AgentStateDict:
        start_time = time.perf_counter()
        
        entry = state["entry"]
        assessment = state["llm_assessment"]
        
        if assessment is None:
            state["action"] = getattr(Action, "ALLOW", "allow")
        else:
            if assessment.recommended_action == "block":
                duration = assessment.ban_duration_seconds or self.config.default_ban_duration_s
                self.fw.block(entry.effective_ip, assessment.threat_label, duration)
                state["action"] = getattr(Action, "BLOCK", "block")
            else:
                state["action"] = getattr(Action, "ALLOW", "allow")

        audit_event = AuditEvent(
            timestamp=datetime.now(timezone.utc),
            ip=entry.effective_ip,
            action=state["action"],
            threat_label=assessment.threat_label if assessment else None,
            reasoning=assessment.reasoning if assessment else ("Error: " + str(state.get("error")))
        )
        self.store.append_audit(audit_event)
        
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        state["node_timings"]["act"] = elapsed_ms
        return state

    async def run(self, entry: LogEntry) -> AgentDecision:
        state: AgentStateDict = {
            "entry": entry,
            "traffic_history": [],
            "probe_events": [],
            "feedback_history": [],
            "llm_assessment": None,
            "action": None,
            "error": None,
            "node_timings": {}
        }

        loop = asyncio.get_running_loop()
        if HAS_LANGGRAPH:
            if self._graph is None:
                self._build_graph()
            
            state = await loop.run_in_executor(None, self._graph.invoke, state)
        else:
            def _run_sequential():
                s = self._investigate(state)
                s = self._reason(s)
                return self._act(s)
            state = await loop.run_in_executor(None, _run_sequential)

        execution_trace = {
            "entry_summary": f"{entry.method} {entry.path} {entry.status}",
            "node_timings": state["node_timings"],
            "llm_used": self.llm.is_loaded
        }
        
        return AgentDecision(
            action=state["action"],
            assessment=state["llm_assessment"],
            execution_trace=execution_trace
        )
