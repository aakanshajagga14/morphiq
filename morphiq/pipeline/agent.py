from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Optional, TypedDict

from morphiq.config import Config
from morphiq.fw.firewall_controller import FirewallController
from morphiq.llm_client import LLMClient
from morphiq.models import (
    Action,
    AgentDecision,
    AuditEvent,
    FeedbackEvent,
    LLMAssessment,
    LogEntry,
    ProbeEvent,
    TrafficRecord,
)
from morphiq.store.sqlite_store import SQLiteStore

logger = logging.getLogger(__name__)

try:
    from langgraph.graph import END, StateGraph
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

    def _fallback_assessment(self, reason: str) -> LLMAssessment:
        return LLMAssessment(
            threat_label="detector_escalation",
            confidence=0.65,
            recommended_action="block",
            ban_duration_seconds=self.config.default_ban_duration_s,
            reasoning=reason,
        )

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

    async def _reason(self, state: AgentStateDict) -> AgentStateDict:
        start_time = time.perf_counter()
        
        if not self.llm.is_loaded:
            state["llm_assessment"] = self._fallback_assessment(
                "Blocked by deterministic detector fallback; LLM is disabled or unavailable."
            )
        else:
            try:
                prompt = self.llm.build_prompt(
                    state["entry"],
                    state["traffic_history"],
                    state["probe_events"],
                    state["feedback_history"]
                )
                
                response = await self.llm.infer(prompt)
                state["llm_assessment"] = self.llm.parse_assessment(response)
                if not state["llm_assessment"]:
                    state["error"] = "Failed to parse assessment"
                    state["llm_assessment"] = self._fallback_assessment(
                        "Blocked by deterministic detector fallback after an invalid LLM response."
                    )
            except Exception as e:
                logger.error(f"Reasoning failed: {e}")
                state["error"] = str(e)
                state["llm_assessment"] = self._fallback_assessment(
                    "Blocked by deterministic detector fallback after an LLM error."
                )
                
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        state["node_timings"]["reason"] = elapsed_ms
        return state

    def _act(self, state: AgentStateDict) -> AgentStateDict:
        start_time = time.perf_counter()
        
        entry = state["entry"]
        assessment = state["llm_assessment"]
        
        if assessment is None:
            state["action"] = Action.ALLOW
        else:
            if assessment.recommended_action == "block":
                duration = assessment.ban_duration_seconds or self.config.default_ban_duration_s
                if self.fw.block(
                    entry.effective_ip, assessment.threat_label, duration
                ):
                    state["action"] = Action.BLOCK
                else:
                    state["action"] = Action.ALLOW
                    state["error"] = "Firewall enforcement failed or IP is whitelisted"
            else:
                state["action"] = Action.ALLOW

        action = state["action"] or Action.ALLOW
        audit_event = AuditEvent(
            source_ip=entry.effective_ip,
            entry_raw=entry.raw_line,
            threat_label=assessment.threat_label if assessment else None,
            confidence=assessment.confidence if assessment else None,
            recommended_action=assessment.recommended_action if assessment else None,
            final_action=action.value,
            reasoning=(
                assessment.reasoning
                if assessment
                else "Allowed without LLM assessment"
            ),
            execution_trace={"node_timings": dict(state["node_timings"])},
            error=state.get("error"),
            occurred_at=datetime.now(timezone.utc),
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

        if HAS_LANGGRAPH:
            if self._graph is None:
                self._build_graph()
            state = await self._graph.ainvoke(state)
        else:
            state = self._investigate(state)
            state = await self._reason(state)
            state = self._act(state)

        execution_trace = {
            "entry_summary": f"{entry.method} {entry.path} {entry.status_code}",
            "node_timings": state["node_timings"],
            "llm_used": self.llm.is_loaded
        }
        
        return AgentDecision(
            action=state["action"] or Action.ALLOW,
            assessment=state["llm_assessment"],
            execution_trace=execution_trace
        )
