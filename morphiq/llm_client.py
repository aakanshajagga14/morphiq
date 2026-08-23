from __future__ import annotations
import asyncio
import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from morphiq.config import Config
from morphiq.models import LogEntry, TrafficRecord, ProbeEvent, FeedbackEvent, LLMAssessment

import aiohttp

logger = logging.getLogger(__name__)

class LLMClient:
    def __init__(self, config: Config):
        self.config = config
        self._is_loaded = False
        self._session: Optional[aiohttp.ClientSession] = None

    @property
    def is_loaded(self) -> bool:
        return self._is_loaded

    def load(self) -> bool:
        if not self.config.llm_enabled:
            logger.info("LLM is disabled in configuration.")
            return False

        logger.info(f"LLM Client configured to use API endpoint: {self.config.llm_base_url}")
        self._is_loaded = True
        return True

    def build_prompt(self, entry: LogEntry, history: list[TrafficRecord], probes: list[ProbeEvent], feedback: list[FeedbackEvent]) -> str:
        history_lines = "\n".join(f"{r.method} {r.path} -> {r.status}" for r in history)
        
        probe_flag = f"YES - {len(probes)} distinct paths in window" if probes else "NO"
        
        if feedback:
            fp_count = sum(1 for f in feedback if getattr(f, 'is_false_positive', False))
            tp_count = len(feedback) - fp_count
            feedback_str = f"Previous flags: {fp_count} false positives, {tp_count} confirmed threats"
        else:
            feedback_str = "None"

        schema = '{"threat_label": str, "confidence": 0-1 float, "recommended_action": "block"|"allow", "ban_duration_seconds": int|null, "reasoning": str}'

        prompt = f"""You are a security analyst evaluating web traffic for potential threats. Analyze the request and output ONLY valid JSON matching this schema:
{schema}

Request Details:
IP: {entry.effective_ip}
Method: {entry.method}
Path: {entry.path}
Query: {entry.query}
Status: {entry.status}
User-Agent: {entry.user_agent}

Recent Traffic History:
{history_lines}

Probe Activity:
{probe_flag}

Analyst Feedback:
{feedback_str}

Evaluate the request and provide your assessment in JSON format.
"""
        return prompt

    async def infer(self, prompt: str) -> str:
        if not self.is_loaded:
            raise RuntimeError("LLM is not loaded.")

        if self._session is None:
            self._session = aiohttp.ClientSession()

        url = f"{self.config.llm_base_url}/chat/completions"
        payload = {
            "messages": [
                {"role": "system", "content": "You are an expert security analyst system that analyzes web requests and returns ONLY JSON."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.1,
            "max_tokens": self.config.llm_max_tokens,
            "stream": False
        }

        try:
            async with self._session.post(url, json=payload, timeout=self.config.llm_timeout_s) as response:
                if response.status != 200:
                    text = await response.text()
                    raise RuntimeError(f"LLM API returned {response.status}: {text}")
                data = await response.json()
                return data["choices"][0]["message"]["content"]
        except Exception as e:
            logger.error(f"Error calling LLM API at {url}: {e}")
            raise

    def parse_assessment(self, response: str) -> Optional[LLMAssessment]:
        text = response.strip()
        # Clean up markdown formatting if the LLM wrapped the JSON in code blocks
        if text.startswith("```json"):
            text = text[7:]
        if text.startswith("```"):
            text = text[3:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()

        data = None
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            match = re.search(r'\{.*?\}', text, re.DOTALL)
            if match:
                try:
                    data = json.loads(match.group(0))
                except json.JSONDecodeError:
                    pass

        if not data or not isinstance(data, dict):
            return None

        required_keys = {"threat_label", "confidence", "recommended_action", "reasoning"}
        if not required_keys.issubset(data.keys()):
            return None

        confidence = data.get("confidence")
        if not isinstance(confidence, (int, float)):
            return None
        confidence = max(0.0, min(1.0, float(confidence)))

        recommended_action = data.get("recommended_action")
        if recommended_action not in ("block", "allow"):
            return None

        ban_duration = data.get("ban_duration_seconds")
        if ban_duration is not None and not isinstance(ban_duration, int):
            return None

        return LLMAssessment(
            threat_label=str(data["threat_label"]),
            confidence=confidence,
            recommended_action=recommended_action,
            ban_duration_seconds=ban_duration,
            reasoning=str(data["reasoning"])
        )
