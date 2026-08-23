from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

# ---------------------------------------------------------------------------
# Log parsing
# ---------------------------------------------------------------------------

@dataclass
class LogEntry:
    """A single parsed HTTP access-log line."""
    source_ip: str
    effective_ip: str
    method: str
    path: str
    query_string: str
    status_code: int
    user_agent: str
    bytes_sent: int
    raw_line: str
    timestamp: datetime


# ---------------------------------------------------------------------------
# Heuristic filtering
# ---------------------------------------------------------------------------

@dataclass
class PatternRule:
    """A compiled regex rule used by the heuristic filter."""
    name: str
    pattern: re.Pattern  # type: ignore[type-arg]
    field: str           # which LogEntry attribute to match against
    description: str = ""


class FilterResult(Enum):
    """Outcome of the heuristic filter stage."""
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"


# ---------------------------------------------------------------------------
# ML feature extraction
# ---------------------------------------------------------------------------

@dataclass
class FeatureVector:
    """Numeric representation of a log entry for ML models."""
    path_length: int
    query_entropy: float
    method_encoded: int
    status_code: int
    user_agent_length: int
    hour_of_day: int
    request_frequency: float


# ---------------------------------------------------------------------------
# Firewall / banning
# ---------------------------------------------------------------------------

@dataclass
class BanRecord:
    """Record of an active IP ban."""
    ip: str
    reason: str
    banned_at: datetime
    expires_at: datetime


# ---------------------------------------------------------------------------
# Audit / persistence
# ---------------------------------------------------------------------------

@dataclass
class AuditEvent:
    """Persisted record of every agent decision."""
    source_ip: str
    entry_raw: str
    threat_label: Optional[str]
    confidence: Optional[float]
    recommended_action: Optional[str]
    final_action: str
    reasoning: Optional[str]
    execution_trace: Optional[dict]  # type: ignore[type-arg]
    error: Optional[str]
    occurred_at: datetime
    id: Optional[int] = None


@dataclass
class TrafficRecord:
    """Lightweight record stored for per-IP traffic context."""
    source_ip: str
    method: str
    path: str
    status_code: int
    user_agent: str
    observed_at: datetime


# ---------------------------------------------------------------------------
# LLM / agent layer
# ---------------------------------------------------------------------------

@dataclass
class LLMAssessment:
    """Structured response from the LLM threat-analysis node."""
    threat_label: str
    confidence: float
    recommended_action: str
    ban_duration_seconds: Optional[int]
    reasoning: str


class Action(Enum):
    """Final enforcement action taken by the agent."""
    BLOCK = "block"
    ALLOW = "allow"


@dataclass
class AgentDecision:
    """Complete output of one agent pipeline run."""
    action: Action
    assessment: Optional[LLMAssessment]
    execution_trace: dict  # type: ignore[type-arg]


# ---------------------------------------------------------------------------
# Feedback / learning
# ---------------------------------------------------------------------------

@dataclass
class FeedbackEvent:
    """Human-submitted feedback used for online learning."""
    ip: str
    is_false_positive: bool
    context: str
    created_at: datetime


# ---------------------------------------------------------------------------
# Probe detection
# ---------------------------------------------------------------------------

@dataclass
class ProbeEvent:
    """Raised when an IP is detected sweeping many distinct paths."""
    ip: str
    distinct_paths: int
    window_start: datetime
    window_end: datetime
    flagged_at: datetime


# ---------------------------------------------------------------------------
# Daemon operational stats
# ---------------------------------------------------------------------------

@dataclass
class DaemonStats:
    """Live counters updated by the daemon main loop."""
    total_parsed: int = 0
    heuristic_flagged: int = 0
    ml_escalated: int = 0
    agent_invoked: int = 0
    blocked: int = 0
    allowed: int = 0
    errors: int = 0
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
