from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class Decision(StrEnum):
    APPROVE = "approve"
    DENY = "deny"
    ESCALATE = "escalate"


@dataclass(frozen=True)
class IntentProfile:
    original_request: str
    action_families: tuple[str, ...]
    explicit_emails: tuple[str, ...]
    explicit_ibans: tuple[str, ...]
    explicit_ids: tuple[str, ...]
    quoted_phrases: tuple[str, ...]
    sensitive_data_requested: bool
    indirect_authorization: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RiskAssessment:
    score: float
    level: str
    factors: tuple[str, ...]
    read_only: bool
    external_side_effect: bool
    destructive: bool
    sensitive: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class IntentAssessment:
    alignment: float
    uncertainty: float
    tool_family: str
    target_match: float
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class PolicyAssessment:
    risk: RiskAssessment
    intent: IntentAssessment

    def to_dict(self) -> dict[str, Any]:
        return {"risk": self.risk.to_dict(), "intent": self.intent.to_dict()}


@dataclass
class PolicyState:
    budget: int
    escalations_used: int = 0
    calls_seen: int = 0
    approved: int = 0
    denied: int = 0
    reviewer_approved: int = 0
    reviewer_denied: int = 0
    history: list[dict[str, Any]] = field(default_factory=list)

    @property
    def remaining(self) -> int:
        return max(0, self.budget - self.escalations_used)

    def to_dict(self, *, include_history: bool = True) -> dict[str, Any]:
        result = asdict(self)
        if not include_history:
            result.pop("history", None)
        result["remaining"] = self.remaining
        return result


@dataclass(frozen=True)
class PolicyOutcome:
    decision: Decision
    reason: str
    score: float | None = None
    threshold: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "reason": self.reason,
            "score": self.score,
            "threshold": self.threshold,
        }


@dataclass(frozen=True)
class ReviewerOutcome:
    decision: Decision
    confidence: float
    reason: str
    raw_text: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "confidence": self.confidence,
            "reason": self.reason,
            "raw_text": self.raw_text,
        }
