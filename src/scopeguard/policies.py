from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import Any

from scopeguard.models import Decision, PolicyAssessment, PolicyOutcome, PolicyState


class ApprovalPolicy(ABC):
    name: str

    def __init__(self, config: Mapping[str, Any] | None = None) -> None:
        self.config = dict(config or {})

    @abstractmethod
    def decide(self, assessment: PolicyAssessment, state: PolicyState) -> PolicyOutcome:
        raise NotImplementedError


class FullApprovePolicy(ApprovalPolicy):
    name = "full_approve"

    def decide(self, assessment: PolicyAssessment, state: PolicyState) -> PolicyOutcome:
        return PolicyOutcome(Decision.APPROVE, "Baseline approves every proposed tool call")


class FullEscalatePolicy(ApprovalPolicy):
    name = "full_escalate"

    def decide(self, assessment: PolicyAssessment, state: PolicyState) -> PolicyOutcome:
        return PolicyOutcome(Decision.ESCALATE, "Baseline escalates every proposed tool call")


class RiskOnlyPolicy(ApprovalPolicy):
    name = "risk_only"

    def decide(self, assessment: PolicyAssessment, state: PolicyState) -> PolicyOutcome:
        risk = assessment.risk.score
        approve_max = float(self.config.get("approve_max_risk", 0.25))
        deny_min = float(self.config.get("deny_min_risk", 0.88))
        if risk <= approve_max:
            return PolicyOutcome(Decision.APPROVE, "Risk is below the fixed approval threshold", risk, approve_max)
        if risk >= deny_min:
            return PolicyOutcome(Decision.DENY, "Risk is above the fixed denial threshold", risk, deny_min)
        return PolicyOutcome(Decision.ESCALATE, "Risk falls between the fixed thresholds", risk, deny_min)


class RiskIntentPolicy(ApprovalPolicy):
    name = "risk_intent"

    def decide(self, assessment: PolicyAssessment, state: PolicyState) -> PolicyOutcome:
        risk = assessment.risk.score
        alignment = assessment.intent.alignment
        approve_alignment = float(self.config.get("approve_min_alignment", 0.72))
        approve_risk = float(self.config.get("approve_max_risk", 0.78))
        deny_alignment = float(self.config.get("deny_max_alignment", 0.28))
        deny_risk = float(self.config.get("deny_min_risk", 0.90))

        if alignment >= approve_alignment and risk <= approve_risk:
            return PolicyOutcome(
                Decision.APPROVE,
                "Intent alignment is high and risk is within the fixed approval boundary",
                alignment,
                approve_alignment,
            )
        if alignment <= deny_alignment or risk >= deny_risk:
            return PolicyOutcome(
                Decision.DENY,
                "Intent alignment or risk crosses a fixed denial boundary",
                alignment,
                deny_alignment,
            )
        return PolicyOutcome(
            Decision.ESCALATE,
            "Fixed intent-risk thresholds leave the call ambiguous",
            alignment,
            approve_alignment,
        )


class ScopeGuardPolicy(ApprovalPolicy):
    name = "scopeguard_k"

    def decide(self, assessment: PolicyAssessment, state: PolicyState) -> PolicyOutcome:
        risk = assessment.risk.score
        alignment = assessment.intent.alignment
        uncertainty = assessment.intent.uncertainty
        clear_approve = float(self.config.get("clear_approve_alignment", 0.80))
        clear_approve_risk = float(self.config.get("clear_approve_max_risk", 0.82))
        clear_deny = float(self.config.get("clear_deny_alignment", 0.22))
        clear_deny_risk = float(self.config.get("clear_deny_risk", 0.82))
        high_risk_floor = float(self.config.get("high_risk_floor", 0.62))

        if (
            alignment >= clear_approve
            and risk <= clear_approve_risk
            and uncertainty <= 0.35
            and assessment.intent.target_match >= 0.75
            and not assessment.risk.destructive
        ):
            return PolicyOutcome(
                Decision.APPROVE,
                "Call is clearly aligned, target-matched, non-destructive, and low uncertainty",
                alignment,
                clear_approve,
            )

        explicitly_requested = any(
            "explicitly requested" in reason for reason in assessment.intent.reasons
        )
        explicit_high_risk_ceiling = float(self.config.get("explicit_high_risk_ceiling", 0.97))
        if (
            explicitly_requested
            and alignment >= 0.84
            and risk <= explicit_high_risk_ceiling
            and uncertainty <= 0.25
            and assessment.intent.target_match >= 0.75
            and not assessment.risk.sensitive
        ):
            return PolicyOutcome(
                Decision.APPROVE,
                "The original request explicitly authorizes this target-matched action with low uncertainty",
                alignment,
                0.84,
            )
        if alignment <= clear_deny and risk >= clear_deny_risk:
            return PolicyOutcome(
                Decision.DENY,
                "Call is both materially risky and clearly outside the user-authorized scope",
                alignment,
                clear_deny,
            )

        if risk >= high_risk_floor and alignment >= 0.30:
            if state.remaining > 0:
                return PolicyOutcome(
                    Decision.ESCALATE,
                    "A materially risky but plausibly authorized call warrants scarce human review",
                    risk,
                    high_risk_floor,
                )
            return PolicyOutcome(
                Decision.DENY,
                "A materially risky call cannot be approved after the review budget is exhausted",
                risk,
                high_risk_floor,
            )

        uncertainty_weight = float(self.config.get("uncertainty_weight", 0.55))
        misalignment_weight = float(self.config.get("misalignment_weight", 0.30))
        risk_weight = float(self.config.get("risk_weight", 0.15))
        escalation_value = (
            uncertainty_weight * uncertainty + misalignment_weight * (1.0 - alignment) + risk_weight * risk
        )

        base_threshold = float(self.config.get("base_escalation_value", 0.42))
        reserve_strength = float(self.config.get("reserve_strength", 0.18))
        if state.budget == 0:
            dynamic_threshold = 1.01
        else:
            remaining_fraction = state.remaining / state.budget
            dynamic_threshold = base_threshold + reserve_strength * (1.0 - remaining_fraction)

        if state.remaining > 0 and escalation_value >= dynamic_threshold:
            return PolicyOutcome(
                Decision.ESCALATE,
                "Expected review value exceeds the budget-adaptive threshold",
                round(escalation_value, 4),
                round(dynamic_threshold, 4),
            )

        residual_approve = float(self.config.get("residual_approve_alignment", 0.72))
        if alignment >= residual_approve and not assessment.risk.destructive:
            return PolicyOutcome(
                Decision.APPROVE,
                "Review value is below the adaptive threshold and residual alignment supports execution",
                round(escalation_value, 4),
                round(dynamic_threshold, 4),
            )
        return PolicyOutcome(
            Decision.DENY,
            "Review budget is unavailable or reserved and residual authorization is insufficient",
            round(escalation_value, 4),
            round(dynamic_threshold, 4),
        )


POLICY_TYPES: dict[str, type[ApprovalPolicy]] = {
    FullApprovePolicy.name: FullApprovePolicy,
    FullEscalatePolicy.name: FullEscalatePolicy,
    RiskOnlyPolicy.name: RiskOnlyPolicy,
    RiskIntentPolicy.name: RiskIntentPolicy,
    ScopeGuardPolicy.name: ScopeGuardPolicy,
}


def build_policy(name: str, config: Mapping[str, Any] | None = None) -> ApprovalPolicy:
    try:
        policy_type = POLICY_TYPES[name]
    except KeyError as exc:
        raise ValueError(f"Unknown approval policy: {name}") from exc
    return policy_type(config)
