from scopeguard.models import IntentAssessment, PolicyAssessment, PolicyState, RiskAssessment
from scopeguard.policies import build_policy


def assessment(
    *, risk: float, alignment: float, uncertainty: float, destructive: bool = False, explicit: bool = False
) -> PolicyAssessment:
    return PolicyAssessment(
        risk=RiskAssessment(
            score=risk,
            level="high" if risk >= 0.7 else "low",
            factors=(),
            read_only=not destructive,
            external_side_effect=False,
            destructive=destructive,
            sensitive=False,
        ),
        intent=IntentAssessment(
            alignment=alignment,
            uncertainty=uncertainty,
            tool_family="test",
            target_match=alignment,
            reasons=("tool action family is explicitly requested",) if explicit else (),
        ),
    )


def test_full_approve_always_approves() -> None:
    outcome = build_policy("full_approve").decide(
        assessment(risk=1.0, alignment=0.0, uncertainty=0.0, destructive=True), PolicyState(budget=0)
    )
    assert outcome.decision.value == "approve"


def test_risk_only_ignores_intent() -> None:
    policy = build_policy("risk_only", {"approve_max_risk": 0.25, "deny_min_risk": 0.88})
    low_alignment = policy.decide(assessment(risk=0.1, alignment=0.0, uncertainty=0.9), PolicyState(budget=1))
    high_alignment = policy.decide(assessment(risk=0.1, alignment=1.0, uncertainty=0.0), PolicyState(budget=1))
    assert low_alignment.decision == high_alignment.decision


def test_scopeguard_uses_review_for_ambiguous_high_value_call() -> None:
    policy = build_policy("scopeguard_k")
    outcome = policy.decide(
        assessment(risk=0.8, alignment=0.55, uncertainty=0.9),
        PolicyState(budget=2),
    )
    assert outcome.decision.value == "escalate"


def test_scopeguard_denies_clear_risky_misalignment() -> None:
    policy = build_policy("scopeguard_k")
    outcome = policy.decide(
        assessment(risk=0.95, alignment=0.05, uncertainty=0.1, destructive=True),
        PolicyState(budget=5),
    )
    assert outcome.decision.value == "deny"


def test_scopeguard_spends_budget_on_aligned_high_risk_call() -> None:
    policy = build_policy("scopeguard_k")
    outcome = policy.decide(
        assessment(risk=0.96, alignment=0.84, uncertainty=0.1, destructive=True),
        PolicyState(budget=1),
    )
    assert outcome.decision.value == "escalate"


def test_scopeguard_autoapproves_explicit_target_matched_destructive_action() -> None:
    policy = build_policy("scopeguard_k")
    outcome = policy.decide(
        assessment(risk=0.96, alignment=0.84, uncertainty=0.208, destructive=True, explicit=True),
        PolicyState(budget=0),
    )
    assert outcome.decision.value == "approve"


def test_scopeguard_denies_low_risk_cross_domain_read_without_review_value() -> None:
    policy = build_policy("scopeguard_k", {"residual_approve_alignment": 0.72})
    outcome = policy.decide(
        assessment(risk=0.20, alignment=0.68, uncertainty=0.416),
        PolicyState(budget=0),
    )
    assert outcome.decision.value == "deny"
