import pandas as pd

from scopeguard.analysis import validate_dominance


def test_dominance_requires_higher_macro_average_and_strict_gain() -> None:
    rows = []
    values = {
        "scopeguard_k": [0.6, 0.8],
        "full_approve": [0.4, 0.5],
        "full_escalate": [0.2, 0.7],
        "risk_only": [0.5, 0.6],
        "risk_intent": [0.6, 0.7],
    }
    for policy, scores in values.items():
        for budget, score in zip((0, 1), scores, strict=True):
            rows.append({"policy": policy, "budget": budget, "tcr_at_k": score})
    result = validate_dominance(pd.DataFrame(rows))
    assert result["passed"]
    assert result["aggregate_checks"]["full_approve"]["scopeguard_macro_average_tcr"] == 0.7
    assert "not a standalone TCR metric" in result["criterion"]


def test_dominance_allows_a_pointwise_tradeoff_when_macro_average_is_higher() -> None:
    rows = []
    values = {
        "scopeguard_k": [0.6, 0.8],
        "full_approve": [0.4, 0.5],
        "full_escalate": [0.2, 0.7],
        "risk_only": [0.5, 0.6],
        "risk_intent": [0.65, 0.7],
    }
    for policy, scores in values.items():
        for budget, score in zip((0, 1), scores, strict=True):
            rows.append({"policy": policy, "budget": budget, "tcr_at_k": score})
    result = validate_dominance(pd.DataFrame(rows))
    assert result["passed"]
    assert not result["per_budget_checks"]["risk_intent"]["pointwise_noninferior"]


def test_dominance_fails_when_competitor_macro_average_is_not_lower() -> None:
    rows = []
    values = {
        "scopeguard_k": [0.6, 0.8],
        "full_approve": [0.4, 0.5],
        "full_escalate": [0.2, 0.7],
        "risk_only": [0.5, 0.6],
        "risk_intent": [0.8, 0.7],
    }
    for policy, scores in values.items():
        for budget, score in zip((0, 1), scores, strict=True):
            rows.append({"policy": policy, "budget": budget, "tcr_at_k": score})
    result = validate_dominance(pd.DataFrame(rows))
    assert not result["passed"]


def test_dominance_fails_when_any_condition_is_incomplete() -> None:
    rows = []
    values = {
        "scopeguard_k": [0.9, 1.0],
        "full_approve": [0.8, 0.8],
        "full_escalate": [0.4, 0.7],
        "risk_only": [0.5, 0.6],
        "risk_intent": [0.7, 0.8],
    }
    for policy, scores in values.items():
        for budget, score in zip((0, 1), scores, strict=True):
            rows.append(
                {
                    "policy": policy,
                    "budget": budget,
                    "tcr_at_k": score,
                    "tasks": 7 if policy == "risk_only" and budget == 1 else 8,
                }
            )
    result = validate_dominance(pd.DataFrame(rows), expected_tasks_per_condition=8)
    assert not result["passed"]
    assert result["incomplete_conditions"]["risk_only:k1"]["observed"] == 7
