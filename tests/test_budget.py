from scopeguard.models import PolicyState


def test_remaining_budget_never_becomes_negative() -> None:
    state = PolicyState(budget=2, escalations_used=5)
    assert state.remaining == 0


def test_budget_counts_only_escalations() -> None:
    state = PolicyState(budget=3)
    state.calls_seen += 4
    state.approved += 2
    state.denied += 1
    assert state.remaining == 3
    state.escalations_used += 1
    assert state.remaining == 2

