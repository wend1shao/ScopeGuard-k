from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class UsageCost:
    model: str
    component: str
    input_tokens: int
    output_tokens: int
    total_tokens: int
    input_cost_usd: float
    output_cost_usd: float
    total_cost_usd: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def calculate_cost(
    *,
    model: str,
    component: str,
    input_tokens: int,
    output_tokens: int,
    input_per_million_tokens: float,
    output_per_million_tokens: float,
) -> UsageCost:
    input_cost = input_tokens * input_per_million_tokens / 1_000_000
    output_cost = output_tokens * output_per_million_tokens / 1_000_000
    return UsageCost(
        model=model,
        component=component,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        total_tokens=input_tokens + output_tokens,
        input_cost_usd=round(input_cost, 10),
        output_cost_usd=round(output_cost, 10),
        total_cost_usd=round(input_cost + output_cost, 10),
    )

