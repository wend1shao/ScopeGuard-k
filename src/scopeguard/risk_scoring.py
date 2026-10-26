from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from scopeguard.intent import READ_FAMILIES, TOOL_FAMILIES
from scopeguard.models import RiskAssessment

BASE_RISK: dict[str, float] = {
    "read_calendar": 0.08,
    "read_contacts": 0.10,
    "read_drive": 0.14,
    "read_email": 0.20,
    "create_file": 0.42,
    "append_file": 0.54,
    "create_calendar": 0.56,
    "reschedule_calendar": 0.68,
    "add_calendar_participants": 0.72,
    "send_email": 0.78,
    "share_file": 0.82,
    "cancel_calendar": 0.88,
    "delete_email": 0.91,
    "delete_file": 0.96,
    "unknown": 0.72,
    "read_bank": 0.24,
    "read_account": 0.28,
    "send_money": 0.96,
    "schedule_payment": 0.90,
    "update_payment": 0.88,
    "update_password": 0.92,
    "update_profile": 0.72,
}


def assess_risk(tool_name: str, args: Mapping[str, Any]) -> RiskAssessment:
    family = TOOL_FAMILIES.get(tool_name, "unknown")
    score = BASE_RISK[family]
    factors = [f"base risk for {family}"]
    args_text = json.dumps(args, sort_keys=True, ensure_ascii=False, default=str).lower()

    external = family in {
        "send_email",
        "share_file",
        "add_calendar_participants",
        "create_calendar",
        "send_money",
        "schedule_payment",
        "update_payment",
    }
    destructive = family in {
        "delete_email",
        "delete_file",
        "cancel_calendar",
        "send_money",
        "update_password",
    }
    sensitive = any(
        token in args_text
        for token in (
            "security code",
            "password",
            "iban",
            "wire $",
            "all unread emails",
            "all received",
            "attachment",
        )
    )

    if sensitive:
        score += 0.10
        factors.append("arguments contain sensitive or bulk-data indicators")
    if destructive:
        factors.append("operation is destructive or difficult to reverse")
    if external:
        factors.append("operation has an external side effect")

    score = max(0.0, min(1.0, score))
    if score < 0.30:
        level = "low"
    elif score < 0.70:
        level = "medium"
    elif score < 0.90:
        level = "high"
    else:
        level = "critical"

    return RiskAssessment(
        score=round(score, 4),
        level=level,
        factors=tuple(factors),
        read_only=family in READ_FAMILIES,
        external_side_effect=external,
        destructive=destructive,
        sensitive=sensitive,
    )
