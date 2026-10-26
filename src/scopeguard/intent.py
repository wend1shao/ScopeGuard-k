from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

from scopeguard.models import IntentAssessment, IntentProfile

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b", re.IGNORECASE)
QUOTED_RE = re.compile(r"['\"]([^'\"]{2,})['\"]")
ID_RE = re.compile(r"\b(?:id\s*)?['\"]?(\d{1,12})['\"]?\b", re.IGNORECASE)

TOOL_FAMILIES: dict[str, str] = {
    "get_current_day": "read_calendar",
    "search_calendar_events": "read_calendar",
    "get_day_calendar_events": "read_calendar",
    "get_unread_emails": "read_email",
    "get_sent_emails": "read_email",
    "get_received_emails": "read_email",
    "get_draft_emails": "read_email",
    "search_emails": "read_email",
    "search_contacts_by_name": "read_contacts",
    "search_contacts_by_email": "read_contacts",
    "search_files_by_filename": "read_drive",
    "get_file_by_id": "read_drive",
    "list_files": "read_drive",
    "search_files": "read_drive",
    "send_email": "send_email",
    "delete_email": "delete_email",
    "create_calendar_event": "create_calendar",
    "cancel_calendar_event": "cancel_calendar",
    "reschedule_calendar_event": "reschedule_calendar",
    "add_calendar_event_participants": "add_calendar_participants",
    "create_file": "create_file",
    "append_to_file": "append_file",
    "delete_file": "delete_file",
    "share_file": "share_file",
    "get_iban": "read_bank",
    "get_balance": "read_bank",
    "get_most_recent_transactions": "read_bank",
    "get_scheduled_transactions": "read_bank",
    "read_file": "read_drive",
    "get_user_info": "read_account",
    "send_money": "send_money",
    "schedule_transaction": "schedule_payment",
    "update_scheduled_transaction": "update_payment",
    "update_password": "update_password",
    "update_user_info": "update_profile",
}

READ_FAMILIES = {"read_calendar", "read_email", "read_contacts", "read_drive", "read_bank", "read_account"}

ACTION_PATTERNS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "send_email",
        ("send an email", "send email", "email to", "email each", "email the", "via email"),
    ),
    ("delete_email", ("delete the email", "delete email", "remove the email")),
    ("create_calendar", ("create an event", "create a new event", "add an event", "book ", "schedule ")),
    ("cancel_calendar", ("cancel ", "delete the event", "remove the event")),
    ("reschedule_calendar", ("reschedule", "move the event", "change the time")),
    ("add_calendar_participants", ("add also", "add participants", "invite ", "do not forget to invite")),
    ("create_file", ("create a new file", "create file", "new file named")),
    ("append_file", ("add them to the file", "append", "add all the ingredients")),
    ("delete_file", ("delete the largest file", "delete the file", "remove the file")),
    ("share_file", ("share the document", "share the file", "shared with")),
    ("send_money", ("pay the bill", "send them", "send the difference", "refund ", "send money", "transfer ")),
    ("schedule_payment", ("scheduled transaction", "schedule a transaction", "recurring scheduled", "set up a recurring")),
    ("update_payment", ("adjust my rent payment", "update my rent payment", "update my standing orders", "update the standing")),
    ("update_password", ("update the password", "change the password")),
    ("update_profile", ("update my account information", "update my account info", "new address")),
)


def _contains_any(text: str, patterns: tuple[str, ...]) -> bool:
    return any(pattern in text for pattern in patterns)


def extract_intent(request: str) -> IntentProfile:
    lowered = request.lower()
    families: set[str] = set()
    for family, patterns in ACTION_PATTERNS:
        if _contains_any(lowered, patterns):
            families.add(family)

    # Mutating a resource normally requires first resolving or reading that resource.
    # This is same-domain support, not permission to inspect unrelated data sources.
    if families.intersection(
        {"create_calendar", "cancel_calendar", "reschedule_calendar", "add_calendar_participants"}
    ):
        families.add("read_calendar")
    if families.intersection({"send_email", "delete_email"}):
        families.add("read_email")
    if families.intersection({"send_email", "add_calendar_participants", "share_file"}):
        families.add("read_contacts")
    if families.intersection({"create_file", "append_file", "delete_file", "share_file"}):
        families.add("read_drive")
    if families.intersection({"send_money", "schedule_payment", "update_payment"}):
        families.add("read_bank")
    if families.intersection({"update_password", "update_profile"}):
        families.add("read_account")

    if any(token in lowered for token in ("calendar", "appointment", "meeting", "event", "free for lunch")):
        families.add("read_calendar")
    if any(token in lowered for token in ("email", "inbox", "security code", "password reset", "unread")):
        families.add("read_email")
    if any(
        token in lowered
        for token in (
            "file",
            "cloud drive",
            "document",
            ".txt",
            ".docx",
            ".xlsx",
            ".pdf",
            "packing list",
        )
    ):
        families.add("read_drive")
    if any(token in lowered for token in ("email address", "contact", "participants")):
        families.add("read_contacts")
    if any(token in lowered for token in ("spending", "transaction history", "transactions", "payment", "iban", "bill")):
        families.add("read_bank")

    return IntentProfile(
        original_request=request,
        action_families=tuple(sorted(families)),
        explicit_emails=tuple(sorted(set(email.lower() for email in EMAIL_RE.findall(request)))),
        explicit_ibans=tuple(sorted(set(iban.upper() for iban in IBAN_RE.findall(request)))),
        explicit_ids=tuple(sorted(set(ID_RE.findall(request)))),
        quoted_phrases=tuple(sorted(set(phrase.strip().lower() for phrase in QUOTED_RE.findall(request)))),
        sensitive_data_requested=any(
            token in lowered for token in ("security code", "password", "secret", "token", "reset link")
        ),
        indirect_authorization=any(
            token in lowered
            for token in (
                "actions specified in the email",
                "todo list",
                "based on the emails",
                "based on the other document",
                "mentioned in the file",
                "to the client",
                "based on the file",
            )
        ),
    )


def _flatten_args(args: Mapping[str, Any]) -> str:
    return json.dumps(args, sort_keys=True, ensure_ascii=False, default=str).lower()


def assess_intent(profile: IntentProfile, tool_name: str, args: Mapping[str, Any]) -> IntentAssessment:
    family = TOOL_FAMILIES.get(tool_name, "unknown")
    reasons: list[str] = []
    args_text = _flatten_args(args)

    if family in READ_FAMILIES:
        same_domain = family in profile.action_families
        alignment = 0.93 if same_domain else 0.68
        reasons.append("read-only call in the requested domain" if same_domain else "supportive read outside the primary domain")
    elif family in profile.action_families:
        alignment = 0.84
        reasons.append("tool action family is explicitly requested")
    elif profile.indirect_authorization and family not in {"delete_email", "delete_file"}:
        alignment = 0.58
        reasons.append("the request delegates limited actions through referenced content")
    else:
        alignment = 0.08
        reasons.append("tool action family is absent from the original request")

    target_match = 1.0
    target_sensitive_families = {"send_email", "share_file", "add_calendar_participants"}
    if family in target_sensitive_families:
        argument_emails = set(email.lower() for email in EMAIL_RE.findall(args_text))
        requested_emails = set(profile.explicit_emails)
        if argument_emails:
            if requested_emails and argument_emails.issubset(requested_emails):
                target_match = 1.0
                reasons.append("external target matches an address in the request")
            elif requested_emails:
                target_match = 0.05
                alignment = min(alignment, 0.12)
                reasons.append("external target differs from addresses authorized by the request")
            else:
                target_match = 0.25
                alignment = min(alignment, 0.35)
                reasons.append("external target is not stated in the original request")

    if family in {"send_money", "schedule_payment", "update_payment"}:
        argument_ibans = set(iban.upper() for iban in IBAN_RE.findall(args_text))
        requested_ibans = set(profile.explicit_ibans)
        if argument_ibans:
            if requested_ibans and argument_ibans.issubset(requested_ibans):
                target_match = 1.0
                reasons.append("financial target matches an IBAN in the request")
            elif requested_ibans:
                target_match = 0.05
                alignment = min(alignment, 0.12)
                reasons.append("financial target differs from the IBAN authorized by the request")
            else:
                target_match = 0.25
                alignment = min(alignment, 0.35)
                reasons.append("financial target is not stated in the original request")

    if family in {"delete_file", "delete_email"} and profile.explicit_ids:
        if any(identifier in args_text for identifier in profile.explicit_ids):
            reasons.append("destructive target identifier matches the request")
        else:
            target_match = 0.10
            alignment = min(alignment, 0.18)
            reasons.append("destructive target identifier differs from the request")

    novelty = 1.0 - target_match
    boundary_uncertainty = 1.0 - min(1.0, abs(alignment - 0.5) * 2.0)
    indirect_bonus = 0.22 if profile.indirect_authorization else 0.0
    uncertainty = max(0.0, min(1.0, 0.65 * boundary_uncertainty + 0.25 * novelty + indirect_bonus))

    return IntentAssessment(
        alignment=round(alignment, 4),
        uncertainty=round(uncertainty, 4),
        tool_family=family,
        target_match=round(target_match, 4),
        reasons=tuple(reasons),
    )
