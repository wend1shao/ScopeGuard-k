import json

from agentdojo.functions_runtime import FunctionCall

from scopeguard.reviewer import LLMReviewer, _json_default


def test_reviewer_parser_accepts_valid_json() -> None:
    outcome = LLMReviewer._parse_outcome('{"decision":"approve","confidence":0.9,"reason":"Authorized"}')
    assert outcome.decision.value == "approve"
    assert outcome.confidence == 0.9


def test_reviewer_parser_fails_closed() -> None:
    outcome = LLMReviewer._parse_outcome("approve this")
    assert outcome.decision.value == "deny"
    assert outcome.confidence == 0.0


def test_reviewer_prompt_serializes_agentdojo_function_calls() -> None:
    payload = {"tool_calls": [FunctionCall(function="delete_file", args={"file_id": "13"})]}
    serialized = json.dumps(payload, default=_json_default)
    assert '"function": "delete_file"' in serialized
