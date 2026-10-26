from __future__ import annotations

import json
import re
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import openai

from agentdojo.types import ChatMessage

from scopeguard.cost_tracker import calculate_cost
from scopeguard.models import Decision, ReviewerOutcome
from scopeguard.openrouter import model_dump
from scopeguard.run_logging import RunLogger

JSON_OBJECT_RE = re.compile(r"\{.*\}", re.DOTALL)


def _json_default(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    return str(value)


def _trace_for_reviewer(messages: Sequence[ChatMessage], max_messages: int = 8) -> list[dict[str, Any]]:
    trace: list[dict[str, Any]] = []
    for message in messages[-max_messages:]:
        if message["role"] == "system":
            continue
        item: dict[str, Any] = {"role": message["role"], "content": message.get("content")}
        if message["role"] == "assistant":
            item["tool_calls"] = message.get("tool_calls")
        if message["role"] == "tool" and message.get("tool_call") is not None:
            item["tool_name"] = message["tool_call"].function
        trace.append(item)
    return trace


class LLMReviewer:
    def __init__(
        self,
        *,
        client: openai.OpenAI,
        model: str,
        logger: RunLogger,
        pricing: dict[str, float],
        system_prompt_path: Path,
        temperature: float = 0.0,
        max_output_tokens: int = 512,
    ) -> None:
        self.client = client
        self.model = model
        self.logger = logger
        self.pricing = pricing
        self.system_prompt = system_prompt_path.read_text(encoding="utf-8")
        self.temperature = temperature
        self.max_output_tokens = max_output_tokens

    def review(
        self,
        *,
        original_request: str,
        tool_name: str,
        tool_args: dict[str, Any],
        tool_metadata: dict[str, Any],
        messages: Sequence[ChatMessage],
    ) -> ReviewerOutcome:
        reviewer_input = {
            "original_user_request": original_request,
            "proposed_tool_call": {"name": tool_name, "arguments": tool_args},
            "tool_metadata": tool_metadata,
            "preceding_trace": _trace_for_reviewer(messages),
            "oracle_information_present": False,
        }
        request_messages = [
            {"role": "system", "content": self.system_prompt},
            {
                "role": "user",
                "content": json.dumps(
                    reviewer_input,
                    ensure_ascii=False,
                    sort_keys=True,
                    default=_json_default,
                ),
            },
        ]
        request = {
            "model": self.model,
            "messages": request_messages,
            "temperature": self.temperature,
            "max_tokens": self.max_output_tokens,
        }
        self.logger.record_llm_call({"component": "reviewer_simulation", "phase": "request", "request": request})
        completion = self.client.chat.completions.create(**request)
        response_payload = model_dump(completion)
        self.logger.record_llm_call(
            {"component": "reviewer_simulation", "phase": "response", "response": response_payload}
        )

        usage = completion.usage
        input_tokens = int(usage.prompt_tokens if usage is not None else 0)
        output_tokens = int(usage.completion_tokens if usage is not None else 0)
        usage_cost = calculate_cost(
            model=self.model,
            component="reviewer_simulation",
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            input_per_million_tokens=float(self.pricing["input_per_million_tokens"]),
            output_per_million_tokens=float(self.pricing["output_per_million_tokens"]),
        )
        self.logger.record_usage(usage_cost.to_dict())

        raw_text = completion.choices[0].message.content or ""
        outcome = self._parse_outcome(raw_text)
        self.logger.record_reviewer_decision(
            {
                "reviewer_input": reviewer_input,
                "outcome": outcome.to_dict(),
                "ground_truth_or_attack_annotations_supplied": False,
            }
        )
        return outcome

    @staticmethod
    def _parse_outcome(raw_text: str) -> ReviewerOutcome:
        match = JSON_OBJECT_RE.search(raw_text)
        if match is None:
            return ReviewerOutcome(
                decision=Decision.DENY,
                confidence=0.0,
                reason="Fail-safe denial because the reviewer response was not valid JSON",
                raw_text=raw_text,
            )
        try:
            payload = json.loads(match.group(0))
            decision = Decision(str(payload["decision"]).strip().lower())
            if decision is Decision.ESCALATE:
                raise ValueError("Reviewer may only approve or deny")
            confidence = max(0.0, min(1.0, float(payload.get("confidence", 0.0))))
            reason = str(payload.get("reason", "No reason supplied"))
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            return ReviewerOutcome(
                decision=Decision.DENY,
                confidence=0.0,
                reason="Fail-safe denial because the reviewer JSON did not match the required schema",
                raw_text=raw_text,
            )
        return ReviewerOutcome(decision=decision, confidence=confidence, reason=reason, raw_text=raw_text)
