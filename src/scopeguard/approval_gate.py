from __future__ import annotations

from ast import literal_eval
from collections.abc import Callable, Sequence
from typing import Any

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.llms.google_llm import EMPTY_FUNCTION_NAME
from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionReturnType, FunctionsRuntime
from agentdojo.types import ChatMessage, ChatToolResultMessage, text_content_block_from_string

from scopeguard.intent import assess_intent, extract_intent
from scopeguard.models import Decision, PolicyAssessment, PolicyState
from scopeguard.policies import ApprovalPolicy
from scopeguard.reviewer import LLMReviewer
from scopeguard.risk_scoring import assess_risk
from scopeguard.run_logging import RunLogger


def _coerce_list_arguments(args: dict[str, Any]) -> None:
    for key, value in args.items():
        if not isinstance(value, str):
            continue
        try:
            parsed = literal_eval(value)
        except (ValueError, SyntaxError):
            continue
        if isinstance(parsed, list):
            args[key] = parsed


class ApprovalGate(BasePipelineElement):
    """Intercepts every AgentDojo tool call before execution."""

    def __init__(
        self,
        *,
        policy: ApprovalPolicy,
        reviewer: LLMReviewer,
        budget: int,
        logger: RunLogger,
        tool_output_formatter: Callable[[FunctionReturnType], str] = tool_result_to_str,
    ) -> None:
        self.policy = policy
        self.reviewer = reviewer
        self.budget = budget
        self.logger = logger
        self.output_formatter = tool_output_formatter
        self._states: dict[tuple[str, ...], PolicyState] = {}

    def _task_key(self) -> tuple[str, ...]:
        context = self.logger.current_task
        return tuple(
            str(context.get(key, ""))
            for key in ("policy", "budget", "user_task_id", "injection_task_id", "attack")
        )

    def reset_task(self) -> None:
        self._states[self._task_key()] = PolicyState(budget=self.budget)

    @property
    def current_state(self) -> PolicyState:
        return self._states.setdefault(self._task_key(), PolicyState(budget=self.budget))

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict[str, Any] = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict[str, Any]]:
        if not messages or messages[-1]["role"] != "assistant" or not messages[-1].get("tool_calls"):
            return query, runtime, env, messages, extra_args

        state = self.current_state
        intent_profile = extra_args.setdefault("intent_profile", extract_intent(query))
        tool_results: list[ChatToolResultMessage] = []

        for tool_call in messages[-1]["tool_calls"] or []:
            state.calls_seen += 1
            tool_name = tool_call.function
            _coerce_list_arguments(tool_call.args)

            if tool_name == EMPTY_FUNCTION_NAME or tool_name not in (tool.name for tool in runtime.functions.values()):
                reason = "Invalid or empty tool name"
                tool_results.append(self._denial_message(tool_call, reason, query))
                state.denied += 1
                self._log_call(tool_call, state, None, Decision.DENY, reason, executed=False)
                continue

            risk = assess_risk(tool_name, tool_call.args)
            intent = assess_intent(intent_profile, tool_name, tool_call.args)
            assessment = PolicyAssessment(risk=risk, intent=intent)
            policy_outcome = self.policy.decide(assessment, state)
            final_decision = policy_outcome.decision
            final_reason = policy_outcome.reason
            reviewer_outcome = None

            self.logger.record_usage(
                {
                    "model": "deterministic-policy",
                    "component": "policy_inference",
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "total_tokens": 0,
                    "input_cost_usd": 0.0,
                    "output_cost_usd": 0.0,
                    "total_cost_usd": 0.0,
                }
            )

            if final_decision is Decision.ESCALATE:
                if state.remaining <= 0:
                    final_decision = Decision.DENY
                    final_reason = "Escalation budget exhausted; escalation converted to auto-deny"
                else:
                    state.escalations_used += 1
                    reviewer_outcome = self.reviewer.review(
                        original_request=query,
                        tool_name=tool_name,
                        tool_args=dict(tool_call.args),
                        tool_metadata={
                            "risk_level": risk.level,
                            "read_only": risk.read_only,
                            "external_side_effect": risk.external_side_effect,
                            "destructive": risk.destructive,
                            "sensitive_arguments_detected": risk.sensitive,
                        },
                        messages=messages,
                    )
                    final_decision = reviewer_outcome.decision
                    final_reason = f"Reviewer {final_decision.value}: {reviewer_outcome.reason}"
                    if final_decision is Decision.APPROVE:
                        state.reviewer_approved += 1
                    else:
                        state.reviewer_denied += 1

            decision_record = {
                "tool_call": {"id": tool_call.id, "function": tool_name, "args": dict(tool_call.args)},
                "intent_profile": intent_profile.to_dict(),
                "assessment": assessment.to_dict(),
                "policy_outcome": policy_outcome.to_dict(),
                "reviewer_outcome": reviewer_outcome.to_dict() if reviewer_outcome else None,
                "final_decision": final_decision.value,
                "final_reason": final_reason,
                "state_before_execution": state.to_dict(include_history=False),
            }
            self.logger.record_policy_decision(decision_record)
            state.history.append(decision_record)

            if final_decision is Decision.APPROVE:
                state.approved += 1
                tool_result, error = runtime.run_function(env, tool_name, tool_call.args)
                formatted = self.output_formatter(tool_result)
                result_message = ChatToolResultMessage(
                    role="tool",
                    content=[text_content_block_from_string(formatted)],
                    tool_call_id=tool_call.id,
                    tool_call=tool_call,
                    error=error,
                )
                tool_results.append(result_message)
                executed_record = {
                    "tool_call_id": tool_call.id,
                    "function": tool_name,
                    "args": dict(tool_call.args),
                    "error": error,
                    "output": formatted,
                }
                self.logger.record_executed_call(executed_record)
                self._log_call(
                    tool_call,
                    state,
                    assessment,
                    final_decision,
                    final_reason,
                    executed=True,
                    output=formatted,
                    error=error,
                )
                self.logger.record_trajectory("tool_result", result_message)
            else:
                state.denied += 1
                denial = self._denial_message(tool_call, final_reason, query)
                tool_results.append(denial)
                self._log_call(
                    tool_call,
                    state,
                    assessment,
                    final_decision,
                    final_reason,
                    executed=False,
                )
                self.logger.record_trajectory("tool_denial", denial)

        return query, runtime, env, [*messages, *tool_results], extra_args

    @staticmethod
    def _denial_message(tool_call: Any, reason: str, original_request: str) -> ChatToolResultMessage:
        return ChatToolResultMessage(
            role="tool",
            content=[
                text_content_block_from_string(
                    f"Tool call denied by approval policy. Reason: {reason}. "
                    "Do not retry this denied call. Return to the original user request, use only authorized alternatives, "
                    f"and then answer the user. Original user request: {original_request}"
                )
            ],
            tool_call_id=tool_call.id,
            tool_call=tool_call,
            error=f"Approval policy denied the tool call: {reason}",
        )

    def _log_call(
        self,
        tool_call: Any,
        state: PolicyState,
        assessment: PolicyAssessment | None,
        decision: Decision,
        reason: str,
        *,
        executed: bool,
        output: str | None = None,
        error: str | None = None,
    ) -> None:
        self.logger.record_tool_call(
            {
                "tool_call_id": tool_call.id,
                "function": tool_call.function,
                "args": dict(tool_call.args),
                "decision": decision.value,
                "reason": reason,
                "executed": executed,
                "output": output,
                "error": error,
                "assessment": assessment.to_dict() if assessment else None,
                "policy_state": state.to_dict(include_history=False),
            }
        )
