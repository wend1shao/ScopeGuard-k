from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import openai

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.llms.openai_llm import (
    _function_to_openai,
    _message_to_openai,
    _openai_to_assistant_message,
)
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.types import ChatMessage

from scopeguard.cost_tracker import calculate_cost
from scopeguard.openrouter import model_dump
from scopeguard.run_logging import RunLogger


class TrackedAgentLLM(BasePipelineElement):
    """OpenAI-compatible AgentDojo element with complete request, response, and cost logging."""

    def __init__(
        self,
        *,
        client: openai.OpenAI,
        model: str,
        logger: RunLogger,
        pricing: dict[str, float],
        temperature: float = 0.0,
        max_output_tokens: int = 2048,
    ) -> None:
        self.client = client
        self.model = model
        self.logger = logger
        self.pricing = pricing
        self.temperature = temperature
        self.max_output_tokens = max_output_tokens
        self.name = model

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict[str, Any] = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict[str, Any]]:
        openai_messages = [_message_to_openai(message, self.model) for message in messages]
        openai_tools = [_function_to_openai(tool) for tool in runtime.functions.values()]
        request = {
            "model": self.model,
            "messages": openai_messages,
            "tools": openai_tools,
            "tool_choice": "auto",
            "temperature": self.temperature,
            "max_tokens": self.max_output_tokens,
        }
        self.logger.record_llm_call({"component": "agent_execution", "phase": "request", "request": request})
        if not extra_args.get("initial_messages_logged"):
            self.logger.record_trajectory("initial_messages", list(messages))
            extra_args["initial_messages_logged"] = True

        completion = self.client.chat.completions.create(**request)
        response_payload = model_dump(completion)
        self.logger.record_llm_call(
            {"component": "agent_execution", "phase": "response", "response": response_payload}
        )

        usage = completion.usage
        input_tokens = int(usage.prompt_tokens if usage is not None else 0)
        output_tokens = int(usage.completion_tokens if usage is not None else 0)
        usage_cost = calculate_cost(
            model=self.model,
            component="agent_execution",
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            input_per_million_tokens=float(self.pricing["input_per_million_tokens"]),
            output_per_million_tokens=float(self.pricing["output_per_million_tokens"]),
        )
        self.logger.record_usage(usage_cost.to_dict())

        output = _openai_to_assistant_message(completion.choices[0].message)
        self.logger.record_trajectory("assistant_message", output)
        return query, runtime, env, [*messages, output], extra_args
