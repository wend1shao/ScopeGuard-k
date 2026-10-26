from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import openai

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, load_system_message
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.models import MODEL_NAMES
from agentdojo.task_suite.task_suite import TaskSuite
from agentdojo.types import ChatAssistantMessage, ChatMessage, text_content_block_from_string

from scopeguard.agent_llm import TrackedAgentLLM
from scopeguard.approval_gate import ApprovalGate
from scopeguard.policies import ApprovalPolicy
from scopeguard.reviewer import LLMReviewer
from scopeguard.run_logging import RunLogger


@dataclass(frozen=True)
class PipelineBundle:
    pipeline: AgentPipeline
    gate: ApprovalGate
    agent: TrackedAgentLLM
    reviewer: LLMReviewer


class IsolatedAgentPipeline(AgentPipeline):
    """AgentPipeline variant that allocates fresh per-task state instead of a mutable default dict."""

    def __init__(self, elements: Iterable[BasePipelineElement]) -> None:
        super().__init__(elements)

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict[str, Any] | None = None,
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict[str, Any]]:
        return super().query(query, runtime, env, messages, {} if extra_args is None else extra_args)


class BoundedToolsExecutionLoop(ToolsExecutionLoop):
    """Ends a repeated tool-call loop with an assistant failure instead of triggering task retries."""

    def __init__(self, elements: Sequence[BasePipelineElement], max_iters: int, logger: RunLogger) -> None:
        super().__init__(elements, max_iters=max_iters)
        self.run_logger = logger

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict[str, Any] = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict[str, Any]]:
        query, runtime, env, messages, extra_args = super().query(query, runtime, env, messages, extra_args)
        last = messages[-1] if messages else None
        if last is not None and last["role"] == "assistant" and last.get("tool_calls"):
            terminal = ChatAssistantMessage(
                role="assistant",
                content=[
                    text_content_block_from_string(
                        "I could not complete the request because the approval policy repeatedly denied a required tool call."
                    )
                ],
                tool_calls=[],
            )
            messages = [*messages, terminal]
            self.run_logger.record_trajectory("tool_loop_limit_reached", terminal)
        return query, runtime, env, messages, extra_args


def build_pipeline(
    *,
    client: openai.OpenAI,
    model: str,
    policy: ApprovalPolicy,
    budget: int,
    logger: RunLogger,
    pricing: dict[str, float],
    reviewer_prompt_path: Path,
    agent_temperature: float = 0.0,
    reviewer_temperature: float = 0.0,
    agent_max_output_tokens: int = 2048,
    reviewer_max_output_tokens: int = 512,
    max_tool_iterations: int = 8,
) -> PipelineBundle:
    agent = TrackedAgentLLM(
        client=client,
        model=model,
        logger=logger,
        pricing=pricing,
        temperature=agent_temperature,
        max_output_tokens=agent_max_output_tokens,
    )
    reviewer = LLMReviewer(
        client=client,
        model=model,
        logger=logger,
        pricing=pricing,
        system_prompt_path=reviewer_prompt_path,
        temperature=reviewer_temperature,
        max_output_tokens=reviewer_max_output_tokens,
    )
    gate = ApprovalGate(policy=policy, reviewer=reviewer, budget=budget, logger=logger)
    pipeline = IsolatedAgentPipeline(
        [
            SystemMessage(load_system_message(None)),
            InitQuery(),
            agent,
            BoundedToolsExecutionLoop([gate, agent], max_iters=max_tool_iterations, logger=logger),
        ]
    )
    pipeline.name = f"{model}-{policy.name}-k{budget}"
    return PipelineBundle(pipeline=pipeline, gate=gate, agent=agent, reviewer=reviewer)


def build_attack(attack_name: str, suite: TaskSuite[Any], pipeline: AgentPipeline, model: str):
    # AgentDojo's provided attack templates use MODEL_NAMES only to render a human-readable model name.
    # Registering the OpenRouter identifier keeps the benchmark attack unchanged.
    MODEL_NAMES.setdefault(model, "DeepSeek V4 Pro")
    return load_attack(attack_name, suite, pipeline)
