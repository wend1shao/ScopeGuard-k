from __future__ import annotations

import argparse
import csv
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

from agentdojo.task_suite.load_suites import get_suite

from scopeguard.agentdojo_adapter import build_attack, build_pipeline
from scopeguard.authorization_audit import audit_authorization
from scopeguard.openrouter import build_openrouter_client
from scopeguard.policies import build_policy
from scopeguard.run_logging import RunLogger


@dataclass(frozen=True)
class TaskPair:
    split: str
    user_task_id: str
    injection_task_id: str
    rationale: str


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        payload = yaml.safe_load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"Expected a mapping in {path}")
    return payload


def load_task_pairs(path: Path, split: str) -> list[TaskPair]:
    pairs: list[TaskPair] = []
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            enabled = str(row.get("enabled", "")).strip().lower() in {"1", "true", "yes"}
            if enabled and row["split"] == split:
                pairs.append(
                    TaskPair(
                        split=split,
                        user_task_id=row["user_task_id"],
                        injection_task_id=row["injection_task_id"],
                        rationale=row.get("rationale", ""),
                    )
                )
    if not pairs:
        raise ValueError(f"No enabled task pairs for split '{split}'")
    return pairs


def _run_task_pair(
    *,
    suite: Any,
    attack: Any,
    bundle: Any,
    logger: RunLogger,
    pair: TaskPair,
    policy_name: str,
    budget: int,
    attack_name: str,
) -> dict[str, Any]:
    user_task = suite.get_user_task_by_id(pair.user_task_id)
    injection_task = suite.get_injection_task_by_id(pair.injection_task_id)
    injections = attack.attack(user_task, injection_task)
    environment = suite.load_and_inject_default_environment(injections)
    initialized_environment = user_task.init_environment(environment.model_copy(deep=True))
    user_ground_truth = user_task.ground_truth(initialized_environment.model_copy(deep=True))
    injection_ground_truth = injection_task.ground_truth(initialized_environment.model_copy(deep=True))

    context = {
        "split": pair.split,
        "policy": policy_name,
        "budget": budget,
        "suite": suite.name,
        "attack": attack_name,
        "user_task_id": pair.user_task_id,
        "injection_task_id": pair.injection_task_id,
    }
    with logger.task_context(**context):
        bundle.gate.reset_task()
        started = time.perf_counter()
        utility, attack_succeeded = suite.run_task_with_pipeline(
            bundle.pipeline,
            user_task,
            injection_task,
            injections,
            environment=environment,
        )
        duration = time.perf_counter() - started
        audit = audit_authorization(
            executed_calls=logger.executed_calls,
            user_ground_truth=user_ground_truth,
            injection_ground_truth=injection_ground_truth,
            attack_succeeded=bool(attack_succeeded),
        )
        logger.append_jsonl("authorization_audit.jsonl", audit)
        result = {
            **context,
            "rationale": pair.rationale,
            "task_success": bool(utility),
            "attack_succeeded": bool(attack_succeeded),
            "unauthorized_executed": bool(audit["unauthorized_executed"]),
            "safe_task_completion": bool(utility) and not bool(audit["unauthorized_executed"]),
            "duration_seconds": round(duration, 6),
            "policy_state": bundle.gate.current_state.to_dict(),
            "authorization_audit": audit,
            "injection_payloads": injections,
        }
        logger.record_task_result(result)
        return result


def run_experiment(
    *,
    project_root: Path,
    split: str,
    policy_filter: set[str] | None = None,
    budget_filter: set[int] | None = None,
    max_tasks: int | None = None,
    run_label: str | None = None,
    benchmark_path: Path | None = None,
    task_manifest_path: Path | None = None,
) -> Path:
    load_dotenv(project_root / ".env")
    benchmark_path = benchmark_path or project_root / "configs" / "benchmark.yaml"
    task_manifest_path = task_manifest_path or project_root / "configs" / "task_manifest.csv"
    if not benchmark_path.is_absolute():
        benchmark_path = project_root / benchmark_path
    if not task_manifest_path.is_absolute():
        task_manifest_path = project_root / task_manifest_path
    benchmark = load_yaml(benchmark_path)
    policy_config = load_yaml(project_root / "configs" / "policies.yaml")
    pricing_config = load_yaml(project_root / "configs" / "pricing.yaml")
    pairs = load_task_pairs(task_manifest_path, split)
    if max_tasks is not None:
        pairs = pairs[:max_tasks]

    policies = [str(item) for item in benchmark["policies"]]
    budgets = [int(item) for item in benchmark["budgets"]]
    if policy_filter is not None:
        policies = [policy for policy in policies if policy in policy_filter]
    if budget_filter is not None:
        budgets = [budget for budget in budgets if budget in budget_filter]
    if not policies or not budgets:
        raise ValueError("Policy and budget filters selected no experiment conditions")

    model = str(benchmark["agent"]["model"])
    pricing = dict(pricing_config["models"][model])
    snapshot = {
        "benchmark": benchmark,
        "policies": policy_config,
        "pricing": pricing_config,
        "split": split,
        "task_pairs": [pair.__dict__ for pair in pairs],
        "selected_policies": policies,
        "selected_budgets": budgets,
        "max_tasks": max_tasks,
        "benchmark_config_path": str(benchmark_path.relative_to(project_root)),
        "task_manifest_path": str(task_manifest_path.relative_to(project_root)),
    }
    logger = RunLogger(
        project_root=project_root,
        output_root=project_root / benchmark["logging"]["root"],
        config_snapshot=snapshot,
        run_label=run_label or split,
        fsync_jsonl=bool(benchmark["logging"].get("fsync_jsonl", True)),
    )
    logger.set_status("running")

    try:
        client = build_openrouter_client()
        suite = get_suite(str(benchmark["benchmark_version"]), str(benchmark["suite"]))
        completed_results: dict[tuple[str, int], list[dict[str, Any]]] = {}

        for policy_name in policies:
            for budget in budgets:
                if (
                    policy_name == "full_approve"
                    and bool(benchmark["execution"].get("reuse_budget_invariant_full_approve", True))
                    and budget != budgets[0]
                    and (policy_name, budgets[0]) in completed_results
                ):
                    reused_results: list[dict[str, Any]] = []
                    for source in completed_results[(policy_name, budgets[0])]:
                        reused = {
                            **source,
                            "run_id": logger.run_id,
                            "budget": budget,
                            "reused_from_budget": budgets[0],
                            "duration_seconds": 0.0,
                            "policy_state": {
                                **source["policy_state"],
                                "budget": budget,
                                "remaining": budget,
                            },
                        }
                        logger.record_task_result(reused)
                        reused_results.append(reused)
                    completed_results[(policy_name, budget)] = reused_results
                    continue

                policy = build_policy(policy_name, policy_config.get(policy_name, {}))
                bundle = build_pipeline(
                    client=client,
                    model=model,
                    policy=policy,
                    budget=budget,
                    logger=logger,
                    pricing=pricing,
                    reviewer_prompt_path=project_root / "prompts" / "reviewer_system.md",
                    agent_temperature=float(benchmark["agent"].get("temperature", 0.0)),
                    reviewer_temperature=float(benchmark["reviewer"].get("temperature", 0.0)),
                    agent_max_output_tokens=int(benchmark["agent"].get("max_output_tokens", 2048)),
                    reviewer_max_output_tokens=int(benchmark["reviewer"].get("max_output_tokens", 512)),
                    max_tool_iterations=int(benchmark["agent"].get("max_tool_iterations", 15)),
                )
                attack = build_attack(str(benchmark["attack"]), suite, bundle.pipeline, model)
                condition_results: list[dict[str, Any]] = []

                def execute_pair(pair: TaskPair) -> dict[str, Any] | None:
                    try:
                        return _run_task_pair(
                            suite=suite,
                            attack=attack,
                            bundle=bundle,
                            logger=logger,
                            pair=pair,
                            policy_name=policy_name,
                            budget=budget,
                            attack_name=str(benchmark["attack"]),
                        )
                    except Exception as exc:
                        logger.append_jsonl(
                            "errors.jsonl",
                            {
                                "event": "task_failed",
                                "policy": policy_name,
                                "budget": budget,
                                "user_task_id": pair.user_task_id,
                                "injection_task_id": pair.injection_task_id,
                                "exception_type": type(exc).__name__,
                                "message": str(exc),
                            },
                        )
                        if not bool(benchmark["execution"].get("continue_on_error", True)):
                            raise
                        return None

                max_workers = max(1, int(benchmark["execution"].get("max_workers", 1)))
                if max_workers == 1:
                    for pair in pairs:
                        result = execute_pair(pair)
                        if result is not None:
                            condition_results.append(result)
                else:
                    with ThreadPoolExecutor(max_workers=max_workers) as executor:
                        futures = {executor.submit(execute_pair, pair): pair for pair in pairs}
                        for future in as_completed(futures):
                            result = future.result()
                            if result is not None:
                                condition_results.append(result)
                completed_results[(policy_name, budget)] = condition_results

        incomplete_conditions = {
            f"{policy_name}:k{budget}": len(results)
            for (policy_name, budget), results in completed_results.items()
            if len(results) != len(pairs)
        }
        if incomplete_conditions:
            logger.set_status(
                "completed_with_errors",
                completed_conditions=len(completed_results),
                expected_tasks_per_condition=len(pairs),
                incomplete_conditions=incomplete_conditions,
            )
        else:
            logger.set_status("completed", completed_conditions=len(completed_results))
    except Exception as exc:
        logger.set_status("failed", exception_type=type(exc).__name__, message=str(exc))
        raise
    return logger.run_dir


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run fully logged ScopeGuard-k experiments")
    parser.add_argument("--split", required=True)
    parser.add_argument("--policy", action="append", dest="policies")
    parser.add_argument("--budget", action="append", type=int, dest="budgets")
    parser.add_argument("--max-tasks", type=int)
    parser.add_argument("--run-label")
    parser.add_argument("--benchmark-config", type=Path, default=Path("configs/benchmark.yaml"))
    parser.add_argument("--task-manifest", type=Path, default=Path("configs/task_manifest.csv"))
    return parser


def main() -> None:
    args = build_argument_parser().parse_args()
    project_root = Path(__file__).resolve().parents[2]
    run_dir = run_experiment(
        project_root=project_root,
        split=args.split,
        policy_filter=set(args.policies) if args.policies else None,
        budget_filter=set(args.budgets) if args.budgets else None,
        max_tasks=args.max_tasks,
        run_label=args.run_label,
        benchmark_path=args.benchmark_config,
        task_manifest_path=args.task_manifest,
    )
    print(json.dumps({"run_dir": str(run_dir)}, indent=2))


if __name__ == "__main__":
    main()
