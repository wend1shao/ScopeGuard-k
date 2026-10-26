from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd


TASK_COLUMNS = [
    "suite",
    "split",
    "policy",
    "budget",
    "user_task_id",
    "injection_task_id",
    "source_run_id",
    "source_line",
    "reused_from_budget",
    "original_request",
    "task_success",
    "attack_succeeded",
    "unauthorized_executed",
    "safe_task_completion",
    "executed_calls",
    "unauthorized_call_count",
    "uncertain_call_count",
    "escalations",
    "tool_calls",
    "approved",
    "denied",
    "reviewer_approved",
    "reviewer_denied",
]

CALL_COLUMNS = [
    "suite",
    "policy",
    "budget",
    "user_task_id",
    "injection_task_id",
    "source_run_id",
    "evidence_run_id",
    "evidence_budget",
    "reused_condition",
    "call_index",
    "tool_call_id",
    "function",
    "args_json",
    "decision",
    "reason",
    "executed",
    "runtime_error",
    "output_sha256",
    "output_preview",
    "authorization_classification",
    "classification_basis",
    "unauthorized_executed",
    "original_request",
]


def export_formal_results(project_root: Path, input_dir: Path, output_dir: Path) -> dict[str, Path]:
    if not input_dir.is_absolute():
        input_dir = project_root / input_dir
    if not output_dir.is_absolute():
        output_dir = project_root / output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    audited_tasks = pd.read_csv(input_dir / "task_results_audited.csv")
    task_results = audited_tasks.rename(
        columns={
            "task_success_original": "task_success",
            "attack_succeeded_original": "attack_succeeded",
            "unauthorized_executed_audited": "unauthorized_executed",
            "safe_task_completion_audited": "safe_task_completion",
            "unauthorized_call_count_audited": "unauthorized_call_count",
            "uncertain_call_count_audited": "uncertain_call_count",
        }
    )[TASK_COLUMNS]
    task_path = output_dir / "task_results.csv"
    task_results.to_csv(task_path, index=False)

    audited_calls = pd.read_csv(input_dir / "tool_authorization_audit.csv")
    tool_calls = audited_calls.rename(
        columns={
            "decision_reason": "reason",
            "unauthorized_executed_audited": "unauthorized_executed",
        }
    )[CALL_COLUMNS]
    call_path = output_dir / "tool_calls.csv"
    tool_calls.to_csv(call_path, index=False)

    audited_tcr = pd.read_csv(input_dir / "tcr_comparison.csv")
    tcr = audited_tcr.rename(
        columns={
            "safe_completions_audited": "safe_completions",
            "tcr_audited": "tcr_at_k",
        }
    )[
        [
            "suite",
            "policy",
            "budget",
            "tasks",
            "safe_completions",
            "tcr_at_k",
            "uncertain_successful_tasks",
            "tcr_audited_upper_bound",
        ]
    ].rename(columns={"tcr_audited_upper_bound": "tcr_upper_bound"})
    tcr_path = output_dir / "tcr_by_k.csv"
    tcr.to_csv(tcr_path, index=False)

    hitl_rows: list[dict[str, object]] = []
    for (suite, policy, budget), group in task_results.groupby(["suite", "policy", "budget"], sort=True):
        successful = group[group["task_success"].astype(bool)]
        completed = int(successful.shape[0])
        successful_escalations = int(successful["escalations"].sum())
        hitl_rows.append(
            {
                "suite": suite,
                "policy": policy,
                "budget": int(budget),
                "tasks": int(group.shape[0]),
                "successfully_completed_tasks": completed,
                "total_escalations": int(group["escalations"].sum()),
                "escalations_on_successful_tasks": successful_escalations,
                "escalations_per_successful_task": (
                    successful_escalations / completed if completed else None
                ),
            }
        )
    hitl_path = output_dir / "hitl_load.csv"
    pd.DataFrame(hitl_rows).to_csv(hitl_path, index=False)

    cost_path = output_dir / "api_cost_breakdown.csv"
    cost_path.write_bytes((input_dir / "api_cost_breakdown.csv").read_bytes())
    metadata_path = output_dir / "run_metadata.json"
    metadata_path.write_bytes((input_dir / "run_metadata.json").read_bytes())

    audit_summary = json.loads((input_dir / "audit_summary.json").read_text(encoding="utf-8"))
    integrity_summary = {
        "schema_version": 1,
        "formal_tasks": audit_summary["formal_tasks"],
        "formal_calls": audit_summary["formal_calls"],
        "condition_counts": audit_summary["condition_counts"],
        "duplicate_conditions": audit_summary["duplicate_conditions"],
        "core_field_missing_records": audit_summary["core_field_missing_records"],
        "safe_completion_formula_mismatches": audit_summary["original_safe_formula_mismatches"],
        "uncertain_task_records": audit_summary["uncertain_task_records"],
        "replay": audit_summary["replay"],
        "budget": audit_summary["budget"],
        "full_approve_reuse": {
            "reused_records": audit_summary["full_approve_reuse"]["reused_records"],
            "outcome_mismatches": audit_summary["full_approve_reuse"]["outcome_mismatches"],
        },
        "reviewer_oracle_audit": audit_summary["reviewer_oracle_audit"],
        "failed_runtime_invocations": audit_summary["failed_runtime_invocations"],
        "failed_runtime_rule": audit_summary["failed_runtime_rule"],
        "metric_definition": "safe_task_completion = task_success AND NOT unauthorized_executed",
    }
    integrity_path = output_dir / "integrity_summary.json"
    integrity_path.write_text(
        json.dumps(integrity_summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return {
        "task_results": task_path,
        "tool_calls": call_path,
        "tcr": tcr_path,
        "hitl": hitl_path,
        "cost": cost_path,
        "run_metadata": metadata_path,
        "integrity": integrity_path,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Export canonical formal results for a GitHub release")
    parser.add_argument("--input-dir", type=Path, default=Path("outputs/formal_dataset"))
    parser.add_argument("--output-dir", type=Path, default=Path("outputs/formal_results"))
    args = parser.parse_args()
    project_root = Path(__file__).resolve().parents[1]
    paths = export_formal_results(project_root, args.input_dir, args.output_dir)
    print(json.dumps({key: str(value) for key, value in paths.items()}, indent=2))


if __name__ == "__main__":
    main()
