#!/usr/bin/env python3
from pathlib import Path

from scopeguard.experiment import run_experiment


if __name__ == "__main__":
    project_root = Path(__file__).resolve().parents[1]
    run_dir = run_experiment(
        project_root=project_root,
        split="calibration",
        policy_filter={"scopeguard_k"},
        budget_filter={1},
        max_tasks=1,
        run_label="smoke",
    )
    print(f"Smoke test completed: {run_dir}")

