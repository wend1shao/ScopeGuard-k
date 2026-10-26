# Formal Results Dataset

This directory contains the canonical results used for analysis, plotting, reporting, and presentation preparation. It intentionally excludes raw multi-gigabyte LLM logs and generated images.

## Contents

- `task_results.csv`: one row per formal policy-budget-task condition, with final metric fields.
- `tool_calls.csv`: every proposed call with tool arguments, policy decision, execution state, authorization classification, runtime error, and output evidence.
- `tcr_by_k.csv`: final safe task completion counts and TCR@k.
- `hitl_load.csv`: escalation counts using successfully completed user tasks.
- `api_cost_breakdown.csv`: agent, policy, and reviewer tokens and dollar cost by condition.
- `run_metadata.json`: formal run configurations, source revisions, and completion states.
- `integrity_summary.json`: task counts, replay checks, budget checks, reuse checks, and reviewer-input checks.
- `cases/`: multiple detailed over-conservative and over-permissive ScopeGuard-k trajectories plus required spot checks.

## Rebuild analysis tables

```bash
python scripts/analyze_results.py \
  --formal-dataset outputs/formal_results \
  --output-tables-dir outputs/reproduced/tables
```

## Generate figures

```bash
MPLCONFIGDIR=.cache/matplotlib python scripts/generate_figures.py \
  --tables-dir outputs/reproduced/tables \
  --figures-dir outputs/reproduced/figures
```

No API key is needed for either command.
