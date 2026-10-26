from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns


POLICY_LABELS = {
    "full_approve": "Full approve",
    "full_escalate": "Full escalate",
    "risk_only": "Risk only",
    "risk_intent": "Risk + intent",
    "scopeguard_k": "ScopeGuard-k",
}


def _save(fig: plt.Figure, path: Path) -> None:
    fig.tight_layout()
    fig.savefig(path, dpi=300, bbox_inches="tight")
    fig.savefig(path.with_suffix(".pdf"), bbox_inches="tight")
    plt.close(fig)


def generate(
    project_root: Path,
    *,
    tables_dir: Path | None = None,
    figures_dir: Path | None = None,
) -> list[Path]:
    tables = tables_dir or project_root / "outputs" / "tables"
    figures = figures_dir or project_root / "outputs" / "figures"
    if not tables.is_absolute():
        tables = project_root / tables
    if not figures.is_absolute():
        figures = project_root / figures
    figures.mkdir(parents=True, exist_ok=True)
    validation = json.loads((tables / "dominance_validation.json").read_text(encoding="utf-8"))
    if not validation.get("passed"):
        raise RuntimeError(
            "Formal figures were not generated because the locked dominance validation did not pass. "
            "Review calibration and evaluation evidence instead of plotting a misleading claim."
        )

    sns.set_theme(style="whitegrid", context="talk")
    palette = {
        "Full approve": "#9E9E9E",
        "Full escalate": "#6A51A3",
        "Risk only": "#E08214",
        "Risk + intent": "#3182BD",
        "ScopeGuard-k": "#1B9E77",
    }
    outputs: list[Path] = []

    tcr = pd.read_csv(tables / "tcr_by_k.csv")
    tcr["Strategy"] = tcr["policy"].map(POLICY_LABELS)
    fig, ax = plt.subplots(figsize=(10, 6))
    sns.lineplot(data=tcr, x="budget", y="tcr_at_k", hue="Strategy", style="Strategy", markers=True, dashes=False, palette=palette, ax=ax)
    ax.set(xlabel="Human review budget k per task", ylabel="Safe task completion rate (TCR@k)", ylim=(0, 1.02))
    ax.legend(title="Strategy", bbox_to_anchor=(1.02, 1), loc="upper left")
    path = figures / "tcr_vs_k.png"
    _save(fig, path)
    outputs.append(path)

    hitl = pd.read_csv(tables / "hitl_load.csv")
    hitl["Strategy"] = hitl["policy"].map(POLICY_LABELS)
    fig, ax = plt.subplots(figsize=(11, 6))
    sns.barplot(data=hitl, x="budget", y="escalations_on_successful_tasks", hue="Strategy", palette=palette, ax=ax)
    ax.set(xlabel="Human review budget k per task", ylabel="Escalations on successfully completed tasks")
    ax.legend(title="Strategy", bbox_to_anchor=(1.02, 1), loc="upper left")
    path = figures / "hitl_comparison.png"
    _save(fig, path)
    outputs.append(path)

    costs = pd.read_csv(tables / "api_cost_breakdown.csv")
    if not costs.empty:
        costs["Strategy"] = costs["policy"].map(POLICY_LABELS)
        costs["Component"] = costs["component"].map(
            {
                "agent_execution": "Agent execution",
                "policy_inference": "Policy inference",
                "reviewer_simulation": "Reviewer simulation",
            }
        )
        summary = costs.groupby(["Strategy", "Component"], as_index=False)["total_cost_usd"].sum()
        pivot = summary.pivot(index="Strategy", columns="Component", values="total_cost_usd").fillna(0)
        fig, ax = plt.subplots(figsize=(10, 6))
        pivot.plot(kind="bar", stacked=True, ax=ax, color=["#4C78A8", "#F58518", "#54A24B"])
        ax.set(xlabel="Strategy", ylabel="API cost (USD)")
        ax.tick_params(axis="x", rotation=20)
        ax.legend(title="Component", bbox_to_anchor=(1.02, 1), loc="upper left")
        path = figures / "cost_breakdown.png"
        _save(fig, path)
        outputs.append(path)

    ablation = pd.read_csv(tables / "ablation_results.csv")
    ablation["Strategy"] = ablation["policy"].map(POLICY_LABELS)
    fig, ax = plt.subplots(figsize=(9, 6))
    sns.lineplot(data=ablation, x="budget", y="tcr_at_k", hue="Strategy", markers=True, dashes=False, palette=palette, ax=ax)
    ax.set(xlabel="Human review budget k per task", ylabel="Safe task completion rate (TCR@k)", ylim=(0, 1.02))
    ax.legend(title="Ablation", bbox_to_anchor=(1.02, 1), loc="upper left")
    path = figures / "ablation_comparison.png"
    _save(fig, path)
    outputs.append(path)

    banking_tables = tables / "banking"
    banking_validation_path = banking_tables / "dominance_validation.json"
    banking_tcr_path = banking_tables / "tcr_by_k.csv"
    if banking_validation_path.exists() and banking_tcr_path.exists():
        banking_validation = json.loads(banking_validation_path.read_text(encoding="utf-8"))
        if banking_validation.get("incomplete_conditions"):
            raise RuntimeError("Banking figures require complete task counts for every registered condition")
        banking = pd.read_csv(banking_tcr_path)
        required = {"full_approve", "full_escalate", "scopeguard_k"}
        if set(banking["policy"].unique()) != required:
            raise RuntimeError("Banking figures require both baselines and ScopeGuard-k")
        banking["Strategy"] = banking["policy"].map(POLICY_LABELS)

        fig, ax = plt.subplots(figsize=(9, 6))
        sns.lineplot(
            data=banking,
            x="budget",
            y="tcr_at_k",
            hue="Strategy",
            style="Strategy",
            markers=True,
            dashes=False,
            palette=palette,
            ax=ax,
        )
        ax.set(
            title="Banking Cross-Scenario Validation",
            xlabel="Human review budget k per task",
            ylabel="Safe task completion rate (TCR@k)",
            ylim=(0, 1.02),
            xticks=sorted(banking["budget"].unique()),
        )
        ax.legend(title="Strategy", bbox_to_anchor=(1.02, 1), loc="upper left")
        path = figures / "banking_tcr_vs_k.png"
        _save(fig, path)
        outputs.append(path)

        common_budgets = sorted(set(tcr["budget"]) & set(banking["budget"]))
        cross_scenario = pd.concat(
            [
                tcr[(tcr["policy"] == "scopeguard_k") & tcr["budget"].isin(common_budgets)].assign(
                    Scenario="Workspace"
                ),
                banking[
                    (banking["policy"] == "scopeguard_k") & banking["budget"].isin(common_budgets)
                ].assign(Scenario="Banking"),
            ],
            ignore_index=True,
        )
        fig, ax = plt.subplots(figsize=(9, 6))
        sns.lineplot(
            data=cross_scenario,
            x="budget",
            y="tcr_at_k",
            hue="Scenario",
            style="Scenario",
            markers=True,
            dashes=False,
            palette={"Workspace": "#1B9E77", "Banking": "#7570B3"},
            ax=ax,
        )
        ax.set(
            title="ScopeGuard-k Cross-Scenario Performance",
            xlabel="Human review budget k per task",
            ylabel="Safe task completion rate (TCR@k)",
            ylim=(0, 1.02),
            xticks=common_budgets,
        )
        ax.legend(title="AgentDojo suite", bbox_to_anchor=(1.02, 1), loc="upper left")
        path = figures / "scopeguard_cross_scenario.png"
        _save(fig, path)
        outputs.append(path)
    return outputs


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate gated final figures")
    parser.add_argument("--tables-dir", type=Path)
    parser.add_argument("--figures-dir", type=Path)
    args = parser.parse_args()
    project_root = Path(__file__).resolve().parents[2]
    outputs = generate(project_root, tables_dir=args.tables_dir, figures_dir=args.figures_dir)
    print(json.dumps([str(path) for path in outputs], indent=2))


if __name__ == "__main__":
    main()
