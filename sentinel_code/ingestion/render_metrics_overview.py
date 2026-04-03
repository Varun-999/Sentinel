import argparse
import json
from pathlib import Path


def load_report(report_path: Path) -> dict:
    with report_path.open("r", encoding="utf-8") as f:
        return json.load(f)


def compute_metrics(report: dict) -> dict:
    summary = report["summary_metrics"]

    total_cases = summary["total_cases"]
    total_known = summary["total_known_vulns"]
    true_positives = summary["true_positives"]
    false_positives = summary["false_positives"]
    successful_patches = summary["successful_patches"]
    regressions_caused = summary["regressions_caused"]
    total_mttr = summary["total_mttr_seconds"]

    false_positive_rate = (false_positives / total_cases * 100.0) if total_cases else 0.0
    detection_coverage = (true_positives / total_known * 100.0) if total_known else 0.0
    conditional_patch_success = (
        successful_patches / true_positives * 100.0 if true_positives else 0.0
    )
    regression_safety = (
        (1.0 - (regressions_caused / true_positives)) * 100.0 if true_positives else 0.0
    )
    avg_mttr = total_mttr / total_cases if total_cases else 0.0
    undetected_cases = max(total_known - true_positives, 0)

    return {
        "total_cases": total_cases,
        "detected_cases": true_positives,
        "undetected_cases": undetected_cases,
        "false_positive_rate": false_positive_rate,
        "detection_coverage": detection_coverage,
        "conditional_patch_success": conditional_patch_success,
        "regression_safety": regression_safety,
        "avg_mttr": avg_mttr,
    }


def draw_card(ax, x, y, w, h, title, value, subtitle, facecolor, edgecolor):
    from matplotlib.patches import FancyBboxPatch

    card = FancyBboxPatch(
        (x, y),
        w,
        h,
        boxstyle="round,pad=0.012,rounding_size=0.03",
        linewidth=1.5,
        facecolor=facecolor,
        edgecolor=edgecolor,
        transform=ax.transAxes,
        clip_on=False,
    )
    ax.add_patch(card)
    ax.text(
        x + 0.04 * w,
        y + 0.72 * h,
        title,
        transform=ax.transAxes,
        fontsize=12,
        fontweight="bold",
        color="#334155",
        va="center",
    )
    ax.text(
        x + 0.04 * w,
        y + 0.42 * h,
        value,
        transform=ax.transAxes,
        fontsize=22,
        fontweight="bold",
        color="#0f172a",
        va="center",
    )
    ax.text(
        x + 0.04 * w,
        y + 0.15 * h,
        subtitle,
        transform=ax.transAxes,
        fontsize=10,
        color="#475569",
        va="center",
    )


def render_metrics_overview(report_path: Path, output_path: Path) -> None:
    try:
        import matplotlib.pyplot as plt
        from matplotlib.patches import FancyBboxPatch
    except ModuleNotFoundError as exc:
        raise SystemExit(
            "matplotlib is required to render metrics_overview.png. "
            "Install it with: pip install matplotlib"
        ) from exc

    report = load_report(report_path)
    metrics = compute_metrics(report)

    plt.rcParams.update({"font.family": "DejaVu Sans", "axes.titlesize": 17, "axes.labelsize": 11})

    fig = plt.figure(figsize=(13.5, 7.2), facecolor="white")
    gs = fig.add_gridspec(2, 2, height_ratios=[0.24, 1.0], width_ratios=[1.7, 1.0], hspace=0.10, wspace=0.14)

    title_ax = fig.add_subplot(gs[0, :])
    title_ax.set_axis_off()
    title_ax.text(0.0, 0.72, "Sentinel Batch Evaluation Overview", fontsize=21, fontweight="bold", color="#0f172a", transform=title_ax.transAxes)
    title_ax.text(0.0, 0.28, "Overall performance metrics derived from the live 20-case benchmark batch.", fontsize=11.5, color="#64748b", transform=title_ax.transAxes)

    chart_ax = fig.add_subplot(gs[1, 0])
    labels = ["Detection\nCoverage", "Patch\nSuccess", "Regression\nSafety", "False Positive\nControl"]
    values = [metrics["detection_coverage"], metrics["conditional_patch_success"], metrics["regression_safety"], 100.0 - metrics["false_positive_rate"]]
    colors = ["#f97316", "#2563eb", "#7c3aed", "#059669"]

    bars = chart_ax.bar(labels, values, color=colors, width=0.56)
    chart_ax.set_ylim(0, 110)
    chart_ax.set_ylabel("Percentage (%)")
    chart_ax.set_title("Core Performance Indicators", pad=10, fontweight="bold")
    chart_ax.grid(axis="y", linestyle="--", linewidth=0.8, alpha=0.25)
    chart_ax.spines["top"].set_visible(False)
    chart_ax.spines["right"].set_visible(False)
    chart_ax.spines["left"].set_color("#94a3b8")
    chart_ax.spines["bottom"].set_color("#94a3b8")

    for bar, value in zip(bars, values):
        chart_ax.text(bar.get_x() + bar.get_width() / 2, value + 2, f"{value:.2f}%", ha="center", va="bottom", fontsize=10.5, fontweight="bold", color="#0f172a")

    side_ax = fig.add_subplot(gs[1, 1])
    side_ax.set_axis_off()
    side_ax.text(0.02, 0.95, "Supporting Metrics", fontsize=15, fontweight="bold", color="#0f172a", transform=side_ax.transAxes)

    draw_card(side_ax, 0.02, 0.68, 0.94, 0.20, "Detection Coverage", f"{metrics['detected_cases']}/{metrics['total_cases']}", "Confirmed vulnerable cases in the benchmark", "#fff7ed", "#f97316")
    draw_card(side_ax, 0.02, 0.41, 0.94, 0.20, "Mean Time to Remediate", f"{metrics['avg_mttr']:.2f}s", "Average end-to-end remediation latency", "#eff6ff", "#2563eb")
    draw_card(side_ax, 0.02, 0.14, 0.94, 0.20, "Undetected Cases", str(metrics["undetected_cases"]), "Current misses are concentrated in command injection", "#fef2f2", "#ef4444")

    fig.text(0.5, 0.02, "Metrics computed automatically from sentinel_code/ingestion/batch_report.json", ha="center", fontsize=10, color="#64748b")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close(fig)


def main() -> None:
    script_dir = Path(__file__).resolve().parent
    default_report = script_dir / "batch_report.json"
    default_output = script_dir / "metrics_overview.png"

    parser = argparse.ArgumentParser(
        description="Render a publication-style Sentinel metrics overview figure from batch_report.json."
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=default_report,
        help="Path to batch_report.json",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=default_output,
        help="Path to output PNG",
    )
    args = parser.parse_args()

    render_metrics_overview(args.report, args.output)
    print(f"Saved metrics overview figure to: {args.output}")


if __name__ == "__main__":
    main()
