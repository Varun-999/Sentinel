import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_report(report_path: Path) -> dict:
    return load_json(report_path)


def load_logs(logs_dir: Path) -> dict[str, dict]:
    logs = {}
    for path in sorted(logs_dir.glob("batch_CVE-*.json")):
        logs[path.stem.replace("batch_", "")] = load_json(path)
    return logs


def compute_summary(report: dict) -> dict:
    summary = report["summary_metrics"]
    total_cases = summary["total_cases"]
    total_known = summary["total_known_vulns"]
    true_positives = summary["true_positives"]
    false_positives = summary["false_positives"]
    successful_patches = summary["successful_patches"]
    regressions_caused = summary["regressions_caused"]
    total_mttr = summary["total_mttr_seconds"]

    return {
        "total_cases": total_cases,
        "detected_cases": true_positives,
        "undetected_cases": max(total_known - true_positives, 0),
        "false_positive_rate": (false_positives / total_cases * 100.0) if total_cases else 0.0,
        "detection_coverage": (true_positives / total_known * 100.0) if total_known else 0.0,
        "conditional_patch_success": (successful_patches / true_positives * 100.0) if true_positives else 0.0,
        "regression_safety": (1.0 - (regressions_caused / true_positives)) * 100.0 if true_positives else 0.0,
        "avg_mttr": total_mttr / total_cases if total_cases else 0.0,
    }


def draw_card(ax, x, y, w, h, title, value, subtitle, facecolor, edgecolor):
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
    ax.text(x + 0.04 * w, y + 0.72 * h, title, transform=ax.transAxes, fontsize=12, fontweight="bold", color="#334155")
    ax.text(x + 0.04 * w, y + 0.42 * h, value, transform=ax.transAxes, fontsize=22, fontweight="bold", color="#0f172a")
    ax.text(x + 0.04 * w, y + 0.15 * h, subtitle, transform=ax.transAxes, fontsize=10, color="#475569")


def save_figure(fig, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=300, bbox_inches="tight")
    plt.close(fig)


def render_metrics_overview(report: dict, output_path: Path) -> None:
    metrics = compute_summary(report)
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
    save_figure(fig, output_path)


def render_detection_vs_patch_success(report: dict, output_path: Path) -> None:
    reports = report["detailed_reports"]
    class_order = ["SQL", "XSS", "PATH_TRAVERSAL", "COMMAND_INJECTION", "INFO_EXPOSURE"]
    total_by_class = Counter(r["ground_truth"] for r in reports)
    detected_by_class = Counter(r["ground_truth"] for r in reports if r["detected"])
    patched_by_class = Counter(r["ground_truth"] for r in reports if r["detected"] and r["verification_status"] == "PASS")

    totals = [total_by_class[c] for c in class_order]
    detected = [detected_by_class[c] for c in class_order]
    patched = [patched_by_class[c] for c in class_order]

    fig, ax = plt.subplots(figsize=(12, 7), facecolor="white")
    x = range(len(class_order))
    width = 0.24

    b1 = ax.bar([i - width for i in x], totals, width=width, label="Ground Truth Cases", color="#cbd5e1")
    b2 = ax.bar(x, detected, width=width, label="Detected Cases", color="#f97316")
    b3 = ax.bar([i + width for i in x], patched, width=width, label="Verified Patched Cases", color="#3b82f6")

    ax.set_title("Detection and Verified Patch Success by Vulnerability Class", fontsize=18, fontweight="bold")
    ax.set_ylabel("Number of Cases")
    ax.set_xticks(list(x))
    ax.set_xticklabels(["SQL", "XSS", "Path\nTraversal", "Command\nInjection", "Info\nExposure"])
    ax.set_ylim(0, max(totals) + 1.5)
    ax.grid(axis="y", linestyle="--", alpha=0.25)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.legend(frameon=False, ncol=3, loc="upper center", bbox_to_anchor=(0.5, 1.06))

    for bars in (b1, b2, b3):
        for bar in bars:
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.06, f"{int(bar.get_height())}", ha="center", va="bottom", fontsize=10, fontweight="bold")

    ax.text(
        0.98, 0.08,
        "Observation: all four missed cases belong to Command Injection,\nwhile other benchmark classes reached full detect-and-verify closure.",
        transform=ax.transAxes, ha="right", va="bottom", fontsize=10,
        bbox={"boxstyle": "round,pad=0.45", "facecolor": "#fff7ed", "edgecolor": "#f97316"},
        color="#7c2d12",
    )
    save_figure(fig, output_path)


def extract_iteration_stats(logs: dict[str, dict]) -> dict:
    stats = {}
    for cve, log in logs.items():
        events = log.get("events", [])
        blue_calls = 0
        verify_fails = 0
        verify_passes = 0
        for event in events:
            agent = event.get("agent", "")
            action = event.get("action", "")
            if agent == "Blue Agent" and "Using LLM to fix" in action:
                blue_calls += 1
            if agent == "Green Agent" and "Verification Result: FAIL" in action:
                verify_fails += 1
            if agent == "Green Agent" and "Verification Result: PASS" in action:
                verify_passes += 1
        if blue_calls or verify_fails or verify_passes:
            stats[cve] = {
                "blue_calls": blue_calls,
                "verify_fails": verify_fails,
                "verify_passes": verify_passes,
            }
    return stats


def render_iteration_analysis(report: dict, logs: dict[str, dict], output_path: Path) -> None:
    iter_stats = extract_iteration_stats(logs)
    reports = [r for r in report["detailed_reports"] if r["detected"]]
    cves = [r["cve"] for r in reports]
    fails = [iter_stats.get(cve, {}).get("verify_fails", 0) for cve in cves]
    attempts = [iter_stats.get(cve, {}).get("blue_calls", 0) for cve in cves]

    sample_cve = max(cves, key=lambda c: (iter_stats.get(c, {}).get("verify_fails", 0), c))
    sample = iter_stats.get(sample_cve, {"verify_fails": 0, "blue_calls": 0, "verify_passes": 0})

    fig = plt.figure(figsize=(13, 7), facecolor="white")
    gs = fig.add_gridspec(1, 2, width_ratios=[1.65, 1.0], wspace=0.18)

    ax = fig.add_subplot(gs[0, 0])
    x = range(len(cves))
    bars = ax.bar(x, fails, color="#8b5cf6", width=0.65, label="Verification Failures Before Pass")
    ax.plot(x, attempts, color="#2563eb", marker="o", linewidth=2.5, label="Blue-Agent Patch Attempts")
    ax.set_title("Iterative Refinement Behavior Across Detected Cases", fontsize=17, fontweight="bold")
    ax.set_ylabel("Count")
    ax.set_xticks(list(x))
    ax.set_xticklabels([cve.replace("CVE-2023-", "") for cve in cves], rotation=45, ha="right")
    ax.grid(axis="y", linestyle="--", alpha=0.25)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.legend(frameon=False, loc="upper left")
    for bar, fail_count in zip(bars, fails):
        ax.text(bar.get_x() + bar.get_width() / 2, fail_count + 0.05, str(fail_count), ha="center", va="bottom", fontsize=9, fontweight="bold")

    ax2 = fig.add_subplot(gs[0, 1])
    ax2.set_axis_off()
    ax2.text(0.0, 0.95, f"Exemplar Case: {sample_cve}", fontsize=16, fontweight="bold", color="#0f172a", transform=ax2.transAxes)
    ax2.text(0.0, 0.87, "Illustrative closed-loop repair path", fontsize=11, color="#64748b", transform=ax2.transAxes)

    steps = [
        ("1. Red Agent", "Exploit confirmed"),
        ("2. Blue Agent", f"{sample['blue_calls']} patch attempts issued"),
        ("3. Green Agent", f"{sample['verify_fails']} failure(s) rejected"),
        ("4. Final State", f"{sample['verify_passes']} verified PASS"),
    ]
    y_positions = [0.68, 0.50, 0.32, 0.14]
    colors = ["#fff7ed", "#eff6ff", "#f5f3ff", "#ecfdf5"]
    edges = ["#f97316", "#3b82f6", "#8b5cf6", "#10b981"]
    for (title, subtitle), y, fc, ec in zip(steps, y_positions, colors, edges):
        box = FancyBboxPatch((0.03, y), 0.92, 0.12, boxstyle="round,pad=0.02,rounding_size=0.03", facecolor=fc, edgecolor=ec, linewidth=1.4, transform=ax2.transAxes)
        ax2.add_patch(box)
        ax2.text(0.08, y + 0.075, title, fontsize=12, fontweight="bold", color="#0f172a", transform=ax2.transAxes)
        ax2.text(0.08, y + 0.032, subtitle, fontsize=10, color="#475569", transform=ax2.transAxes)
    ax2.text(0.49, 0.80, "↓", fontsize=22, ha="center", va="center", color="#94a3b8", transform=ax2.transAxes)
    ax2.text(0.49, 0.62, "↓", fontsize=22, ha="center", va="center", color="#94a3b8", transform=ax2.transAxes)
    ax2.text(0.49, 0.44, "↓", fontsize=22, ha="center", va="center", color="#94a3b8", transform=ax2.transAxes)

    save_figure(fig, output_path)


def render_failure_case_breakdown(report: dict, output_path: Path) -> None:
    reports = report["detailed_reports"]
    class_order = ["SQL", "XSS", "PATH_TRAVERSAL", "COMMAND_INJECTION", "INFO_EXPOSURE"]
    missed_counts = Counter(r["ground_truth"] for r in reports if not r["detected"])
    total_by_class = Counter(r["ground_truth"] for r in reports)
    detected_by_class = Counter(r["ground_truth"] for r in reports if r["detected"])

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 6), facecolor="white", gridspec_kw={"width_ratios": [1.0, 1.15]})

    pie_values = [missed_counts[c] for c in class_order if missed_counts[c] > 0]
    pie_labels = [c.replace("_", " ").title() for c in class_order if missed_counts[c] > 0]
    if not pie_values:
        pie_values = [1]
        pie_labels = ["No Missed Cases"]
        pie_colors = ["#10b981"]
    else:
        pie_colors = ["#ef4444", "#f97316", "#f59e0b", "#8b5cf6"][: len(pie_values)]

    ax1.pie(pie_values, labels=pie_labels, autopct="%1.0f%%", startangle=90, colors=pie_colors, wedgeprops={"linewidth": 1, "edgecolor": "white"})
    ax1.set_title("Distribution of Undetected Cases", fontsize=16, fontweight="bold")

    x = range(len(class_order))
    detected_vals = [detected_by_class[c] for c in class_order]
    missed_vals = [missed_counts[c] for c in class_order]
    ax2.bar(x, detected_vals, color="#10b981", width=0.58, label="Detected")
    ax2.bar(x, missed_vals, bottom=detected_vals, color="#ef4444", width=0.58, label="Missed")
    ax2.set_xticks(list(x))
    ax2.set_xticklabels(["SQL", "XSS", "Path\nTraversal", "Command\nInjection", "Info\nExposure"])
    ax2.set_ylabel("Cases")
    ax2.set_title("Failure-Case Concentration by Ground-Truth Class", fontsize=16, fontweight="bold")
    ax2.grid(axis="y", linestyle="--", alpha=0.25)
    ax2.spines["top"].set_visible(False)
    ax2.spines["right"].set_visible(False)
    ax2.legend(frameon=False)

    for i, cls in enumerate(class_order):
        total = total_by_class[cls]
        ax2.text(i, total + 0.08, f"{missed_counts[cls]} missed", ha="center", va="bottom", fontsize=9, fontweight="bold", color="#7f1d1d")

    fig.text(0.5, 0.02, "Current failure cases are isolated to Command Injection under the present sandbox constraints.", ha="center", fontsize=10, color="#64748b")
    save_figure(fig, output_path)


def render_all(report_path: Path, logs_dir: Path, output_dir: Path) -> None:
    report = load_report(report_path)
    logs = load_logs(logs_dir)

    render_metrics_overview(report, output_dir / "metrics_overview.png")
    render_detection_vs_patch_success(report, output_dir / "detection_vs_patch_success.png")
    render_iteration_analysis(report, logs, output_dir / "iteration_analysis.png")
    render_failure_case_breakdown(report, output_dir / "failure_case_breakdown.png")


def main() -> None:
    script_dir = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description="Render all manuscript result figures from Sentinel ingestion outputs.")
    parser.add_argument("--report", type=Path, default=script_dir / "batch_report.json", help="Path to batch_report.json")
    parser.add_argument("--logs", type=Path, default=script_dir / "logs", help="Path to ingestion logs directory")
    parser.add_argument("--output-dir", type=Path, default=script_dir, help="Directory to save generated PNG figures")
    args = parser.parse_args()

    render_all(args.report, args.logs, args.output_dir)
    print(f"Saved manuscript figures to: {args.output_dir}")


if __name__ == "__main__":
    main()
