#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 ETH Zurich
"""Plot the offline analyzer's saved local evaluation summary (matplotlib 3.10.3)."""
import json
import pathlib
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: plot-evaluation.py SUMMARY_JSON OUTPUT_DIRECTORY")
    summary = json.loads(pathlib.Path(sys.argv[1]).read_text())
    if summary["version"] != 1 or len(summary["observations"]) != 36:
        raise SystemExit("expected one complete version 1 evaluation summary")
    out = pathlib.Path(sys.argv[2])
    out.mkdir(parents=True, exist_ok=True)
    conditions = ["baseline", "delay20", "delay60", "loss25", "rate128k", "loss100"]
    positions = {name: index for index, name in enumerate(conditions)}
    styles = {"native": ("#386cb0", "o", -.12), "wasm": ("#f28e2b", "^", .12)}
    fig, axes = plt.subplots(2, 3, figsize=(14, 8), constrained_layout=True)
    p95, replies, timing, burst, overhead, paired = axes.flat
    for kind, (color, marker, offset) in styles.items():
        rows = [row for row in summary["observations"] if row["trial"]["kind"] == kind]
        for row in rows:
            x = positions[row["trial"]["condition"]] + offset + (row["trial"]["repeat"] - 1) * .025
            if row["p95_rtt_ns"] is not None:
                p95.scatter(x, row["p95_rtt_ns"] / 1e6, color=color, marker=marker)
            replies.scatter(x, row["received"] / row["sent"] * 100, color=color, marker=marker)
            timing_samples = row["rtt_minus_target_processing_and_nominal_delay_ns"] or []
            timing.scatter([x] * len(timing_samples),
                           [value / 1e6 for value in timing_samples],
                           color=color, marker=marker, s=10, alpha=.35)
            if row["burst_goodput_bits_per_second"] is not None:
                burst.scatter(x, row["burst_goodput_bits_per_second"] / 1000, color=color, marker=marker)
            overhead.scatter(x, row["execution_overhead_ns"] / 1e9, color=color, marker=marker)
        p95.scatter([], [], color=color, marker=marker, label=kind)
    for row in summary["comparisons"]:
        if row["wasm_minus_native_median_ns"] is not None:
            paired.scatter(positions[row["condition"]] + (row["repeat"] - 1) * .08,
                           row["wasm_minus_native_median_ns"] / 1e6, color="#756bb1", s=25)
    p95.axhline(80, color="black", linestyle="--", linewidth=.8, label="SLA threshold")
    p95.text(5, .02, "no replies\nSLA fails", transform=p95.get_xaxis_transform(), ha="center", fontsize=8)
    p95.legend(fontsize=8)
    replies.axhline(90, color="black", linestyle="--", linewidth=.8)
    replies.set_ylim(-3, 103)
    timing.axhline(0, color="black", linewidth=.8)
    timing.text(.98, .02, "no timing\nobservations", transform=timing.transAxes, ha="right", fontsize=8)
    burst.axhline(128, color="black", linestyle="--", linewidth=.8, label="shared rate limit (rate128k only)")
    burst.set_yscale("log")
    burst.legend(fontsize=7)
    paired.axhline(0, color="black", linewidth=.8)
    paired.text(.98, .02, "unavailable", transform=paired.transAxes, ha="right", fontsize=8)
    titles = ["Empirical p95 (12 probes per trial)", "Observed reply fraction",
              "RTT minus target processing and nominal delay", "Fixed 32 KiB burst echo goodput",
              "Outer trial time minus probe elapsed time", "Paired WASM minus native median RTT"]
    units = ["RTT (ms)", "Replies (%)", "Timing excess (ms)", "Goodput (kbit/s, log)", "Elapsed difference (s)", "RTT difference (ms)"]
    for ax, title, unit in zip(axes.flat, titles, units):
        ax.set_title(title, fontsize=10)
        ax.set_ylabel(unit)
        ax.set_xticks(range(len(conditions)), conditions, rotation=30, ha="right")
        ax.set_xlim(-.5, 5.5)
        ax.grid(axis="y", alpha=.2)
    fig.suptitle("Owned loopback experiment — three repetitions; small samples, no external-network claims\n"
                 + "Source " + summary["source_sha"][:12], fontsize=12)
    fig.savefig(out / "latency-evaluation.svg")
    fig.savefig(out / "latency-evaluation.png", dpi=160)
    plt.close(fig)
    (out / "plot-version.json").write_text(json.dumps({"matplotlib": matplotlib.__version__, "source_sha": summary["source_sha"]}) + "\n")


if __name__ == "__main__":
    main()
