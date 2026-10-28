# SPDX-License-Identifier: MIT
"""Render Figure 3 directly from the versioned raw benchmark record.

Requires the optional plot dependencies. The PNG output is reproducible within
an unchanged renderer, font and Matplotlib environment.
"""
import argparse
import hashlib
from io import BytesIO
import json
from pathlib import Path


WORKLOADS = (
    "signed_credential_generation",
    "trusted_persistent_verification",
    "authenticated_api_issue_anchor_verify",
)


def figure_provenance(record):
    """Hash the complete canonical benchmark record, including component runs."""
    canonical = json.dumps(record, ensure_ascii=False, sort_keys=True,
                           separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def render_figure(record):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from PIL import Image, PngImagePlugin

    version = record["software_version"]
    values = [record[name]["mean_batch_ms"] for name in WORKLOADS]
    labels = ["Signed credential\ngeneration", "Trusted SQLite\nverification",
              "Authenticated API\nissue-anchor-verify"]
    navy, gray = "#23455e", "#5e6e79"
    fig, ax = plt.subplots(figsize=(10.82, 6.12), dpi=150)
    fig.patch.set_facecolor("white")
    bars = ax.bar(range(3), values, color=["#4e829e", "#356a87", navy], width=.55)
    ax.set_yscale("log")
    ax.set_ylim(5, max(1800, max(values) * 1.4))
    ax.set_ylabel("Mean batch time (ms; log scale)", color=navy, fontsize=12)
    ax.set_xticks(range(3), labels, fontsize=11)
    ax.grid(axis="y", alpha=.25)
    ax.set_axisbelow(True)
    ax.set_title(f"v{version} synthetic benchmark: {record['workload_per_batch']} operations per batch, "
                 f"{record['independent_runs']} runs × {record['repeats_per_run']} repetitions",
                 fontsize=14, color=navy, pad=20)
    for bar, value in zip(bars, values):
        ax.annotate(f"{value:.3f} ms", (bar.get_x() + bar.get_width() / 2, value),
                    xytext=(0, 7), textcoords="offset points", ha="center", fontsize=11, color=navy)
    fig.text(.5, .025,
             "Different workloads and included costs; figures are not comparable per-operation latencies.",
             ha="center", fontsize=10, color=gray)
    fig.tight_layout(rect=(0, .06, 1, 1))
    buffer = BytesIO()
    fig.savefig(buffer, format="png", dpi=150)
    plt.close(fig)
    buffer.seek(0)
    image = Image.open(buffer).convert("RGB").resize((1623, 918), Image.Resampling.LANCZOS)
    result = BytesIO()
    metadata = PngImagePlugin.PngInfo()
    metadata.add_text("EduChainTrustBenchmarkSHA256", figure_provenance(record))
    image.save(result, format="PNG", pnginfo=metadata)
    return result.getvalue()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    record = json.loads(args.input.read_text(encoding="utf-8"))
    args.out.write_bytes(render_figure(record))
    print(args.out)


if __name__ == "__main__":
    main()
