# SPDX-License-Identifier: MIT
"""Run three independent benchmark processes and retain all 30 batch samples."""
import argparse
import json
from pathlib import Path
import statistics
import subprocess
import sys
from tempfile import TemporaryDirectory


NAMES = ("signed_credential_generation", "trusted_persistent_verification",
         "authenticated_api_issue_anchor_verify")


def summary(samples):
    ordered = sorted(samples)
    return {"raw_batch_ms": samples, "mean_batch_ms": statistics.mean(samples),
            "median_batch_ms": statistics.median(samples),
            "p95_batch_ms": ordered[min(len(samples) - 1, int((len(samples) - 1) * .95 + .5))],
            "stdev_batch_ms": statistics.stdev(samples)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n", type=int, default=100)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--repeats-per-run", type=int, default=10)
    parser.add_argument("--out", type=Path, default=Path("benchmark/results_v1.12.0.json"))
    args = parser.parse_args()
    if args.n < 1 or args.runs < 2 or args.repeats_per_run < 2:
        parser.error("n >= 1, runs >= 2 and repeats-per-run >= 2 required")
    script = Path(__file__).with_name("run_benchmarks.py")
    records = []
    with TemporaryDirectory() as directory:
        for index in range(args.runs):
            path = Path(directory) / f"run-{index+1}.json"
            subprocess.run([sys.executable, str(script), "--n", str(args.n), "--repeats",
                            str(args.repeats_per_run), "--out", str(path)], check=True,
                           stdout=subprocess.DEVNULL)
            records.append(json.loads(path.read_text(encoding="utf-8")))
    result = {"software_version": "1.12.0", "scope": records[0]["scope"],
              "environment": records[0]["environment"], "workload_per_batch": args.n,
              "independent_runs": args.runs, "repeats_per_run": args.repeats_per_run,
              "repeats": args.runs * args.repeats_per_run, "run_records": records}
    for name in NAMES:
        result[name] = summary([value for record in records for value in record[name]["raw_batch_ms"]])
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"software_version": result["software_version"], "independent_runs": args.runs,
                      "repeats": result["repeats"],
                      "means_ms": {name: result[name]["mean_batch_ms"] for name in NAMES}}, indent=2))


if __name__ == "__main__":
    main()
