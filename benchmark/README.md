# Signed workflow benchmark

Run `python benchmark/run_campaign.py --n 100 --runs 3 --repeats-per-run 10` to measure signed credential generation, trusted SQLite verification, and in-process authenticated API issue, anchor, and verify cycles. Each API batch includes application startup and a fresh SQLite database. The output is `benchmark/results_v1.12.0.json`; it records individual samples, summary statistics, and environment information. These batch measurements are not network throughput or production latency.

For a smaller standalone run, use `python benchmark/run_benchmarks.py --n 10 --repeats 2 --out benchmark/single_run_local.json`. To create a plot of campaign results, install `.[plot]` and run `python benchmark/plot_results.py --input benchmark/results_v1.12.0.json --out benchmark/figure3_v1.12.0.png`. The benchmark uses synthetic data only.
