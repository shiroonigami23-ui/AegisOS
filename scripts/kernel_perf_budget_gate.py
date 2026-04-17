#!/usr/bin/env python3
import argparse
import json
import subprocess
import sys
from pathlib import Path


def _load_json(path: Path) -> dict:
  data = json.loads(path.read_text(encoding="utf-8"))
  if not isinstance(data, dict):
    raise ValueError(f"invalid JSON object in {path}")
  return data


def _run_benchmark(repo_root: Path, iterations: int) -> dict:
  cmd = [
      sys.executable,
      str(repo_root / "scripts" / "kernel_hotpath_benchmark.py"),
      "--iterations",
      str(iterations),
  ]
  result = subprocess.run(cmd, cwd=repo_root, check=True, capture_output=True, text=True)
  data = json.loads(result.stdout)
  if not isinstance(data, dict):
    raise ValueError("benchmark output was not an object")
  return data


def _check_thresholds(bench: dict, budget: dict) -> list[str]:
  failures: list[str] = []
  thresholds = budget.get("thresholds", {})
  if not isinstance(thresholds, dict):
    return ["budget thresholds missing or invalid"]

  for metric_name, metric_budget in thresholds.items():
    if not isinstance(metric_budget, dict):
      failures.append(f"threshold {metric_name} has invalid config")
      continue
    metric = bench.get(metric_name)
    if not isinstance(metric, dict):
      failures.append(f"benchmark metric missing: {metric_name}")
      continue

    ops_per_sec = float(metric.get("ops_per_sec", 0.0))
    ns_per_op = float(metric.get("ns_per_op", 0.0))
    min_ops_per_sec = float(metric_budget.get("min_ops_per_sec", 0.0))
    max_ns_per_op = float(metric_budget.get("max_ns_per_op", float("inf")))

    if ops_per_sec < min_ops_per_sec:
      failures.append(
          f"{metric_name}: ops_per_sec {ops_per_sec:.3f} below min {min_ops_per_sec:.3f}"
      )
    if ns_per_op > max_ns_per_op:
      failures.append(
          f"{metric_name}: ns_per_op {ns_per_op:.3f} above max {max_ns_per_op:.3f}"
      )
  return failures


def main() -> int:
  parser = argparse.ArgumentParser(description="Kernel perf budget gate for cross-module hotpath benchmark.")
  parser.add_argument("--budget", default="docs/PERF_BUDGET.json")
  parser.add_argument("--benchmark-json", default=None,
                      help="Optional precomputed benchmark JSON path. If omitted, benchmark is executed.")
  parser.add_argument("--emit-benchmark-json", default=None,
                      help="Optional output path to write benchmark payload used by this gate.")
  args = parser.parse_args()

  repo_root = Path(__file__).resolve().parents[1]
  budget_path = repo_root / args.budget
  budget = _load_json(budget_path)
  if int(budget.get("schema_version", 0)) != 1:
    raise ValueError("unsupported PERF_BUDGET schema_version")

  if args.benchmark_json:
    bench = _load_json(repo_root / args.benchmark_json)
  else:
    iterations = int(budget.get("iterations_ci", 120000))
    bench = _run_benchmark(repo_root, iterations)

  if args.emit_benchmark_json:
    out_path = repo_root / args.emit_benchmark_json
    out_path.write_text(json.dumps(bench, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

  failures = _check_thresholds(bench, budget)
  if failures:
    print("Kernel perf budget gate: FAILED")
    for line in failures:
      print(f"- {line}")
    return 1

  print("Kernel perf budget gate: PASSED")
  print(json.dumps(bench, sort_keys=True, separators=(",", ":")))
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
