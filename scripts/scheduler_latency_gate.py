#!/usr/bin/env python3
import argparse
import json
import subprocess
import sys
from pathlib import Path


def _load_json(path: Path) -> dict:
  data = json.loads(path.read_text(encoding="utf-8-sig"))
  if not isinstance(data, dict):
    raise ValueError(f"invalid JSON object in {path}")
  return data


def _run_scheduler_bench(root: Path, ticks: int, seed: int) -> dict:
  cmd = [
      sys.executable,
      str(root / "scripts" / "scheduler_turbo_benchmark.py"),
      "--ticks",
      str(ticks),
      "--seed",
      str(seed),
  ]
  out = subprocess.run(cmd, cwd=root, capture_output=True, text=True, check=True)
  payload = json.loads(out.stdout)
  if not isinstance(payload, dict):
    raise ValueError("scheduler benchmark output invalid")
  return payload


def main() -> int:
  parser = argparse.ArgumentParser(description="Scheduler latency budget gate (p50/p95/p99).")
  parser.add_argument("--budget", default="docs/LATENCY_BUDGET.json")
  parser.add_argument("--profile", default="desktop")
  parser.add_argument("--ticks", type=int, default=800)
  parser.add_argument("--seed", type=int, default=1337)
  args = parser.parse_args()

  root = Path(__file__).resolve().parents[1]
  budget = _load_json(root / args.budget)
  profiles = budget.get("profiles", {})
  if args.profile not in profiles:
    raise ValueError(f"unknown profile '{args.profile}'")
  limits = profiles[args.profile]["turbo"]

  bench = _run_scheduler_bench(root, args.ticks, args.seed)
  turbo = bench.get("turbo", {})

  checks = [
      ("p50_wait", "max_p50_wait"),
      ("p95_wait", "max_p95_wait"),
      ("p99_wait", "max_p99_wait"),
      ("high_priority_p95_wait", "max_high_priority_p95_wait"),
      ("mean_wait", "max_mean_wait"),
  ]

  failures = []
  for metric_key, max_key in checks:
    actual = float(turbo.get(metric_key, 0))
    allowed = float(limits.get(max_key, 0))
    if actual > allowed:
      failures.append(f"{metric_key}: {actual} > {allowed}")

  if failures:
    print("Scheduler latency gate: FAILED")
    print(f"profile={args.profile}")
    for f in failures:
      print(f"- {f}")
    return 1

  print("Scheduler latency gate: PASSED")
  print(f"profile={args.profile}")
  print(json.dumps(bench, sort_keys=True, separators=(",", ":")))
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
