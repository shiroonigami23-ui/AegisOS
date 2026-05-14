#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


def _load_history(path: Path) -> list[dict]:
  if not path.exists():
    return []
  rows = []
  for line in path.read_text(encoding="utf-8").splitlines():
    line = line.strip()
    if not line:
      continue
    try:
      payload = json.loads(line)
      if isinstance(payload, dict):
        rows.append(payload)
    except json.JSONDecodeError:
      continue
  return rows


def main() -> int:
  parser = argparse.ArgumentParser(description="Perf scorecard threshold gate")
  parser.add_argument("--history", default="benchmarks/history/perf_scorecard_history.jsonl")
  parser.add_argument("--max-relative-drop", type=float, default=0.05)
  parser.add_argument("--min-samples", type=int, default=5)
  args = parser.parse_args()

  root = Path(__file__).resolve().parents[1]
  rows = _load_history(root / args.history)
  if len(rows) < args.min_samples:
    print("Perf scorecard gate: PASSED")
    print(f"insufficient_history={len(rows)}")
    return 0

  current = float(rows[-1].get("composite_score", 0.0))
  baseline_slice = rows[-args.min_samples:-1]
  baseline = sum(float(r.get("composite_score", 0.0)) for r in baseline_slice) / max(1, len(baseline_slice))
  if baseline <= 0:
    print("Perf scorecard gate: PASSED")
    print("baseline_non_positive")
    return 0

  relative_drop = (baseline - current) / baseline
  if relative_drop > args.max_relative_drop:
    print("Perf scorecard gate: FAILED")
    print(f"current={current}")
    print(f"baseline={baseline}")
    print(f"relative_drop={relative_drop}")
    return 1

  print("Perf scorecard gate: PASSED")
  print(f"current={current}")
  print(f"baseline={baseline}")
  print(f"relative_drop={relative_drop}")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
