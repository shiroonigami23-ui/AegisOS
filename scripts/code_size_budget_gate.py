#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


def _load_json(path: Path) -> dict:
  data = json.loads(path.read_text(encoding="utf-8-sig"))
  if not isinstance(data, dict):
    raise ValueError(f"invalid JSON in {path}")
  return data


def _count_loc(path: Path) -> int:
  loc = 0
  for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
    s = line.strip()
    if not s or s.startswith("//") or s.startswith("#"):
      continue
    loc += 1
  return loc


def main() -> int:
  parser = argparse.ArgumentParser(description="Code size budget gate")
  parser.add_argument("--budget", default="docs/CODE_SIZE_BUDGET.json")
  args = parser.parse_args()

  root = Path(__file__).resolve().parents[1]
  budget = _load_json(root / args.budget)
  budgets = budget.get("budgets", {})
  failures = []
  report = {}

  for name, cfg in budgets.items():
    glob = str(cfg.get("glob", ""))
    max_loc = int(cfg.get("max_loc", 0))
    files = sorted(root.glob(glob))
    total = sum(_count_loc(p) for p in files if p.is_file())
    report[name] = {"glob": glob, "max_loc": max_loc, "actual_loc": total, "file_count": len(files)}
    if total > max_loc:
      failures.append(f"{name}: {total} > {max_loc} ({glob})")

  if failures:
    print("Code size budget gate: FAILED")
    for f in failures:
      print(f"- {f}")
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 1

  print("Code size budget gate: PASSED")
  print(json.dumps(report, sort_keys=True, separators=(",", ":")))
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
