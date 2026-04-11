#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
from typing import Dict, List


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY_PATH = ROOT / "packages" / "core" / "security-key-rotation-policy.json"


def load_policy(path: Path = DEFAULT_POLICY_PATH) -> Dict[str, object]:
  if not path.exists():
    raise ValueError(f"policy file missing: {path}")
  policy = json.loads(path.read_text(encoding="utf-8"))
  if not isinstance(policy, dict) or policy.get("schema_version") != 1:
    raise ValueError("invalid rotation policy schema")
  if not isinstance(policy.get("default_max_age_days"), int) or policy["default_max_age_days"] <= 0:
    raise ValueError("default_max_age_days must be positive integer")
  if not isinstance(policy.get("warning_window_days"), int) or policy["warning_window_days"] < 0:
    raise ValueError("warning_window_days must be non-negative integer")
  if not isinstance(policy.get("critical_window_days"), int) or policy["critical_window_days"] < 0:
    raise ValueError("critical_window_days must be non-negative integer")
  classes = policy.get("key_classes", {})
  if not isinstance(classes, dict):
    raise ValueError("key_classes must be an object")
  for name, entry in classes.items():
    if not isinstance(entry, dict):
      raise ValueError(f"invalid key class entry: {name}")
    max_age = entry.get("max_age_days")
    if not isinstance(max_age, int) or max_age <= 0:
      raise ValueError(f"invalid max_age_days for class: {name}")
  return policy


def _class_max_age_days(policy: Dict[str, object], key_class: str) -> int:
  classes = policy.get("key_classes", {})
  if isinstance(classes, dict) and key_class in classes:
    entry = classes[key_class]
    if isinstance(entry, dict) and isinstance(entry.get("max_age_days"), int):
      return int(entry["max_age_days"])
  return int(policy["default_max_age_days"])


def evaluate_keys(policy: Dict[str, object],
                  keys: List[Dict[str, object]],
                  now_epoch: int) -> Dict[str, object]:
  if not isinstance(now_epoch, int) or now_epoch < 0:
    raise ValueError("now_epoch must be non-negative integer")
  if not isinstance(keys, list):
    raise ValueError("keys must be a list")
  warning_window = int(policy["warning_window_days"])
  critical_window = int(policy["critical_window_days"])
  results = []
  due_count = 0
  critical_count = 0
  for key in keys:
    if not isinstance(key, dict):
      raise ValueError("each key entry must be object")
    key_id = str(key.get("key_id", "")).strip()
    key_class = str(key.get("key_class", "")).strip()
    last_rotated_epoch = key.get("last_rotated_epoch")
    if not key_id or not key_class:
      raise ValueError("key_id and key_class are required")
    if not isinstance(last_rotated_epoch, int) or last_rotated_epoch < 0:
      raise ValueError("last_rotated_epoch must be non-negative integer")
    max_age_days = _class_max_age_days(policy, key_class)
    age_days = (now_epoch - last_rotated_epoch) / 86400.0
    days_until_due = max_age_days - age_days
    status = "ok"
    if days_until_due <= critical_window:
      status = "critical"
      critical_count += 1
      due_count += 1
    elif days_until_due <= warning_window:
      status = "warning"
      due_count += 1
    results.append(
        {
            "key_id": key_id,
            "key_class": key_class,
            "max_age_days": max_age_days,
            "age_days": round(age_days, 2),
            "days_until_due": round(days_until_due, 2),
            "status": status,
        }
    )
  overall = "ok"
  if critical_count > 0:
    overall = "critical"
  elif due_count > 0:
    overall = "warning"
  return {
      "schema_version": 1,
      "evaluated_key_count": len(results),
      "due_count": due_count,
      "critical_count": critical_count,
      "overall_status": overall,
      "keys": results,
  }


def parse_args() -> argparse.Namespace:
  parser = argparse.ArgumentParser(description="Security key rotation schedule enforcer.")
  parser.add_argument("--keys-json", required=True, help="Path to JSON array of key entries")
  parser.add_argument("--now-epoch", required=True, type=int, help="Current epoch seconds")
  parser.add_argument("--policy-json", default=str(DEFAULT_POLICY_PATH), help="Optional policy path")
  return parser.parse_args()


def main() -> int:
  args = parse_args()
  policy = load_policy(Path(args.policy_json))
  keys = json.loads(Path(args.keys_json).read_text(encoding="utf-8"))
  report = evaluate_keys(policy, keys, args.now_epoch)
  print(json.dumps(report, separators=(",", ":")))
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
