#!/usr/bin/env python3
import argparse
import json
import math
from pathlib import Path
from typing import Dict, List


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "packages" / "profiles" / "boot-budget-policy.json"
PROFILES_DIR = ROOT / "packages" / "profiles"
THERMAL_STATES = {"nominal", "elevated", "throttled"}


def _load_profile_package_count(profile_name: str) -> int:
  manifest = PROFILES_DIR / f"{profile_name}.yaml"
  if not manifest.exists():
    raise ValueError(f"profile manifest not found: {manifest}")
  count = 0
  in_packages = False
  for line in manifest.read_text(encoding="utf-8").splitlines():
    stripped = line.strip()
    if stripped == "packages:":
      in_packages = True
      continue
    if in_packages and stripped.startswith("- "):
      count += 1
    elif in_packages and stripped:
      break
  if count == 0:
    raise ValueError(f"profile manifest has no packages: {manifest}")
  return count


def load_budget_policy(path: Path = POLICY_PATH) -> Dict[str, object]:
  if not path.exists():
    raise ValueError(f"budget policy missing: {path}")
  data = json.loads(path.read_text(encoding="utf-8"))
  if not isinstance(data, dict) or data.get("schema_version") != 1:
    raise ValueError("invalid boot budget policy schema")
  profiles = data.get("profiles", {})
  if not isinstance(profiles, dict) or not profiles:
    raise ValueError("boot budget policy profiles missing")
  for profile_name, entry in profiles.items():
    if not isinstance(entry, dict):
      raise ValueError(f"invalid profile budget entry: {profile_name}")
    cold = entry.get("cold_boot_budget_s")
    warm = entry.get("warm_boot_budget_s")
    if not isinstance(cold, (int, float)) or not isinstance(warm, (int, float)):
      raise ValueError(f"invalid boot budget values for profile: {profile_name}")
    if cold <= 0 or warm <= 0:
      raise ValueError(f"boot budget values must be positive for profile: {profile_name}")
  return data


def _percentile(sorted_values: List[float], pct: float) -> float:
  if not sorted_values:
    return 0.0
  idx = (len(sorted_values) - 1) * pct
  lo = int(math.floor(idx))
  hi = int(math.ceil(idx))
  if lo == hi:
    return sorted_values[lo]
  return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * (idx - lo)


def _resolve_mode(battery_percent: float, thermal_state: str) -> str:
  if thermal_state == "throttled":
    return "thermal_throttled"
  if battery_percent <= 20.0:
    return "low_battery"
  if thermal_state == "elevated":
    return "thermal_elevated"
  return "balanced"


def _recommend_actions(mode: str, profile_name: str, boot_type: str) -> List[Dict[str, object]]:
  actions: List[Dict[str, object]] = []
  if mode == "thermal_throttled":
    actions.extend([
        {
            "action": "defer_noncritical_services",
            "estimated_savings_s": 1.2,
            "priority": "high",
        },
        {
            "action": "reduce_parallel_startup_fanout",
            "estimated_savings_s": 0.7,
            "priority": "high",
        },
        {
            "action": "enable_service_checkpoint_resume",
            "estimated_savings_s": 0.4,
            "priority": "medium",
        },
    ])
  elif mode in {"low_battery", "thermal_elevated"}:
    actions.extend([
        {
            "action": "switch_to_low_power_boot_profile",
            "estimated_savings_s": 0.9,
            "priority": "high",
        },
        {
            "action": "delay_background_indexers",
            "estimated_savings_s": 0.5,
            "priority": "medium",
        },
    ])
    if boot_type == "cold":
      actions.append({
          "action": "use_cached_driver_probe_results",
          "estimated_savings_s": 0.3,
          "priority": "medium",
      })
  if profile_name == "developer":
    actions.append({
        "action": "defer_optional_dev_tooling_units",
        "estimated_savings_s": 0.6,
        "priority": "medium",
    })
  return actions


def _mode_budget_adjustment(mode: str) -> float:
  if mode == "thermal_throttled":
    return -1.2
  if mode in {"low_battery", "thermal_elevated"}:
    return -0.6
  return 0.0


def evaluate_boot_samples(profile_name: str,
                          boot_type: str,
                          samples_seconds: List[float],
                          battery_percent: float = 100.0,
                          thermal_state: str = "nominal",
                          policy: Dict[str, object] | None = None) -> Dict[str, object]:
  if policy is None:
    policy = load_budget_policy()
  if boot_type not in {"cold", "warm"}:
    raise ValueError("boot_type must be 'cold' or 'warm'")
  if not isinstance(battery_percent, (int, float)) or battery_percent < 0 or battery_percent > 100:
    raise ValueError("battery_percent must be in [0, 100]")
  if thermal_state not in THERMAL_STATES:
    raise ValueError(f"thermal_state must be one of {sorted(THERMAL_STATES)}")
  profiles = policy["profiles"]
  if profile_name not in profiles:
    raise ValueError(f"unknown profile: {profile_name}")
  if not isinstance(samples_seconds, list) or not samples_seconds:
    raise ValueError("samples_seconds must be a non-empty list")
  samples: List[float] = []
  for s in samples_seconds:
    if not isinstance(s, (int, float)) or s <= 0:
      raise ValueError("all samples must be positive numbers")
    samples.append(float(s))
  budget_key = "cold_boot_budget_s" if boot_type == "cold" else "warm_boot_budget_s"
  budget = float(profiles[profile_name][budget_key])
  pkg_count = _load_profile_package_count(profile_name)
  mode = _resolve_mode(float(battery_percent), thermal_state)
  # Dynamic slack for heavier package compositions, plus mode pressure for thermal/battery constraints.
  adjusted_budget = budget + max(0.0, (pkg_count - 5) * 0.15) + _mode_budget_adjustment(mode)
  adjusted_budget = max(1.0, adjusted_budget)
  sorted_samples = sorted(samples)
  mean = sum(samples) / len(samples)
  p95 = _percentile(sorted_samples, 0.95)
  max_sample = sorted_samples[-1]
  pass_count = sum(1 for s in samples if s <= adjusted_budget)
  pass_rate = pass_count / len(samples)
  status = "pass" if pass_rate >= 0.95 and p95 <= adjusted_budget else "fail"
  severity = "ok"
  if status == "fail":
    if p95 > adjusted_budget * 1.2 or pass_rate < 0.8:
      severity = "critical"
    else:
      severity = "warning"
  recommendations = _recommend_actions(mode, profile_name, boot_type) if status == "fail" else []
  estimated_recovery = round(sum(float(item["estimated_savings_s"]) for item in recommendations), 3)
  return {
      "schema_version": 1,
      "profile": profile_name,
      "boot_type": boot_type,
      "power_mode": mode,
      "battery_percent": round(float(battery_percent), 2),
      "thermal_state": thermal_state,
      "sample_count": len(samples),
      "package_count": pkg_count,
      "base_budget_seconds": budget,
      "adjusted_budget_seconds": round(adjusted_budget, 3),
      "mean_seconds": round(mean, 3),
      "p95_seconds": round(p95, 3),
      "max_seconds": round(max_sample, 3),
      "pass_count": pass_count,
      "pass_rate": round(pass_rate, 4),
      "status": status,
      "severity": severity,
      "optimizer_recommendations": recommendations,
      "estimated_recovery_seconds": estimated_recovery,
      "recommendation": (
          "trim startup services and parallelize critical path"
          if status == "fail"
          else "within budget"
      ),
  }


def evaluate_batch(batch_payload: Dict[str, object],
                   policy: Dict[str, object] | None = None) -> Dict[str, object]:
  if policy is None:
    policy = load_budget_policy()
  if not isinstance(batch_payload, dict):
    raise ValueError("batch payload must be an object")
  runs = batch_payload.get("runs", [])
  if not isinstance(runs, list) or not runs:
    raise ValueError("batch payload must include non-empty runs list")
  reports = []
  failures = 0
  critical = 0
  for run in runs:
    if not isinstance(run, dict):
      raise ValueError("each run must be an object")
    report = evaluate_boot_samples(
        profile_name=str(run.get("profile", "")),
        boot_type=str(run.get("boot_type", "")),
        samples_seconds=list(run.get("samples_seconds", [])),
        battery_percent=float(run.get("battery_percent", 100.0)),
        thermal_state=str(run.get("thermal_state", "nominal")),
        policy=policy,
    )
    reports.append(report)
    if report["status"] != "pass":
      failures += 1
      if report["severity"] == "critical":
        critical += 1
  return {
      "schema_version": 1,
      "total_runs": len(reports),
      "failed_runs": failures,
      "critical_failures": critical,
      "reports": reports,
  }


def _parse_samples_arg(samples_text: str) -> List[float]:
  parts = [p.strip() for p in samples_text.split(",") if p.strip()]
  if not parts:
    raise ValueError("samples arg is empty")
  return [float(p) for p in parts]


def parse_args() -> argparse.Namespace:
  parser = argparse.ArgumentParser(description="Device profile boot budget enforcer.")
  parser.add_argument("--profile", help="Profile name (minimal/server/desktop/developer)")
  parser.add_argument("--boot-type", choices=["cold", "warm"], help="Boot type")
  parser.add_argument("--samples", help="Comma-separated sample seconds, e.g. 8.2,9.1,7.9")
  parser.add_argument("--batch-json", help="Path to batch input JSON")
  parser.add_argument("--battery-percent", type=float, default=100.0, help="Battery percent [0-100]")
  parser.add_argument(
      "--thermal-state",
      choices=sorted(THERMAL_STATES),
      default="nominal",
      help="Thermal state hint for optimizer",
  )
  return parser.parse_args()


def main() -> int:
  args = parse_args()
  policy = load_budget_policy()
  if args.batch_json:
    payload = json.loads(Path(args.batch_json).read_text(encoding="utf-8"))
    report = evaluate_batch(payload, policy=policy)
  else:
    if not args.profile or not args.boot_type or not args.samples:
      raise ValueError("single-run mode requires --profile --boot-type --samples")
    report = evaluate_boot_samples(
        profile_name=args.profile,
        boot_type=args.boot_type,
        samples_seconds=_parse_samples_arg(args.samples),
        battery_percent=args.battery_percent,
        thermal_state=args.thermal_state,
        policy=policy,
    )
  print(json.dumps(report, separators=(",", ":")))
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
