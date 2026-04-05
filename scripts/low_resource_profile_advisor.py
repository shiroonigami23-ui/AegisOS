#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
from typing import Dict, List


CPU_CLASSES = {"legacy", "entry", "mid", "high"}
RAM_CLASSES = {"ultra_low", "low", "mid", "high"}
ROOT = Path(__file__).resolve().parents[1]
PROFILES_DIR = ROOT / "packages" / "profiles"


def _validate_class(name: str, value: str, allowed: set) -> str:
  if value not in allowed:
    raise ValueError(f"invalid {name}: {value} (allowed: {', '.join(sorted(allowed))})")
  return value


def _load_profile_packages(profile_name: str) -> List[str]:
  manifest_path = PROFILES_DIR / f"{profile_name}.yaml"
  packages: List[str] = []
  in_packages = False
  if not manifest_path.exists():
    raise ValueError(f"profile manifest missing: {manifest_path}")
  for line in manifest_path.read_text(encoding="utf-8").splitlines():
    if line.strip() == "packages:":
      in_packages = True
      continue
    if not in_packages:
      continue
    stripped = line.strip()
    if not stripped:
      continue
    if not stripped.startswith("- "):
      break
    packages.append(stripped[2:].strip())
  if not packages:
    raise ValueError(f"profile manifest has no packages: {manifest_path}")
  return packages


def recommend_profile(cpu_class: str, ram_class: str) -> Dict[str, object]:
  cpu = _validate_class("cpu_class", cpu_class, CPU_CLASSES)
  ram = _validate_class("ram_class", ram_class, RAM_CLASSES)

  profile = "desktop"
  rationale: List[str] = []
  alternatives: List[str] = []
  tuning: List[str] = []

  if ram == "ultra_low" or cpu == "legacy":
    profile = "minimal"
    rationale.append("Prioritizes boot reliability and low memory footprint on constrained hardware.")
    alternatives = ["server"]
    tuning = [
        "Disable background indexing and telemetry-heavy services.",
        "Prefer lightweight shell and avoid desktop compositor.",
        "Cap service worker pools to reduce memory pressure.",
    ]
  elif ram == "low" or cpu == "entry":
    profile = "server"
    rationale.append("Reduces UI overhead while keeping core services and security hardening.")
    alternatives = ["minimal", "desktop"]
    tuning = [
        "Use text-first administration tools where possible.",
        "Enable memory-pressure reclaim hooks aggressively.",
        "Keep startup target to essential services only.",
    ]
  elif ram == "mid" and cpu in {"mid", "high"}:
    profile = "desktop"
    rationale.append("Balanced interactive experience with acceptable power and memory usage.")
    alternatives = ["server", "developer"]
    tuning = [
        "Keep desktop shell but disable non-essential visual effects.",
        "Prefer adaptive scheduler profile for mixed foreground/background workloads.",
        "Enable package prefetch only for frequently used apps.",
    ]
  else:
    profile = "developer"
    rationale.append("High-resource configuration can support SDK tooling and local build workloads.")
    alternatives = ["desktop", "server"]
    tuning = [
        "Increase build cache and sandbox worker concurrency.",
        "Enable developer SDK and diagnostics collectors.",
        "Set background tasks to low-priority scheduling class.",
    ]

  packages = _load_profile_packages(profile)

  return {
      "schema_version": 1,
      "cpu_class": cpu,
      "ram_class": ram,
      "recommended_profile": profile,
      "profile_manifest": str((PROFILES_DIR / f"{profile}.yaml").relative_to(ROOT)).replace("\\", "/"),
      "package_count": len(packages),
      "sample_packages": packages[:5],
      "alternatives": alternatives,
      "rationale": rationale,
      "tuning_advice": tuning,
  }


def parse_args() -> argparse.Namespace:
  parser = argparse.ArgumentParser(
      description="Recommend AegisOS profile for low-resource hardware classes."
  )
  parser.add_argument("--cpu-class", required=True, choices=sorted(CPU_CLASSES))
  parser.add_argument("--ram-class", required=True, choices=sorted(RAM_CLASSES))
  return parser.parse_args()


def main() -> int:
  args = parse_args()
  recommendation = recommend_profile(args.cpu_class, args.ram_class)
  print(json.dumps(recommendation, separators=(",", ":")))
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
