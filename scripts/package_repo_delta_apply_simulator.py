#!/usr/bin/env python3
import argparse
import json
from dataclasses import dataclass
from typing import Dict


@dataclass
class DeltaApplyResult:
  status: str
  applied_via: str
  target_version: str
  message: str

  def to_json(self) -> str:
    return json.dumps(
        {
            "schema_version": 1,
            "status": self.status,
            "applied_via": self.applied_via,
            "target_version": self.target_version,
            "message": self.message,
        },
        separators=(",", ":"),
    )


def validate_delta_manifest(manifest: Dict[str, str]) -> None:
  required = [
      "name",
      "version",
      "delta_base_version",
      "delta_payload_digest",
      "delta_fallback_full_digest",
  ]
  for key in required:
    if key not in manifest or not str(manifest[key]).strip():
      raise ValueError(f"manifest missing required field: {key}")
  if not str(manifest["delta_payload_digest"]).startswith("sha256:"):
    raise ValueError("delta_payload_digest must start with sha256:")
  if not str(manifest["delta_fallback_full_digest"]).startswith("sha256:"):
    raise ValueError("delta_fallback_full_digest must start with sha256:")


def simulate_delta_apply(manifest: Dict[str, str],
                         installed_version: str,
                         provided_delta_digest: str,
                         provided_full_digest: str) -> DeltaApplyResult:
  validate_delta_manifest(manifest)
  target_version = str(manifest["version"])
  expected_base = str(manifest["delta_base_version"])
  expected_delta = str(manifest["delta_payload_digest"])
  expected_full = str(manifest["delta_fallback_full_digest"])
  if installed_version != expected_base:
    return DeltaApplyResult(
        status="rejected",
        applied_via="none",
        target_version=target_version,
        message="installed version does not match delta base",
    )
  if provided_delta_digest == expected_delta:
    return DeltaApplyResult(
        status="applied",
        applied_via="delta",
        target_version=target_version,
        message="delta payload accepted",
    )
  if provided_full_digest == expected_full:
    return DeltaApplyResult(
        status="applied",
        applied_via="full_fallback",
        target_version=target_version,
        message="delta failed integrity; full fallback accepted",
    )
  return DeltaApplyResult(
      status="rejected",
      applied_via="none",
      target_version=target_version,
      message="both delta and full fallback digests invalid",
  )


def parse_args() -> argparse.Namespace:
  parser = argparse.ArgumentParser(description="Simulate package delta apply with fallback logic.")
  parser.add_argument("--manifest-json", required=True, help="Path to manifest json file")
  parser.add_argument("--installed-version", required=True)
  parser.add_argument("--provided-delta-digest", required=True)
  parser.add_argument("--provided-full-digest", required=True)
  return parser.parse_args()


def main() -> int:
  args = parse_args()
  with open(args.manifest_json, "r", encoding="utf-8") as f:
    manifest = json.load(f)
  result = simulate_delta_apply(
      manifest=manifest,
      installed_version=args.installed_version,
      provided_delta_digest=args.provided_delta_digest,
      provided_full_digest=args.provided_full_digest,
  )
  print(result.to_json())
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
