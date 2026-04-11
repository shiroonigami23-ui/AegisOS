#!/usr/bin/env python3
import argparse
import hashlib
import hmac
import json
from pathlib import Path
from typing import Dict, Tuple


ROOT = Path(__file__).resolve().parents[1]


def parse_simple_yaml(path: Path) -> Dict[str, object]:
  data: Dict[str, object] = {}
  current_list_key = None
  for raw in path.read_text(encoding="utf-8").splitlines():
    line = raw.rstrip()
    if not line or line.lstrip().startswith("#"):
      continue
    stripped = line.lstrip()
    if stripped.startswith("- "):
      if current_list_key is None:
        raise ValueError(f"{path}: list item without parent key")
      data.setdefault(current_list_key, []).append(stripped[2:].strip())
      continue
    if ":" not in line:
      raise ValueError(f"{path}: invalid line: {line}")
    key, value = line.split(":", 1)
    key = key.strip()
    value = value.strip()
    if value == "":
      current_list_key = key
      data.setdefault(key, [])
    elif value.startswith("[") and value.endswith("]"):
      inner = value[1:-1].strip()
      data[key] = [] if inner == "" else [x.strip() for x in inner.split(",") if x.strip()]
      current_list_key = None
    else:
      data[key] = value
      current_list_key = None
  return data


def canonical_signing_payload(name: str, version: str, manifest_path: str, signature_digest: str) -> bytes:
  return f"{name}|{version}|{manifest_path}|{signature_digest}".encode("utf-8")


def hmac_sha256_hex(secret: str, payload: bytes) -> str:
  mac = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256)
  return mac.hexdigest()


def compute_manifest_digest(manifest_path: Path) -> str:
  content = manifest_path.read_bytes()
  return "sha256:" + hashlib.sha256(content).hexdigest()


def load_signature_policy(policy_json_path: Path) -> Dict[str, str]:
  payload = json.loads(policy_json_path.read_text(encoding="utf-8"))
  if int(payload.get("schema_version", 0)) != 1:
    raise ValueError("signature policy schema_version must be 1")
  fmt = str(payload.get("signature_format", ""))
  prefix = str(payload.get("allowed_key_id_prefix", ""))
  digest_algo = str(payload.get("digest_algorithm", ""))
  if fmt != "hmac-sha256-v1":
    raise ValueError("unsupported signature_format in policy")
  if not prefix:
    raise ValueError("allowed_key_id_prefix required")
  if digest_algo != "sha256":
    raise ValueError("unsupported digest_algorithm in policy")
  return {
      "signature_format": fmt,
      "allowed_key_id_prefix": prefix,
      "digest_prefix": f"{digest_algo}:",
  }


def verify_package_entry(entry: Dict[str, object],
                         keyring: Dict[str, str],
                         base_dir: Path = ROOT,
                         signature_format: str = "hmac-sha256-v1",
                         key_id_prefix: str = "aegis-hmac-",
                         digest_prefix: str = "sha256:") -> Tuple[bool, str]:
  required = [
      "name",
      "version",
      "manifest_path",
      "signature_format",
      "signature_key_id",
      "signature_digest",
      "signature_value",
  ]
  for field in required:
    if field not in entry:
      return False, f"missing_{field}"
  if entry["signature_format"] != signature_format:
    return False, "unsupported_signature_format"
  if not str(entry["signature_key_id"]).startswith(key_id_prefix):
    return False, "signature_key_id_prefix_mismatch"
  if not str(entry["signature_digest"]).startswith(digest_prefix):
    return False, "signature_digest_prefix_mismatch"

  key_id = str(entry["signature_key_id"])
  secret = keyring.get(key_id)
  if not secret:
    return False, "missing_keyring_secret"
  if len(secret) < 16:
    return False, "weak_keyring_secret"

  manifest_path = base_dir / str(entry["manifest_path"])
  if not manifest_path.exists():
    return False, "manifest_missing"
  computed_digest = compute_manifest_digest(manifest_path)
  if computed_digest != entry["signature_digest"]:
    return False, "signature_digest_mismatch"

  payload = canonical_signing_payload(
      str(entry["name"]),
      str(entry["version"]),
      str(entry["manifest_path"]),
      str(entry["signature_digest"]),
  )
  expected_sig = hmac_sha256_hex(secret, payload)
  if not hmac.compare_digest(expected_sig, str(entry["signature_value"])):
    return False, "signature_value_mismatch"

  manifest = parse_simple_yaml(manifest_path)
  if manifest.get("name") != entry["name"] or manifest.get("version") != entry["version"]:
    return False, "manifest_identity_mismatch"
  return True, "ok"


def verify_repository_index(index_json_path: Path,
                            keyring: Dict[str, str],
                            base_dir: Path = ROOT,
                            policy: Dict[str, str] = None) -> Dict[str, object]:
  payload = json.loads(index_json_path.read_text(encoding="utf-8"))
  packages = payload.get("packages", [])
  if not isinstance(packages, list) or not packages:
    raise ValueError("repository index packages must be non-empty list")
  verdicts = []
  ok_count = 0
  effective_policy = policy or {
      "signature_format": "hmac-sha256-v1",
      "allowed_key_id_prefix": "aegis-hmac-",
      "digest_prefix": "sha256:",
  }
  for entry in packages:
    ok, reason = verify_package_entry(
        entry,
        keyring=keyring,
        base_dir=base_dir,
        signature_format=effective_policy["signature_format"],
        key_id_prefix=effective_policy["allowed_key_id_prefix"],
        digest_prefix=effective_policy["digest_prefix"],
    )
    verdicts.append({
        "name": entry.get("name", ""),
        "version": entry.get("version", ""),
        "ok": 1 if ok else 0,
        "reason": reason,
    })
    if ok:
      ok_count += 1
  return {
      "schema_version": 1,
      "index_path": str(index_json_path),
      "total": len(packages),
      "ok_count": ok_count,
      "failed_count": len(packages) - ok_count,
      "all_ok": 1 if ok_count == len(packages) else 0,
      "verdicts": verdicts,
  }


def main() -> int:
  parser = argparse.ArgumentParser(description="Verify real package signatures (HMAC-SHA256).")
  parser.add_argument("--index-json", default=str(ROOT / "packages" / "repository-index.json"))
  parser.add_argument("--policy-json", default=str(ROOT / "packages" / "core" / "package-signature-policy.json"))
  parser.add_argument("--keyring-json", required=True, help="JSON object of {key_id: secret}")
  args = parser.parse_args()

  keyring = json.loads(Path(args.keyring_json).read_text(encoding="utf-8"))
  if not isinstance(keyring, dict) or not keyring:
    raise ValueError("keyring json must be non-empty object")
  policy = load_signature_policy(Path(args.policy_json))
  report = verify_repository_index(Path(args.index_json), keyring=keyring, base_dir=ROOT, policy=policy)
  print(json.dumps(report, separators=(",", ":"), sort_keys=True))
  return 0 if report["all_ok"] else 1


if __name__ == "__main__":
  try:
    raise SystemExit(main())
  except (ValueError, json.JSONDecodeError) as exc:
    print(f"Signature verification failed: {exc}")
    raise SystemExit(1)
