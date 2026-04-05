#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path


SCHEMA_VERSION = 1
KNOWN_MASK = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4)
REQUIRED_BASE_FIELDS = [
    "process_id",
    "capabilities",
    "allow_fs_read",
    "allow_fs_write",
    "allow_net_client",
    "allow_net_server",
    "allow_device_io",
]


def validate_policy(policy):
    pid = int(policy.get("process_id", 0))
    caps = int(policy.get("capabilities", 0))
    fs_read = int(policy.get("allow_fs_read", 0))
    fs_write = int(policy.get("allow_fs_write", 0))
    net_client = int(policy.get("allow_net_client", 0))
    net_server = int(policy.get("allow_net_server", 0))
    device_io = int(policy.get("allow_device_io", 0))
    schema_version = int(policy.get("schema_version", SCHEMA_VERSION))

    if pid == 0:
        return False, "process_id must be non-zero"
    if caps & ~KNOWN_MASK:
        return False, "policy includes unknown capability bits"
    if schema_version != SCHEMA_VERSION:
        return False, "unsupported sandbox policy schema_version"
    if fs_read and not (caps & (1 << 0)):
        return False, "allow_fs_read set but FS_READ capability missing"
    if fs_write and not (caps & (1 << 1)):
        return False, "allow_fs_write set but FS_WRITE capability missing"
    if net_client and not (caps & (1 << 2)):
        return False, "allow_net_client set but NET_CLIENT capability missing"
    if net_server and not (caps & (1 << 3)):
        return False, "allow_net_server set but NET_SERVER capability missing"
    if device_io and not (caps & (1 << 4)):
        return False, "allow_device_io set but DEVICE_IO capability missing"
    if net_server and not net_client:
        return False, "server mode requires client networking enabled"
    return True, "ok"


def migrate_doc(raw):
    missing = [k for k in REQUIRED_BASE_FIELDS if k not in raw]
    if missing:
        return None, "missing required fields: " + ",".join(missing), "failed"

    migrated = dict(raw)
    if "schema_version" not in migrated:
        migrated["schema_version"] = SCHEMA_VERSION
    if "policy_revision" not in migrated:
        migrated["policy_revision"] = 1

    ok, reason = validate_policy(migrated)
    if not ok:
        return None, reason, "failed"

    was_legacy = ("schema_version" not in raw) or ("policy_revision" not in raw)
    return migrated, "migrated" if was_legacy else "already_current", (
        "migrated" if was_legacy else "already_current"
    )


def run_batch(input_dir, output_dir):
    input_dir = Path(input_dir)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    files = sorted(input_dir.glob("*.json"))
    summary = {
        "total": len(files),
        "migrated": 0,
        "already_current": 0,
        "failed": 0,
        "results": [],
    }
    for path in files:
        status = "failed"
        reason = ""
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            migrated, reason, status = migrate_doc(raw)
            if status != "failed":
                out_path = output_dir / path.name
                out_path.write_text(
                    json.dumps(migrated, sort_keys=True, separators=(",", ":")),
                    encoding="utf-8",
                )
        except Exception as exc:
            reason = f"parse_error: {exc}"
            status = "failed"

        summary[status] += 1
        summary["results"].append({"file": path.name, "status": status, "reason": reason})
    return summary


def main():
    parser = argparse.ArgumentParser(
        description="Batch migrate legacy AegisOS sandbox policy JSON documents."
    )
    parser.add_argument("--input-dir", required=True, help="Directory containing input .json policies")
    parser.add_argument("--output-dir", required=True, help="Directory for migrated .json policies")
    parser.add_argument("--summary-json", help="Optional path to write migration summary JSON")
    args = parser.parse_args()

    summary = run_batch(args.input_dir, args.output_dir)
    print(
        f"total={summary['total']} migrated={summary['migrated']} "
        f"already_current={summary['already_current']} failed={summary['failed']}"
    )

    if args.summary_json:
        Path(args.summary_json).write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    if summary["failed"] > 0:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
