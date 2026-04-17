#!/usr/bin/env python3
import json
from pathlib import Path


def main() -> int:
  repo_root = Path(__file__).resolve().parents[1]
  ledger_path = repo_root / "docs" / "SNAPSHOT_SCHEMA_LEDGER.json"
  ledger = json.loads(ledger_path.read_text(encoding="utf-8"))

  if int(ledger.get("schema_version", 0)) != 1:
    raise ValueError("Unsupported snapshot schema ledger version")

  entries = ledger.get("entries", [])
  if not isinstance(entries, list) or not entries:
    raise ValueError("Snapshot schema ledger entries must be a non-empty list")

  failures: list[str] = []
  for entry in entries:
    if not isinstance(entry, dict):
      failures.append("entry is not an object")
      continue
    entry_id = str(entry.get("id", "<unknown>"))
    rel_file = entry.get("file")
    pattern = entry.get("pattern")
    if not isinstance(rel_file, str) or not isinstance(pattern, str):
      failures.append(f"{entry_id}: invalid file/pattern")
      continue
    file_path = repo_root / rel_file
    if not file_path.exists():
      failures.append(f"{entry_id}: missing file {rel_file}")
      continue
    content = file_path.read_text(encoding="utf-8")
    normalized_content = content.replace('\\"', '"')
    normalized_pattern = pattern.replace('\\"', '"')
    if normalized_pattern not in normalized_content:
      failures.append(f"{entry_id}: pattern not found in {rel_file}")

  if failures:
    print("Snapshot schema ledger validation: FAILED")
    for failure in failures:
      print(f"- {failure}")
    return 1

  print(f"Snapshot schema ledger validation: PASSED ({len(entries)} entries)")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
