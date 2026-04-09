#!/usr/bin/env python3
import json
import os
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List


class TxnState(str, Enum):
  IDLE = "idle"
  PREPARED = "prepared"
  COMMITTED = "committed"
  ROLLED_BACK = "rolled_back"


@dataclass
class AtomicUpdateTransaction:
  state: TxnState = TxnState.IDLE
  transaction_id: str = ""
  manifest_hash: str = ""
  staged_packages: List[str] = field(default_factory=list)
  rollback_reason: str = ""

  def begin(self, transaction_id: str, manifest_hash: str) -> None:
    if self.state != TxnState.IDLE:
      raise ValueError("transaction already active")
    if not transaction_id or not manifest_hash:
      raise ValueError("transaction_id and manifest_hash are required")
    self.state = TxnState.PREPARED
    self.transaction_id = transaction_id
    self.manifest_hash = manifest_hash
    self.staged_packages = []
    self.rollback_reason = ""

  def stage_package(self, package_name: str) -> None:
    if self.state != TxnState.PREPARED:
      raise ValueError("can stage only in prepared state")
    if not package_name:
      raise ValueError("package_name is required")
    if package_name not in self.staged_packages:
      self.staged_packages.append(package_name)

  def commit(self) -> None:
    if self.state != TxnState.PREPARED:
      raise ValueError("can commit only in prepared state")
    if not self.staged_packages:
      raise ValueError("cannot commit transaction with no staged packages")
    self.state = TxnState.COMMITTED

  def rollback(self, reason: str) -> None:
    if self.state not in (TxnState.PREPARED, TxnState.COMMITTED):
      raise ValueError("can rollback only prepared or committed transaction")
    self.state = TxnState.ROLLED_BACK
    self.rollback_reason = reason or "rollback_requested"

  def reset(self) -> None:
    self.state = TxnState.IDLE
    self.transaction_id = ""
    self.manifest_hash = ""
    self.staged_packages = []
    self.rollback_reason = ""

  def summary_json(self) -> str:
    return json.dumps(
        {
            "schema_version": 1,
            "state": self.state.value,
            "transaction_id": self.transaction_id,
            "manifest_hash": self.manifest_hash,
            "staged_count": len(self.staged_packages),
            "staged_packages": list(self.staged_packages),
            "rollback_reason": self.rollback_reason,
        },
        separators=(",", ":"),
    )

  def load_from_json(self, payload: str) -> None:
    data = json.loads(payload)
    if not isinstance(data, dict):
      raise ValueError("payload must be a JSON object")
    if data.get("schema_version") != 1:
      raise ValueError("unsupported schema_version")
    state = data.get("state")
    if state not in {s.value for s in TxnState}:
      raise ValueError("invalid transaction state")
    transaction_id = data.get("transaction_id", "")
    manifest_hash = data.get("manifest_hash", "")
    rollback_reason = data.get("rollback_reason", "")
    staged_packages = data.get("staged_packages", [])
    staged_count = data.get("staged_count", len(staged_packages))
    if not isinstance(transaction_id, str) or not isinstance(manifest_hash, str):
      raise ValueError("transaction_id and manifest_hash must be strings")
    if not isinstance(rollback_reason, str):
      raise ValueError("rollback_reason must be a string")
    if not isinstance(staged_packages, list) or not all(isinstance(x, str) and x for x in staged_packages):
      raise ValueError("staged_packages must be a list of non-empty strings")
    if not isinstance(staged_count, int) or staged_count < 0:
      raise ValueError("staged_count must be a non-negative integer")
    deduped = []
    for pkg in staged_packages:
      if pkg not in deduped:
        deduped.append(pkg)
    if state == TxnState.PREPARED.value and (not transaction_id or not manifest_hash):
      raise ValueError("prepared transaction requires transaction_id and manifest_hash")
    if staged_count != len(deduped):
      raise ValueError("staged_count mismatch with staged_packages")
    if state == TxnState.COMMITTED.value:
      if not transaction_id or not manifest_hash or not deduped:
        raise ValueError("committed transaction requires id/hash/staged packages")
    if state == TxnState.IDLE.value:
      if transaction_id or manifest_hash or deduped or rollback_reason:
        raise ValueError("idle transaction must not contain active fields")
    self.state = TxnState(state)
    self.transaction_id = transaction_id
    self.manifest_hash = manifest_hash
    self.staged_packages = deduped
    self.rollback_reason = rollback_reason

  def save_to_file(self, path: str) -> None:
    if not path:
      raise ValueError("path is required")
    target = Path(path)
    if target.exists() and target.is_dir():
      raise ValueError("path must be a file path, not a directory")
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = self.summary_json()
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=str(target.parent),
        prefix=f".{target.name}.",
        suffix=".tmp",
        delete=False,
    ) as tmp:
      tmp.write(payload)
      temp_path = tmp.name
    os.replace(temp_path, target)

  def load_from_file(self, path: str) -> None:
    if not path:
      raise ValueError("path is required")
    source = Path(path)
    if not source.exists() or source.is_dir():
      raise ValueError("path must point to an existing file")
    self.load_from_json(source.read_text(encoding="utf-8"))


def demo() -> int:
  txn = AtomicUpdateTransaction()
  txn.begin("demo-txn", "sha256:demo")
  txn.stage_package("aegis-kernel")
  txn.stage_package("aegis-security-core")
  txn.commit()
  print(txn.summary_json())
  return 0


if __name__ == "__main__":
  raise SystemExit(demo())
