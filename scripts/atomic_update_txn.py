#!/usr/bin/env python3
import json
from dataclasses import dataclass, field
from enum import Enum
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
    if not isinstance(transaction_id, str) or not isinstance(manifest_hash, str):
      raise ValueError("transaction_id and manifest_hash must be strings")
    if not isinstance(rollback_reason, str):
      raise ValueError("rollback_reason must be a string")
    if not isinstance(staged_packages, list) or not all(isinstance(x, str) and x for x in staged_packages):
      raise ValueError("staged_packages must be a list of non-empty strings")
    deduped = []
    for pkg in staged_packages:
      if pkg not in deduped:
        deduped.append(pkg)
    if state == TxnState.PREPARED.value and (not transaction_id or not manifest_hash):
      raise ValueError("prepared transaction requires transaction_id and manifest_hash")
    self.state = TxnState(state)
    self.transaction_id = transaction_id
    self.manifest_hash = manifest_hash
    self.staged_packages = deduped
    self.rollback_reason = rollback_reason


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
