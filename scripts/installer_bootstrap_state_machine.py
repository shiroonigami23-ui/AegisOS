#!/usr/bin/env python3
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List


class InstallerState(str, Enum):
  IDLE = "idle"
  PREFLIGHT = "preflight"
  VERIFY_ARTIFACTS = "verify_artifacts"
  ATTEST = "attest"
  APPLY = "apply"
  VERIFY_BOOT = "verify_boot"
  COMPLETE = "complete"
  RECOVERY = "recovery"
  FAILED = "failed"


@dataclass
class BootstrapTransition:
  timestamp_epoch: int
  from_state: str
  to_state: str
  reason: str


@dataclass
class InstallerBootstrapStateMachine:
  state: InstallerState = InstallerState.IDLE
  install_id: str = ""
  target_channel: str = ""
  target_version: str = ""
  recoverable_failure: bool = False
  last_error: str = ""
  required_attestation_hooks: List[str] = field(default_factory=list)
  attestation_results: Dict[str, str] = field(default_factory=dict)
  transitions: List[BootstrapTransition] = field(default_factory=list)
  max_transitions: int = 512

  def _push_transition(self, timestamp_epoch: int, from_state: InstallerState, to_state: InstallerState, reason: str) -> None:
    self.transitions.append(
        BootstrapTransition(
            timestamp_epoch=timestamp_epoch,
            from_state=from_state.value,
            to_state=to_state.value,
            reason=reason,
        )
    )
    if len(self.transitions) > self.max_transitions:
      self.transitions = self.transitions[-self.max_transitions :]

  def _transition(self, to_state: InstallerState, reason: str, timestamp_epoch: int = 0) -> None:
    from_state = self.state
    self.state = to_state
    self._push_transition(timestamp_epoch, from_state, to_state, reason)

  def start_install(self,
                    install_id: str,
                    target_channel: str,
                    target_version: str,
                    required_attestation_hooks: List[str]) -> None:
    if self.state not in {InstallerState.IDLE, InstallerState.COMPLETE}:
      raise ValueError("cannot start install from current state")
    if not install_id or not target_channel or not target_version:
      raise ValueError("install_id, target_channel, target_version are required")
    if target_channel not in {"stable", "beta", "nightly"}:
      raise ValueError("invalid target_channel")
    if not isinstance(required_attestation_hooks, list) or not required_attestation_hooks:
      raise ValueError("required_attestation_hooks must be non-empty list")
    hooks = []
    for h in required_attestation_hooks:
      if not isinstance(h, str) or not h:
        raise ValueError("attestation hook names must be non-empty strings")
      if h not in hooks:
        hooks.append(h)
    self.install_id = install_id
    self.target_channel = target_channel
    self.target_version = target_version
    self.required_attestation_hooks = hooks
    self.attestation_results = {}
    self.last_error = ""
    self.recoverable_failure = False
    self._transition(InstallerState.PREFLIGHT, "install_started")

  def mark_preflight_ok(self) -> None:
    if self.state != InstallerState.PREFLIGHT:
      raise ValueError("preflight step invalid for current state")
    self._transition(InstallerState.VERIFY_ARTIFACTS, "preflight_passed")

  def mark_artifacts_verified(self) -> None:
    if self.state != InstallerState.VERIFY_ARTIFACTS:
      raise ValueError("artifact verify step invalid for current state")
    self._transition(InstallerState.ATTEST, "artifacts_verified")

  def mark_attestation_passed(self, hook_name: str, evidence_hash: str) -> None:
    if self.state != InstallerState.ATTEST:
      raise ValueError("attestation step invalid for current state")
    if hook_name not in self.required_attestation_hooks:
      raise ValueError("unknown attestation hook")
    if not evidence_hash or not evidence_hash.startswith("sha256:"):
      raise ValueError("evidence_hash must start with sha256:")
    self.attestation_results[hook_name] = evidence_hash
    if all(h in self.attestation_results for h in self.required_attestation_hooks):
      self._transition(InstallerState.APPLY, "all_attestation_hooks_passed")

  def mark_payload_applied(self) -> None:
    if self.state != InstallerState.APPLY:
      raise ValueError("apply step invalid for current state")
    self._transition(InstallerState.VERIFY_BOOT, "payload_applied")

  def mark_boot_verified(self) -> None:
    if self.state != InstallerState.VERIFY_BOOT:
      raise ValueError("boot verification invalid for current state")
    self._transition(InstallerState.COMPLETE, "boot_verified")

  def fail_current_step(self, error: str, recoverable: bool) -> None:
    if self.state in {InstallerState.IDLE, InstallerState.COMPLETE}:
      raise ValueError("cannot fail in idle/complete state")
    self.last_error = error or "unknown_failure"
    self.recoverable_failure = bool(recoverable)
    if recoverable:
      self._transition(InstallerState.RECOVERY, "recoverable_failure")
    else:
      self._transition(InstallerState.FAILED, "fatal_failure")

  def recovery_step_completed(self, success: bool) -> None:
    if self.state != InstallerState.RECOVERY:
      raise ValueError("recovery step invalid for current state")
    if success:
      self.recoverable_failure = False
      self.last_error = ""
      self._transition(InstallerState.VERIFY_ARTIFACTS, "recovery_succeeded")
    else:
      self._transition(InstallerState.FAILED, "recovery_failed")

  def reset(self) -> None:
    self.state = InstallerState.IDLE
    self.install_id = ""
    self.target_channel = ""
    self.target_version = ""
    self.recoverable_failure = False
    self.last_error = ""
    self.required_attestation_hooks = []
    self.attestation_results = {}
    self.transitions = []

  def summary_json(self) -> str:
    payload = {
        "schema_version": 1,
        "state": self.state.value,
        "install_id": self.install_id,
        "target_channel": self.target_channel,
        "target_version": self.target_version,
        "recoverable_failure": 1 if self.recoverable_failure else 0,
        "last_error": self.last_error,
        "required_attestation_hooks": list(self.required_attestation_hooks),
        "attestation_results": dict(self.attestation_results),
        "transition_count": len(self.transitions),
        "transitions": [
            {
                "timestamp_epoch": t.timestamp_epoch,
                "from_state": t.from_state,
                "to_state": t.to_state,
                "reason": t.reason,
            }
            for t in self.transitions
        ],
    }
    return json.dumps(payload, separators=(",", ":"))


def demo() -> int:
  sm = InstallerBootstrapStateMachine()
  sm.start_install("demo-install", "stable", "0.1.0", ["tpm_quote", "sbom_verify"])
  sm.mark_preflight_ok()
  sm.mark_artifacts_verified()
  sm.mark_attestation_passed("tpm_quote", "sha256:1111111111111111111111111111111111111111111111111111111111111111")
  sm.mark_attestation_passed("sbom_verify", "sha256:2222222222222222222222222222222222222222222222222222222222222222")
  sm.mark_payload_applied()
  sm.mark_boot_verified()
  print(sm.summary_json())
  return 0


if __name__ == "__main__":
  raise SystemExit(demo())
