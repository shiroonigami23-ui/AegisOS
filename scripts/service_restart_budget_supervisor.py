#!/usr/bin/env python3
import json
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class ServiceRestartPolicy:
  service: str
  max_restarts: int
  window_seconds: int
  base_backoff_seconds: int
  max_backoff_seconds: int
  jitter_percent: int = 0
  escalation_threshold: int = 5


@dataclass
class ServiceRuntimeState:
  restart_timestamps: List[int] = field(default_factory=list)
  consecutive_failures: int = 0
  cooldown_until: int = 0
  escalated: bool = False


@dataclass
class RestartIncident:
  service: str
  timestamp_epoch: int
  reason: str
  severity: str
  details: Dict[str, int]


@dataclass
class ServiceRestartBudgetSupervisor:
  policies: Dict[str, ServiceRestartPolicy] = field(default_factory=dict)
  states: Dict[str, ServiceRuntimeState] = field(default_factory=dict)
  incidents: List[RestartIncident] = field(default_factory=list)
  decision_count: int = 0

  @staticmethod
  def _require_int(value: object, field_name: str, minimum: int = 0) -> int:
    if not isinstance(value, int):
      raise ValueError(f"{field_name} must be int")
    if value < minimum:
      raise ValueError(f"{field_name} must be >= {minimum}")
    return value

  @classmethod
  def from_manifest_dict(cls, payload: Dict[str, object]) -> "ServiceRestartBudgetSupervisor":
    if not isinstance(payload, dict):
      raise ValueError("manifest must be dict")
    entries = payload.get("services")
    if not isinstance(entries, list) or not entries:
      raise ValueError("manifest.services must be non-empty list")
    supervisor = cls()
    for raw in entries:
      if not isinstance(raw, dict):
        raise ValueError("service policy entries must be objects")
      service = raw.get("service", "")
      if not isinstance(service, str) or not service:
        raise ValueError("service must be non-empty string")
      policy = ServiceRestartPolicy(
          service=service,
          max_restarts=cls._require_int(raw.get("max_restarts"), "max_restarts", 1),
          window_seconds=cls._require_int(raw.get("window_seconds"), "window_seconds", 1),
          base_backoff_seconds=cls._require_int(raw.get("base_backoff_seconds"), "base_backoff_seconds", 1),
          max_backoff_seconds=cls._require_int(raw.get("max_backoff_seconds"), "max_backoff_seconds", 1),
          jitter_percent=cls._require_int(raw.get("jitter_percent", 0), "jitter_percent", 0),
          escalation_threshold=cls._require_int(raw.get("escalation_threshold", 5), "escalation_threshold", 1),
      )
      if policy.base_backoff_seconds > policy.max_backoff_seconds:
        raise ValueError("base_backoff_seconds cannot exceed max_backoff_seconds")
      if policy.jitter_percent > 100:
        raise ValueError("jitter_percent must be <= 100")
      supervisor.policies[service] = policy
      supervisor.states[service] = ServiceRuntimeState()
    return supervisor

  @classmethod
  def from_manifest_file(cls, manifest_path: str) -> "ServiceRestartBudgetSupervisor":
    with open(manifest_path, "r", encoding="utf-8") as f:
      payload = json.load(f)
    return cls.from_manifest_dict(payload)

  def _compute_backoff(self, policy: ServiceRestartPolicy, state: ServiceRuntimeState, timestamp_epoch: int) -> int:
    exponent = max(0, state.consecutive_failures - 1)
    delay = policy.base_backoff_seconds * (2 ** exponent)
    delay = min(delay, policy.max_backoff_seconds)
    if policy.jitter_percent == 0:
      return delay
    jitter_span = int((delay * policy.jitter_percent) / 100)
    if jitter_span <= 0:
      return delay
    seed = sum(ord(ch) for ch in policy.service) + timestamp_epoch + state.consecutive_failures
    jitter = seed % (jitter_span + 1)
    return min(policy.max_backoff_seconds, delay + jitter)

  def _prune_restart_window(self, policy: ServiceRestartPolicy, state: ServiceRuntimeState, now: int) -> None:
    floor = now - policy.window_seconds
    state.restart_timestamps = [ts for ts in state.restart_timestamps if ts >= floor]

  def can_restart(self, service: str, now_epoch: int) -> bool:
    if service not in self.states:
      raise ValueError("unknown service")
    return now_epoch >= self.states[service].cooldown_until

  def record_exit(self, service: str, exit_code: int, timestamp_epoch: int) -> Dict[str, object]:
    policy = self.policies.get(service)
    state = self.states.get(service)
    if policy is None or state is None:
      raise ValueError("unknown service")
    self.decision_count += 1
    self._prune_restart_window(policy, state, timestamp_epoch)

    if exit_code == 0:
      state.consecutive_failures = 0
      state.escalated = False
      state.cooldown_until = timestamp_epoch
      return {
          "service": service,
          "action": "no_restart_needed",
          "allowed": 1,
          "cooldown_until": state.cooldown_until,
          "window_failures": len(state.restart_timestamps),
      }

    if len(state.restart_timestamps) >= policy.max_restarts:
      state.escalated = True
      incident = RestartIncident(
          service=service,
          timestamp_epoch=timestamp_epoch,
          reason="restart_budget_exhausted",
          severity="critical",
          details={
              "max_restarts": policy.max_restarts,
              "window_seconds": policy.window_seconds,
              "window_failures": len(state.restart_timestamps),
          },
      )
      self.incidents.append(incident)
      state.cooldown_until = timestamp_epoch + policy.max_backoff_seconds
      return {
          "service": service,
          "action": "freeze",
          "allowed": 0,
          "cooldown_until": state.cooldown_until,
          "window_failures": len(state.restart_timestamps),
          "reason": "restart_budget_exhausted",
      }

    state.restart_timestamps.append(timestamp_epoch)
    state.consecutive_failures += 1
    if state.consecutive_failures >= policy.escalation_threshold:
      state.escalated = True
    delay = self._compute_backoff(policy, state, timestamp_epoch)
    state.cooldown_until = timestamp_epoch + delay
    return {
        "service": service,
        "action": "restart_after_backoff",
        "allowed": 1,
        "delay_seconds": delay,
        "cooldown_until": state.cooldown_until,
        "window_failures": len(state.restart_timestamps),
        "consecutive_failures": state.consecutive_failures,
        "escalated": 1 if state.escalated else 0,
    }

  def summary_json(self) -> str:
    payload = {
        "schema_version": 1,
        "decision_count": self.decision_count,
        "service_count": len(self.policies),
        "incident_count": len(self.incidents),
        "services": {
            name: {
                "max_restarts": policy.max_restarts,
                "window_seconds": policy.window_seconds,
                "base_backoff_seconds": policy.base_backoff_seconds,
                "max_backoff_seconds": policy.max_backoff_seconds,
                "jitter_percent": policy.jitter_percent,
                "escalation_threshold": policy.escalation_threshold,
                "cooldown_until": self.states[name].cooldown_until,
                "consecutive_failures": self.states[name].consecutive_failures,
                "window_failures": len(self.states[name].restart_timestamps),
                "escalated": 1 if self.states[name].escalated else 0,
            }
            for name, policy in self.policies.items()
        },
        "incidents": [
            {
                "service": x.service,
                "timestamp_epoch": x.timestamp_epoch,
                "reason": x.reason,
                "severity": x.severity,
                "details": x.details,
            }
            for x in self.incidents
        ],
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def demo() -> int:
  supervisor = ServiceRestartBudgetSupervisor.from_manifest_dict(
      {
          "services": [
              {
                  "service": "ui-shell",
                  "max_restarts": 3,
                  "window_seconds": 120,
                  "base_backoff_seconds": 2,
                  "max_backoff_seconds": 30,
                  "jitter_percent": 10,
                  "escalation_threshold": 3,
              }
          ]
      }
  )
  print(supervisor.record_exit("ui-shell", 1, 1000))
  print(supervisor.record_exit("ui-shell", 1, 1004))
  print(supervisor.record_exit("ui-shell", 1, 1008))
  print(supervisor.summary_json())
  return 0


if __name__ == "__main__":
  raise SystemExit(demo())
