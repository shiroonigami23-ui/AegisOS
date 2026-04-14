import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "service_restart_budget_supervisor.py"

spec = importlib.util.spec_from_file_location("service_restart_budget_supervisor", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

ServiceRestartBudgetSupervisor = module.ServiceRestartBudgetSupervisor


class ServiceRestartBudgetSupervisorTest(unittest.TestCase):
    def setUp(self):
        self.supervisor = ServiceRestartBudgetSupervisor.from_manifest_dict(
            {
                "services": [
                    {
                        "service": "ui-shell",
                        "max_restarts": 3,
                        "window_seconds": 60,
                        "base_backoff_seconds": 2,
                        "max_backoff_seconds": 20,
                        "jitter_percent": 0,
                        "escalation_threshold": 3,
                    },
                    {
                        "service": "network-agent",
                        "max_restarts": 2,
                        "window_seconds": 30,
                        "base_backoff_seconds": 1,
                        "max_backoff_seconds": 8,
                    },
                ]
            }
        )

    def test_backoff_growth_and_escalation(self):
        d1 = self.supervisor.record_exit("ui-shell", exit_code=1, timestamp_epoch=100)
        d2 = self.supervisor.record_exit("ui-shell", exit_code=1, timestamp_epoch=105)
        d3 = self.supervisor.record_exit("ui-shell", exit_code=1, timestamp_epoch=112)
        self.assertEqual(d1["action"], "restart_after_backoff")
        self.assertEqual(d1["delay_seconds"], 2)
        self.assertEqual(d2["delay_seconds"], 4)
        self.assertEqual(d3["delay_seconds"], 8)
        self.assertEqual(d3["escalated"], 1)
        self.assertFalse(self.supervisor.can_restart("ui-shell", 119))
        self.assertTrue(self.supervisor.can_restart("ui-shell", 120))

    def test_restart_budget_exhausted_freezes_service(self):
        self.supervisor.record_exit("network-agent", exit_code=1, timestamp_epoch=200)
        self.supervisor.record_exit("network-agent", exit_code=1, timestamp_epoch=205)
        freeze = self.supervisor.record_exit("network-agent", exit_code=1, timestamp_epoch=210)
        self.assertEqual(freeze["allowed"], 0)
        self.assertEqual(freeze["action"], "freeze")
        self.assertEqual(freeze["reason"], "restart_budget_exhausted")
        self.assertEqual(len(self.supervisor.incidents), 1)
        self.assertEqual(self.supervisor.incidents[0].severity, "critical")

    def test_success_resets_consecutive_failures(self):
        self.supervisor.record_exit("ui-shell", exit_code=1, timestamp_epoch=300)
        ok = self.supervisor.record_exit("ui-shell", exit_code=0, timestamp_epoch=305)
        self.assertEqual(ok["action"], "no_restart_needed")
        state = self.supervisor.states["ui-shell"]
        self.assertEqual(state.consecutive_failures, 0)
        self.assertEqual(state.escalated, False)

    def test_window_pruning_allows_new_restarts_after_horizon(self):
        self.supervisor.record_exit("network-agent", exit_code=1, timestamp_epoch=400)
        self.supervisor.record_exit("network-agent", exit_code=1, timestamp_epoch=405)
        blocked = self.supervisor.record_exit("network-agent", exit_code=1, timestamp_epoch=410)
        self.assertEqual(blocked["allowed"], 0)
        fresh = self.supervisor.record_exit("network-agent", exit_code=1, timestamp_epoch=450)
        self.assertEqual(fresh["allowed"], 1)
        self.assertEqual(fresh["window_failures"], 1)

    def test_summary_json_contains_incidents_and_service_state(self):
        self.supervisor.record_exit("network-agent", exit_code=1, timestamp_epoch=500)
        self.supervisor.record_exit("network-agent", exit_code=1, timestamp_epoch=501)
        self.supervisor.record_exit("network-agent", exit_code=1, timestamp_epoch=502)
        payload = json.loads(self.supervisor.summary_json())
        self.assertEqual(payload["schema_version"], 1)
        self.assertGreaterEqual(payload["decision_count"], 3)
        self.assertEqual(payload["incident_count"], 1)
        self.assertEqual(payload["freeze_decision_count"], 1)
        self.assertIn("network-agent", payload["services"])
        self.assertEqual(payload["services"]["network-agent"]["last_action"], "freeze")

    def test_health_probe_json_exposes_service_status(self):
        self.supervisor.record_exit("ui-shell", exit_code=1, timestamp_epoch=1000)
        self.supervisor.record_exit("network-agent", exit_code=1, timestamp_epoch=1000)
        self.supervisor.record_exit("network-agent", exit_code=1, timestamp_epoch=1001)
        self.supervisor.record_exit("network-agent", exit_code=1, timestamp_epoch=1002)
        probe = json.loads(self.supervisor.health_probe_json(now_epoch=1003))
        self.assertEqual(probe["schema_version"], 1)
        self.assertEqual(probe["service_count"], 2)
        self.assertGreaterEqual(probe["unhealthy_count"], 1)
        services = {entry["service"]: entry for entry in probe["services"]}
        self.assertIn(services["network-agent"]["status"], {"degraded", "frozen"})
        self.assertIn("restart_pressure", services["ui-shell"])

    def test_metrics_export_json_contains_ops_counters(self):
        self.supervisor.record_exit("ui-shell", exit_code=1, timestamp_epoch=1200)
        self.supervisor.record_exit("ui-shell", exit_code=1, timestamp_epoch=1202)
        self.supervisor.record_exit("network-agent", exit_code=1, timestamp_epoch=1200)
        self.supervisor.record_exit("network-agent", exit_code=1, timestamp_epoch=1201)
        self.supervisor.record_exit("network-agent", exit_code=1, timestamp_epoch=1202)
        metrics = json.loads(self.supervisor.metrics_export_json(now_epoch=1203))
        self.assertEqual(metrics["schema_version"], 1)
        self.assertIn("counters", metrics)
        self.assertIn("gauges", metrics)
        self.assertGreaterEqual(metrics["counters"]["decision_count"], 5)
        self.assertGreaterEqual(metrics["counters"]["freeze_decision_count"], 1)
        self.assertGreaterEqual(metrics["gauges"]["service_count"], 2)
        self.assertGreaterEqual(metrics["gauges"]["max_restart_pressure"], 0.0)

    def test_manifest_validation_rejects_bad_shapes(self):
        with self.assertRaises(ValueError):
            ServiceRestartBudgetSupervisor.from_manifest_dict({"services": []})
        with self.assertRaises(ValueError):
            ServiceRestartBudgetSupervisor.from_manifest_dict(
                {
                    "services": [
                        {
                            "service": "bad",
                            "max_restarts": 2,
                            "window_seconds": 10,
                            "base_backoff_seconds": 30,
                            "max_backoff_seconds": 20,
                        }
                    ]
                }
            )


if __name__ == "__main__":
    unittest.main()
