import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "device_profile_boot_budget_enforcer.py"

spec = importlib.util.spec_from_file_location("device_profile_boot_budget_enforcer", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class DeviceProfileBootBudgetEnforcerTest(unittest.TestCase):
    def test_single_run_pass(self):
        report = module.evaluate_boot_samples(
            profile_name="minimal",
            boot_type="cold",
            samples_seconds=[8.0, 8.5, 9.2, 8.7, 8.9],
        )
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["severity"], "ok")
        self.assertGreater(report["adjusted_budget_seconds"], 0)
        self.assertEqual(report["power_mode"], "balanced")

    def test_single_run_fail_warning(self):
        report = module.evaluate_boot_samples(
            profile_name="desktop",
            boot_type="cold",
            samples_seconds=[20.0, 21.0, 26.0, 27.0, 23.0],
        )
        self.assertEqual(report["status"], "fail")
        self.assertIn(report["severity"], {"warning", "critical"})
        self.assertIn("recommendation", report)

    def test_batch_mixed(self):
        payload = {
            "runs": [
                {
                    "profile": "minimal",
                    "boot_type": "warm",
                    "samples_seconds": [6.0, 6.3, 6.5],
                    "battery_percent": 17.0,
                },
                {
                    "profile": "developer",
                    "boot_type": "cold",
                    "samples_seconds": [31.0, 34.0, 33.0],
                    "thermal_state": "throttled",
                },
            ]
        }
        out = module.evaluate_batch(payload)
        self.assertEqual(out["total_runs"], 2)
        self.assertGreaterEqual(out["failed_runs"], 1)
        self.assertEqual(len(out["reports"]), 2)
        self.assertIn(out["reports"][0]["power_mode"], {"low_battery", "balanced"})
        self.assertIn(out["reports"][1]["power_mode"], {"thermal_throttled", "balanced"})

    def test_optimizer_recommendations_on_thermal_fail(self):
        report = module.evaluate_boot_samples(
            profile_name="developer",
            boot_type="cold",
            samples_seconds=[33.0, 34.0, 35.0, 34.5],
            battery_percent=55.0,
            thermal_state="throttled",
        )
        self.assertEqual(report["status"], "fail")
        self.assertEqual(report["power_mode"], "thermal_throttled")
        self.assertGreater(len(report["optimizer_recommendations"]), 0)
        self.assertGreater(report["estimated_recovery_seconds"], 0.0)

    def test_invalid_thermal_state(self):
        with self.assertRaises(ValueError):
            module.evaluate_boot_samples(
                profile_name="minimal",
                boot_type="warm",
                samples_seconds=[7.0, 7.1, 7.2],
                thermal_state="very_hot",
            )

    def test_cli_single(self):
        proc = subprocess.run(
            [
                "python",
                str(SCRIPT),
                "--profile",
                "server",
                "--boot-type",
                "warm",
                "--samples",
                "10.2,10.7,11.1,10.0",
                "--battery-percent",
                "25",
                "--thermal-state",
                "elevated",
            ],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=True,
        )
        payload = json.loads(proc.stdout.strip())
        self.assertEqual(payload["profile"], "server")
        self.assertEqual(payload["boot_type"], "warm")
        self.assertEqual(payload["thermal_state"], "elevated")

    def test_cli_batch(self):
        with tempfile.TemporaryDirectory() as tmp:
            inp = Path(tmp) / "batch.json"
            inp.write_text(
                json.dumps(
                    {
                        "runs": [
                            {
                                "profile": "minimal",
                                "boot_type": "cold",
                                "samples_seconds": [8.0, 8.3, 8.4, 8.1],
                            },
                            {
                                "profile": "desktop",
                                "boot_type": "warm",
                                "samples_seconds": [12.0, 12.4, 12.1, 12.3],
                                "battery_percent": 15.0,
                                "thermal_state": "elevated",
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            proc = subprocess.run(
                ["python", str(SCRIPT), "--batch-json", str(inp)],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=True,
            )
            payload = json.loads(proc.stdout.strip())
            self.assertEqual(payload["schema_version"], 1)
            self.assertEqual(payload["total_runs"], 2)
            self.assertIn("power_mode", payload["reports"][1])


if __name__ == "__main__":
    unittest.main()
