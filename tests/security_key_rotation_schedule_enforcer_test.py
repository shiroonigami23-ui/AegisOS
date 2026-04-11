import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "security_key_rotation_schedule_enforcer.py"

spec = importlib.util.spec_from_file_location("security_key_rotation_schedule_enforcer", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class SecurityKeyRotationScheduleEnforcerTest(unittest.TestCase):
    def test_policy_load(self):
        policy = module.load_policy()
        self.assertEqual(policy["schema_version"], 1)
        self.assertIn("key_classes", policy)

    def test_evaluate_keys_statuses(self):
        policy = module.load_policy()
        now = 1_800_000_000
        keys = [
            {"key_id": "k-sign-1", "key_class": "signing", "last_rotated_epoch": now - 70 * 86400},
            {"key_id": "k-auth-1", "key_class": "auth", "last_rotated_epoch": now - 40 * 86400},
            {"key_id": "k-enc-1", "key_class": "encryption", "last_rotated_epoch": now - 10 * 86400},
        ]
        report = module.evaluate_keys(policy, keys, now)
        self.assertEqual(report["evaluated_key_count"], 3)
        self.assertGreaterEqual(report["due_count"], 1)
        self.assertIn(report["overall_status"], {"warning", "critical"})

    def test_default_class_fallback(self):
        policy = module.load_policy()
        now = 1_800_000_000
        keys = [{"key_id": "k-x", "key_class": "unknown-class", "last_rotated_epoch": now - 50 * 86400}]
        report = module.evaluate_keys(policy, keys, now)
        self.assertEqual(report["keys"][0]["max_age_days"], policy["default_max_age_days"])

    def test_cli(self):
        policy = module.load_policy()
        now = 1_800_000_000
        keys = [
            {"key_id": "k-sign-2", "key_class": "signing", "last_rotated_epoch": now - 30 * 86400},
            {"key_id": "k-auth-2", "key_class": "auth", "last_rotated_epoch": now - 20 * 86400},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            keys_path = Path(tmp) / "keys.json"
            keys_path.write_text(json.dumps(keys), encoding="utf-8")
            proc = subprocess.run(
                [
                    "python",
                    str(SCRIPT),
                    "--keys-json",
                    str(keys_path),
                    "--now-epoch",
                    str(now),
                    "--policy-json",
                    str(ROOT / "packages" / "core" / "security-key-rotation-policy.json"),
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=True,
            )
            payload = json.loads(proc.stdout.strip())
            self.assertEqual(payload["schema_version"], 1)
            self.assertEqual(payload["evaluated_key_count"], 2)
            self.assertIn(payload["overall_status"], {"ok", "warning", "critical"})

    def test_invalid_inputs(self):
        policy = module.load_policy()
        now = 1_800_000_000
        with self.assertRaises(ValueError):
            module.evaluate_keys(policy, "bad", now)
        with self.assertRaises(ValueError):
            module.evaluate_keys(policy, [{"key_id": "", "key_class": "auth", "last_rotated_epoch": now}], now)


if __name__ == "__main__":
    unittest.main()
