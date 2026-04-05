import importlib.util
import json
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "low_resource_profile_advisor.py"

spec = importlib.util.spec_from_file_location("low_resource_profile_advisor", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class LowResourceProfileTuningAdvisorTest(unittest.TestCase):
    def test_recommend_minimal_for_legacy_or_ultra_low(self):
        rec = module.recommend_profile("legacy", "mid")
        self.assertEqual(rec["recommended_profile"], "minimal")
        self.assertIn("server", rec["alternatives"])

        rec2 = module.recommend_profile("mid", "ultra_low")
        self.assertEqual(rec2["recommended_profile"], "minimal")

    def test_recommend_server_for_entry_low(self):
        rec = module.recommend_profile("entry", "low")
        self.assertEqual(rec["recommended_profile"], "server")
        self.assertIn("minimal", rec["alternatives"])
        self.assertEqual(rec["schema_version"], 1)

    def test_cli_output_json(self):
        proc = subprocess.run(
            ["python", str(SCRIPT), "--cpu-class", "mid", "--ram-class", "mid"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=True,
        )
        payload = json.loads(proc.stdout.strip())
        self.assertEqual(payload["recommended_profile"], "desktop")
        self.assertEqual(payload["cpu_class"], "mid")
        self.assertEqual(payload["ram_class"], "mid")


if __name__ == "__main__":
    unittest.main()
