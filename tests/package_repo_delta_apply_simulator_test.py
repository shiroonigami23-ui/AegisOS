import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "package_repo_delta_apply_simulator.py"

spec = importlib.util.spec_from_file_location("package_repo_delta_apply_simulator", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def _manifest():
    return {
        "name": "aegis-update-service",
        "version": "0.1.0",
        "delta_base_version": "0.0.9",
        "delta_payload_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "delta_fallback_full_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
    }


class PackageRepoDeltaApplySimulatorTest(unittest.TestCase):
    def test_apply_via_delta(self):
        result = module.simulate_delta_apply(
            _manifest(),
            installed_version="0.0.9",
            provided_delta_digest="sha256:1111111111111111111111111111111111111111111111111111111111111111",
            provided_full_digest="sha256:bad",
        )
        self.assertEqual(result.status, "applied")
        self.assertEqual(result.applied_via, "delta")

    def test_apply_via_full_fallback(self):
        result = module.simulate_delta_apply(
            _manifest(),
            installed_version="0.0.9",
            provided_delta_digest="sha256:bad",
            provided_full_digest="sha256:2222222222222222222222222222222222222222222222222222222222222222",
        )
        self.assertEqual(result.status, "applied")
        self.assertEqual(result.applied_via, "full_fallback")

    def test_reject_base_version_mismatch(self):
        result = module.simulate_delta_apply(
            _manifest(),
            installed_version="0.0.8",
            provided_delta_digest="sha256:1111111111111111111111111111111111111111111111111111111111111111",
            provided_full_digest="sha256:2222222222222222222222222222222222222222222222222222222222222222",
        )
        self.assertEqual(result.status, "rejected")
        self.assertEqual(result.applied_via, "none")

    def test_reject_when_both_digests_fail(self):
        result = module.simulate_delta_apply(
            _manifest(),
            installed_version="0.0.9",
            provided_delta_digest="sha256:bad",
            provided_full_digest="sha256:bad",
        )
        self.assertEqual(result.status, "rejected")
        self.assertEqual(result.applied_via, "none")

    def test_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            m = Path(tmp) / "manifest.json"
            m.write_text(json.dumps(_manifest()), encoding="utf-8")
            proc = subprocess.run(
                [
                    "python",
                    str(SCRIPT),
                    "--manifest-json",
                    str(m),
                    "--installed-version",
                    "0.0.9",
                    "--provided-delta-digest",
                    _manifest()["delta_payload_digest"],
                    "--provided-full-digest",
                    "sha256:bad",
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                check=True,
            )
            payload = json.loads(proc.stdout.strip())
            self.assertEqual(payload["status"], "applied")
            self.assertEqual(payload["applied_via"], "delta")


if __name__ == "__main__":
    unittest.main()
