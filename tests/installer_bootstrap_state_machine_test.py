import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "installer_bootstrap_state_machine.py"

spec = importlib.util.spec_from_file_location("installer_bootstrap_state_machine", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

InstallerBootstrapStateMachine = module.InstallerBootstrapStateMachine
InstallerState = module.InstallerState


class InstallerBootstrapStateMachineTest(unittest.TestCase):
    def test_happy_path(self):
        sm = InstallerBootstrapStateMachine()
        sm.start_install("inst-1", "stable", "1.0.0", ["tpm_quote", "sbom_verify"])
        sm.mark_preflight_ok()
        sm.mark_artifacts_verified()
        sm.mark_attestation_passed(
            "tpm_quote",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        )
        self.assertEqual(sm.state, InstallerState.ATTEST)
        sm.mark_attestation_passed(
            "sbom_verify",
            "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        )
        self.assertEqual(sm.state, InstallerState.APPLY)
        sm.mark_payload_applied()
        sm.mark_boot_verified()
        self.assertEqual(sm.state, InstallerState.COMPLETE)
        payload = json.loads(sm.summary_json())
        self.assertEqual(payload["state"], "complete")
        self.assertEqual(payload["transition_count"], len(payload["transitions"]))

    def test_recovery_path(self):
        sm = InstallerBootstrapStateMachine()
        sm.start_install("inst-2", "beta", "1.1.0", ["tpm_quote"])
        sm.mark_preflight_ok()
        sm.fail_current_step("checksum_mismatch", recoverable=True)
        self.assertEqual(sm.state, InstallerState.RECOVERY)
        sm.recovery_step_completed(True)
        self.assertEqual(sm.state, InstallerState.VERIFY_ARTIFACTS)

    def test_fatal_failure_path(self):
        sm = InstallerBootstrapStateMachine()
        sm.start_install("inst-3", "nightly", "2.0.0", ["tpm_quote"])
        sm.mark_preflight_ok()
        sm.fail_current_step("tpm_unavailable", recoverable=False)
        self.assertEqual(sm.state, InstallerState.FAILED)

    def test_invalid_transitions_rejected(self):
        sm = InstallerBootstrapStateMachine()
        with self.assertRaises(ValueError):
            sm.mark_preflight_ok()
        sm.start_install("inst-4", "stable", "1.0.1", ["tpm_quote"])
        with self.assertRaises(ValueError):
            sm.mark_artifacts_verified()
        sm.mark_preflight_ok()
        sm.mark_artifacts_verified()
        with self.assertRaises(ValueError):
            sm.mark_attestation_passed("unknown_hook", "sha256:abc")
        with self.assertRaises(ValueError):
            sm.mark_attestation_passed("tpm_quote", "md5:abc")

    def test_reset(self):
        sm = InstallerBootstrapStateMachine()
        sm.start_install("inst-5", "stable", "1.2.0", ["tpm_quote"])
        sm.mark_preflight_ok()
        sm.reset()
        self.assertEqual(sm.state, InstallerState.IDLE)
        self.assertEqual(sm.install_id, "")
        self.assertEqual(sm.transitions, [])


if __name__ == "__main__":
    unittest.main()
