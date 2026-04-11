import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "package_signature_verifier.py"

spec = importlib.util.spec_from_file_location("package_signature_verifier", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class PackageSignatureVerifierTest(unittest.TestCase):
    def test_hmac_sign_and_verify_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "pkg.yaml"
            manifest.write_text(
                "\n".join(
                    [
                        "name: aegis-test-pkg",
                        "version: 1.2.3",
                        "description: test",
                        "dependencies:",
                        "- base",
                    ]
                ),
                encoding="utf-8",
            )
            digest = module.compute_manifest_digest(manifest)
            payload = module.canonical_signing_payload("aegis-test-pkg", "1.2.3", "pkg.yaml", digest)
            signature = module.hmac_sha256_hex("aegis-secret-key-0001", payload)
            entry = {
                "name": "aegis-test-pkg",
                "version": "1.2.3",
                "manifest_path": "pkg.yaml",
                "signature_format": "hmac-sha256-v1",
                "signature_key_id": "aegis-hmac-core",
                "signature_digest": digest,
                "signature_value": signature,
            }
            ok, reason = module.verify_package_entry(
                entry, keyring={"aegis-hmac-core": "aegis-secret-key-0001"}, base_dir=root
            )
            self.assertTrue(ok)
            self.assertEqual(reason, "ok")

    def test_verify_rejects_digest_and_signature_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "pkg.yaml"
            manifest.write_text("name: pkg\nversion: 0.0.1\n", encoding="utf-8")
            digest = module.compute_manifest_digest(manifest)
            payload = module.canonical_signing_payload("pkg", "0.0.1", "pkg.yaml", digest)
            sig = module.hmac_sha256_hex("aegis-secret-key-0002", payload)
            entry = {
                "name": "pkg",
                "version": "0.0.1",
                "manifest_path": "pkg.yaml",
                "signature_format": "hmac-sha256-v1",
                "signature_key_id": "aegis-hmac-core",
                "signature_digest": digest[:-1] + "0",
                "signature_value": sig,
            }
            ok, reason = module.verify_package_entry(
                entry, keyring={"aegis-hmac-core": "aegis-secret-key-0002"}, base_dir=root
            )
            self.assertFalse(ok)
            self.assertEqual(reason, "signature_digest_mismatch")

    def test_verify_repository_index_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "pkg.yaml"
            manifest.write_text("name: pkg\nversion: 0.0.1\n", encoding="utf-8")
            digest = module.compute_manifest_digest(manifest)
            payload = module.canonical_signing_payload("pkg", "0.0.1", "pkg.yaml", digest)
            sig = module.hmac_sha256_hex("aegis-secret-key-0003", payload)
            idx = {
                "schema_version": 1,
                "packages": [
                    {
                        "name": "pkg",
                        "version": "0.0.1",
                        "manifest_path": "pkg.yaml",
                        "signature_format": "hmac-sha256-v1",
                        "signature_key_id": "aegis-hmac-core",
                        "signature_digest": digest,
                        "signature_value": sig,
                    }
                ],
            }
            index_path = root / "index.json"
            index_path.write_text(json.dumps(idx), encoding="utf-8")
            report = module.verify_repository_index(
                index_path, keyring={"aegis-hmac-core": "aegis-secret-key-0003"}, base_dir=root
            )
            self.assertEqual(report["all_ok"], 1)
            self.assertEqual(report["ok_count"], 1)
            self.assertEqual(report["failed_count"], 0)

    def test_prefix_and_secret_strength_policy_enforced(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "pkg.yaml"
            manifest.write_text("name: pkg\nversion: 0.0.1\n", encoding="utf-8")
            digest = module.compute_manifest_digest(manifest)
            payload = module.canonical_signing_payload("pkg", "0.0.1", "pkg.yaml", digest)
            sig = module.hmac_sha256_hex("aegis-secret-key-0004", payload)
            entry = {
                "name": "pkg",
                "version": "0.0.1",
                "manifest_path": "pkg.yaml",
                "signature_format": "hmac-sha256-v1",
                "signature_key_id": "bad-prefix",
                "signature_digest": digest,
                "signature_value": sig,
            }
            ok, reason = module.verify_package_entry(
                entry, keyring={"bad-prefix": "short"}, base_dir=root
            )
            self.assertFalse(ok)
            self.assertEqual(reason, "signature_key_id_prefix_mismatch")

    def test_load_signature_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "signature_format": "hmac-sha256-v1",
                        "allowed_key_id_prefix": "aegis-hmac-",
                        "digest_algorithm": "sha256",
                    }
                ),
                encoding="utf-8",
            )
            policy = module.load_signature_policy(path)
            self.assertEqual(policy["signature_format"], "hmac-sha256-v1")
            self.assertEqual(policy["allowed_key_id_prefix"], "aegis-hmac-")


if __name__ == "__main__":
    unittest.main()
