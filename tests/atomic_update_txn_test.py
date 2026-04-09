import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "atomic_update_txn.py"

spec = importlib.util.spec_from_file_location("atomic_update_txn", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

AtomicUpdateTransaction = module.AtomicUpdateTransaction
TxnState = module.TxnState


class AtomicUpdateTxnTest(unittest.TestCase):
    def test_happy_path_commit(self):
        txn = AtomicUpdateTransaction()
        txn.begin("txn-1", "sha256:abc")
        txn.stage_package("aegis-kernel")
        txn.stage_package("aegis-security-core")
        txn.commit()
        self.assertEqual(txn.state, TxnState.COMMITTED)
        payload = json.loads(txn.summary_json())
        self.assertEqual(payload["state"], "committed")
        self.assertEqual(payload["staged_count"], 2)

    def test_reject_commit_without_stage(self):
        txn = AtomicUpdateTransaction()
        txn.begin("txn-2", "sha256:def")
        with self.assertRaises(ValueError):
            txn.commit()

    def test_rollback_paths(self):
        txn = AtomicUpdateTransaction()
        txn.begin("txn-3", "sha256:ghi")
        txn.stage_package("aegis-kernel")
        txn.rollback("verification_failed")
        self.assertEqual(txn.state, TxnState.ROLLED_BACK)
        self.assertEqual(txn.rollback_reason, "verification_failed")
        txn.reset()
        self.assertEqual(txn.state, TxnState.IDLE)
        with self.assertRaises(ValueError):
            txn.rollback("bad_state")

    def test_resume_from_json(self):
        txn = AtomicUpdateTransaction()
        txn.begin("txn-4", "sha256:jkl")
        txn.stage_package("aegis-kernel")
        txn.stage_package("aegis-security-core")
        snapshot = txn.summary_json()

        resumed = AtomicUpdateTransaction()
        resumed.load_from_json(snapshot)
        self.assertEqual(resumed.state, TxnState.PREPARED)
        self.assertEqual(resumed.transaction_id, "txn-4")
        self.assertEqual(resumed.manifest_hash, "sha256:jkl")
        self.assertEqual(resumed.staged_packages, ["aegis-kernel", "aegis-security-core"])
        resumed.commit()
        self.assertEqual(resumed.state, TxnState.COMMITTED)

    def test_resume_rejects_bad_payload(self):
        txn = AtomicUpdateTransaction()
        with self.assertRaises(ValueError):
            txn.load_from_json('{"schema_version":2,"state":"prepared"}')
        with self.assertRaises(ValueError):
            txn.load_from_json('{"schema_version":1,"state":"prepared","transaction_id":"","manifest_hash":"","staged_packages":[],"rollback_reason":""}')
        with self.assertRaises(ValueError):
            txn.load_from_json('{"schema_version":1,"state":"committed","transaction_id":"txn","manifest_hash":"sha256:x","staged_count":0,"staged_packages":[],"rollback_reason":""}')
        with self.assertRaises(ValueError):
            txn.load_from_json('{"schema_version":1,"state":"prepared","transaction_id":"txn","manifest_hash":"sha256:x","staged_count":2,"staged_packages":["aegis-kernel"],"rollback_reason":""}')
        with self.assertRaises(ValueError):
            txn.load_from_json('{"schema_version":1,"state":"idle","transaction_id":"txn","manifest_hash":"","staged_count":0,"staged_packages":[],"rollback_reason":""}')

    def test_file_roundtrip_and_atomic_save(self):
        txn = AtomicUpdateTransaction()
        txn.begin("txn-file", "sha256:file")
        txn.stage_package("aegis-kernel")
        with tempfile.TemporaryDirectory() as tmp:
            state_file = Path(tmp) / "state" / "txn.json"
            txn.save_to_file(str(state_file))
            resumed = AtomicUpdateTransaction()
            resumed.load_from_file(str(state_file))
            self.assertEqual(resumed.state, TxnState.PREPARED)
            self.assertEqual(resumed.transaction_id, "txn-file")
            self.assertEqual(resumed.staged_packages, ["aegis-kernel"])

    def test_file_helpers_reject_invalid_paths(self):
        txn = AtomicUpdateTransaction()
        with tempfile.TemporaryDirectory() as tmp:
            as_dir = Path(tmp) / "as_dir"
            as_dir.mkdir()
            with self.assertRaises(ValueError):
                txn.save_to_file(str(as_dir))
            with self.assertRaises(ValueError):
                txn.load_from_file(str(as_dir))
            missing = Path(tmp) / "missing.json"
            with self.assertRaises(ValueError):
                txn.load_from_file(str(missing))


if __name__ == "__main__":
    unittest.main()
