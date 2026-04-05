import importlib.util
import json
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


if __name__ == "__main__":
    unittest.main()
