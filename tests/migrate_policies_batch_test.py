import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "migrate_policies_batch.py"


class MigratePoliciesBatchTest(unittest.TestCase):
    def test_batch_migration_success_and_already_current(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            inp = base / "in"
            out = base / "out"
            summary = base / "summary.json"
            inp.mkdir()
            inp.joinpath("legacy.json").write_text(
                json.dumps(
                    {
                        "process_id": 1001,
                        "capabilities": 5,
                        "allow_fs_read": 1,
                        "allow_fs_write": 0,
                        "allow_net_client": 1,
                        "allow_net_server": 0,
                        "allow_device_io": 0,
                    }
                ),
                encoding="utf-8",
            )
            inp.joinpath("current.json").write_text(
                json.dumps(
                    {
                        "process_id": 1002,
                        "capabilities": 5,
                        "allow_fs_read": 1,
                        "allow_fs_write": 0,
                        "allow_net_client": 1,
                        "allow_net_server": 0,
                        "allow_device_io": 0,
                        "schema_version": 1,
                        "policy_revision": 3,
                    }
                ),
                encoding="utf-8",
            )
            rc = subprocess.run(
                [
                    "python",
                    str(SCRIPT),
                    "--input-dir",
                    str(inp),
                    "--output-dir",
                    str(out),
                    "--summary-json",
                    str(summary),
                ],
                check=False,
                capture_output=True,
                text=True,
                cwd=str(ROOT),
            ).returncode
            self.assertEqual(rc, 0)
            data = json.loads(summary.read_text(encoding="utf-8"))
            self.assertEqual(data["total"], 2)
            self.assertEqual(data["migrated"], 1)
            self.assertEqual(data["already_current"], 1)
            self.assertEqual(data["failed"], 0)
            self.assertTrue((out / "legacy.json").exists())
            migrated = json.loads((out / "legacy.json").read_text(encoding="utf-8"))
            self.assertEqual(migrated["schema_version"], 1)
            self.assertEqual(migrated["policy_revision"], 1)

    def test_batch_migration_failure_exit_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            inp = base / "in"
            out = base / "out"
            inp.mkdir()
            inp.joinpath("bad.json").write_text(
                json.dumps(
                    {
                        "process_id": 2001,
                        "capabilities": 8,
                        "allow_fs_read": 0,
                        "allow_fs_write": 0,
                        "allow_net_client": 0,
                        "allow_net_server": 1,
                        "allow_device_io": 0,
                    }
                ),
                encoding="utf-8",
            )
            rc = subprocess.run(
                [
                    "python",
                    str(SCRIPT),
                    "--input-dir",
                    str(inp),
                    "--output-dir",
                    str(out),
                ],
                check=False,
                capture_output=True,
                text=True,
                cwd=str(ROOT),
            ).returncode
            self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
