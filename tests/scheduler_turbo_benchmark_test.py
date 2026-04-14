import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "scheduler_turbo_benchmark.py"

spec = importlib.util.spec_from_file_location("scheduler_turbo_benchmark", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class SchedulerTurboBenchmarkTest(unittest.TestCase):
    def test_compare_has_latency_improvement(self):
        report = module.compare(ticks=400, seed=4242)
        self.assertEqual(report["schema_version"], 1)
        rr_hp_dispatch = (
            report["round_robin"]["per_task"]["1003"]["dispatch_count"]
            + report["round_robin"]["per_task"]["1005"]["dispatch_count"]
        )
        turbo_hp_dispatch = (
            report["turbo"]["per_task"]["1003"]["dispatch_count"]
            + report["turbo"]["per_task"]["1005"]["dispatch_count"]
        )
        self.assertGreater(turbo_hp_dispatch, rr_hp_dispatch)

    def test_simulation_is_deterministic(self):
        a = module.compare(ticks=200, seed=777)
        b = module.compare(ticks=200, seed=777)
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
