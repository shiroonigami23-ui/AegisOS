import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "sandbox_escape_fuzz_corpus.py"
SEEDS = ROOT / "tests" / "sandbox_escape_seed_corpus.txt"

spec = importlib.util.spec_from_file_location("sandbox_escape_fuzz_corpus", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class SandboxEscapeFuzzCorpusTest(unittest.TestCase):
    def test_seed_corpus_loads(self):
        seeds = module.load_seed_corpus(SEEDS)
        self.assertGreaterEqual(len(seeds), 4)
        self.assertTrue(all(isinstance(x, int) for x in seeds))

    def test_generation_is_deterministic(self):
        seeds = [991, 1777, 31415]
        corpus_a = module.build_corpus(seeds, count_per_kind=3)
        corpus_b = module.build_corpus(seeds, count_per_kind=3)
        self.assertEqual(corpus_a, corpus_b)
        summary = module.summarize_corpus(corpus_a)
        self.assertEqual(summary["entries"], len(corpus_a))
        self.assertEqual(summary["kind_counts"]["path"], 9)
        self.assertEqual(summary["kind_counts"]["dns"], 9)

    def test_reason_coverage_present(self):
        seeds = [991, 1777, 31415, 27182, 65537]
        corpus = module.build_corpus(seeds, count_per_kind=5)
        reasons = {entry["reason"] for entry in corpus}
        expected = {
            "path_traversal",
            "path_dot_segment",
            "path_encoded_escape",
            "dns_rebinding_mismatch",
            "dns_dual_stack_missing_family",
            "dns_host_encoding_anomaly",
        }
        self.assertTrue(expected.issubset(reasons))
        self.assertTrue(any(entry["expected_block"] == 1 for entry in corpus))

    def test_json_output_written(self):
        seeds = [991, 1777]
        corpus = module.build_corpus(seeds, count_per_kind=2)
        summary = module.summarize_corpus(corpus)
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "corpus.json"
            payload = {
                "schema_version": 1,
                "seed_count": len(seeds),
                "count_per_kind": 2,
                "summary": summary,
                "entries": corpus,
            }
            output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            loaded = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(loaded["schema_version"], 1)
            self.assertEqual(loaded["summary"]["entries"], len(corpus))


if __name__ == "__main__":
    unittest.main()
