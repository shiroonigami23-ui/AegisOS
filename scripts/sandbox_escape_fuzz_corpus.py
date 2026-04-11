#!/usr/bin/env python3
import argparse
import json
import random
from pathlib import Path
from typing import Dict, List


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SEED_CORPUS = ROOT / "tests" / "sandbox_escape_seed_corpus.txt"


PATH_ESCAPE_PATTERNS = [
    "/sandbox/app/../etc/passwd",
    "/sandbox/app/./secrets.txt",
    "/sandbox/app//double/slash",
    "/sandbox/app/%2e%2e/etc/shadow",
    "/sandbox/app/%2Fetc/hosts",
    "/sandbox/app/%5cwindows/system32",
]

DNS_ESCAPE_PATTERNS = [
    {"host": "api.safe.local", "resolved_ipv4": "10.100.0.11", "resolved_ipv6": "2001:db8::64"},
    {"host": "api.safe.local", "resolved_ipv4": "10.100.0.10", "resolved_ipv6": ""},
    {"host": "api..safe.local", "resolved_ipv4": "10.100.0.10", "resolved_ipv6": "2001:db8::64"},
    {"host": "api%2esafe.local", "resolved_ipv4": "10.100.0.10", "resolved_ipv6": "2001:db8::64"},
]


def load_seed_corpus(path: Path) -> List[int]:
  seeds: List[int] = []
  for raw in path.read_text(encoding="utf-8").splitlines():
    line = raw.strip()
    if not line:
      continue
    seeds.append(int(line))
  if not seeds:
    raise ValueError("seed corpus is empty")
  return seeds


def classify_path_payload(path: str) -> str:
  lowered = path.lower()
  if "/../" in path or path.endswith("/.."):
    return "path_traversal"
  if "/./" in path or path.endswith("/."):
    return "path_dot_segment"
  if "//" in path:
    return "path_double_slash"
  if "%2e" in lowered or "%2f" in lowered or "%5c" in lowered:
    return "path_encoded_escape"
  return "path_clean"


def classify_dns_payload(host: str, resolved_ipv4: str, resolved_ipv6: str) -> str:
  lowered = host.lower()
  if ".." in host or "%2e" in lowered:
    return "dns_host_encoding_anomaly"
  if resolved_ipv4 == "10.100.0.11":
    return "dns_rebinding_mismatch"
  if not resolved_ipv6:
    return "dns_dual_stack_missing_family"
  return "dns_clean"


def build_corpus(seeds: List[int], count_per_kind: int) -> List[Dict[str, object]]:
  corpus: List[Dict[str, object]] = []
  idx = 1
  for seed in seeds:
    rng = random.Random(seed)
    for _ in range(count_per_kind):
      path = PATH_ESCAPE_PATTERNS[rng.randrange(0, len(PATH_ESCAPE_PATTERNS))]
      reason = classify_path_payload(path)
      corpus.append(
          {
              "id": idx,
              "seed": seed,
              "kind": "path",
              "payload": {"path": path},
              "expected_block": 1 if reason != "path_clean" else 0,
              "reason": reason,
          }
      )
      idx += 1
      dns = DNS_ESCAPE_PATTERNS[rng.randrange(0, len(DNS_ESCAPE_PATTERNS))]
      dns_reason = classify_dns_payload(dns["host"], dns["resolved_ipv4"], dns["resolved_ipv6"])
      corpus.append(
          {
              "id": idx,
              "seed": seed,
              "kind": "dns",
              "payload": dns,
              "expected_block": 1 if dns_reason != "dns_clean" else 0,
              "reason": dns_reason,
          }
      )
      idx += 1
  return corpus


def summarize_corpus(corpus: List[Dict[str, object]]) -> Dict[str, object]:
  reason_counts: Dict[str, int] = {}
  kind_counts: Dict[str, int] = {"path": 0, "dns": 0}
  for entry in corpus:
    reason = str(entry["reason"])
    kind = str(entry["kind"])
    reason_counts[reason] = reason_counts.get(reason, 0) + 1
    kind_counts[kind] = kind_counts.get(kind, 0) + 1
  return {
      "schema_version": 1,
      "entries": len(corpus),
      "kind_counts": kind_counts,
      "reason_counts": reason_counts,
  }


def main() -> int:
  parser = argparse.ArgumentParser(description="Generate sandbox escape fuzz seed corpus.")
  parser.add_argument("--seed-corpus", default=str(DEFAULT_SEED_CORPUS))
  parser.add_argument("--count-per-kind", type=int, default=4)
  parser.add_argument("--output-json", default=str(ROOT / "tests" / "sandbox_escape_fuzz_corpus.json"))
  args = parser.parse_args()

  if args.count_per_kind <= 0:
    raise ValueError("count-per-kind must be > 0")

  seeds = load_seed_corpus(Path(args.seed_corpus))
  corpus = build_corpus(seeds, args.count_per_kind)
  summary = summarize_corpus(corpus)
  out = {
      "schema_version": 1,
      "seed_count": len(seeds),
      "count_per_kind": args.count_per_kind,
      "summary": summary,
      "entries": corpus,
  }
  Path(args.output_json).write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
  print(json.dumps(summary, separators=(",", ":"), sort_keys=True))
  return 0


if __name__ == "__main__":
  try:
    raise SystemExit(main())
  except ValueError as exc:
    print(f"Corpus generation failed: {exc}")
    raise SystemExit(1)
