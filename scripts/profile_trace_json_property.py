#!/usr/bin/env python3
import argparse
import json
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SEED_CORPUS = ROOT / "tests" / "trace_json_seed_corpus.txt"
IS_WINDOWS = os.name == "nt"


def run(cmd, env=None):
  full_env = os.environ.copy()
  if env:
    full_env.update(env)
  return subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True, check=False, env=full_env)


def load_seed_corpus(path):
  seeds = []
  for raw in path.read_text(encoding="utf-8").splitlines():
    line = raw.strip()
    if not line:
      continue
    seeds.append(int(line))
  return seeds


def main():
  parser = argparse.ArgumentParser(description="Profile trace JSON property test runtime and seed replay corpus.")
  parser.add_argument("--seed-corpus", default=str(SEED_CORPUS), help="Path to newline-separated integer seeds")
  parser.add_argument("--summary-json", help="Optional JSON output path")
  parser.add_argument("--baseline-runs", type=int, default=5, help="Number of baseline runs for median timing")
  parser.add_argument("--smoke", action="store_true", help="Use reduced runs and subset seed corpus for CI smoke")
  parser.add_argument(
      "--smoke-seeds",
      type=int,
      default=3,
      help="Number of corpus seeds to replay in smoke mode (or all in full mode)",
  )
  args = parser.parse_args()

  if args.baseline_runs <= 0:
    print("baseline-runs must be > 0", file=sys.stderr)
    return 2

  artifact_suffix = ".exe" if IS_WINDOWS else ""
  binary_name = f"out_sandbox_engine_profile{artifact_suffix}"
  run_target = binary_name if IS_WINDOWS else f"./{binary_name}"

  compile_cmd = [
      "clang",
      "-std=c11",
      "-Wall",
      "-Wextra",
      "-Wpedantic",
      "-Iuserland/include",
      "userland/security/capability.c",
      "userland/security/sandbox_policy.c",
      "userland/security/sandbox_engine.c",
      "tests/sandbox_engine_test.c",
      "-o",
      binary_name,
  ]
  built = run(compile_cmd)
  if built.returncode != 0:
    print("[fail] compile trace profile binary")
    if built.stdout.strip():
      print(built.stdout.strip())
    if built.stderr.strip():
      print(built.stderr.strip())
    return 1

  corpus = load_seed_corpus(Path(args.seed_corpus))
  if not corpus:
    print("[fail] seed corpus is empty")
    return 1
  selected_corpus = corpus[: args.smoke_seeds] if args.smoke else corpus
  baseline_runs = 3 if args.smoke else args.baseline_runs

  baseline_samples = []
  for _ in range(baseline_runs):
    env = {
        "AEGIS_TRACE_JSON_FUZZ_SEED": str(corpus[0]),
    }
    start = time.perf_counter()
    rc = run([run_target], env=env)
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    if rc.returncode != 0:
      print("[fail] baseline run failed")
      if rc.stdout.strip():
        print(rc.stdout.strip())
      if rc.stderr.strip():
        print(rc.stderr.strip())
      return 1
    baseline_samples.append(elapsed_ms)

  replay_samples = []
  for seed in selected_corpus:
    env = {"AEGIS_TRACE_JSON_FUZZ_REPLAY_SEED": str(seed)}
    start = time.perf_counter()
    rc = run([run_target], env=env)
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    if rc.returncode != 0:
      print(f"[fail] replay run failed for seed={seed}")
      if rc.stdout.strip():
        print(rc.stdout.strip())
      if rc.stderr.strip():
        print(rc.stderr.strip())
      return 1
    replay_samples.append({"seed": seed, "elapsed_ms": round(elapsed_ms, 3)})

  summary = {
      "schema_version": 1,
      "mode": "smoke" if args.smoke else "full",
      "baseline_runs": baseline_runs,
      "baseline_samples_ms": [round(x, 3) for x in baseline_samples],
      "baseline_median_ms": round(statistics.median(baseline_samples), 3),
      "seed_corpus_total": len(corpus),
      "seed_replay_count": len(selected_corpus),
      "seed_replay_samples": replay_samples,
  }
  print(json.dumps(summary, indent=2, sort_keys=True))
  if args.summary_json:
    Path(args.summary_json).write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

  try:
    (ROOT / binary_name).unlink()
  except FileNotFoundError:
    pass
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
