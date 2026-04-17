#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import List


def _repo_root() -> Path:
  return Path(__file__).resolve().parents[1]


def _pick_compiler(preferred: str | None) -> List[str]:
  compilers: List[str] = []
  if preferred:
    compilers.append(preferred)
  compilers.extend(["clang", "gcc", "cc"])
  seen = set()
  unique: List[str] = []
  for c in compilers:
    if c in seen:
      continue
    seen.add(c)
    unique.append(c)
  return unique


def _binary_path(root: Path) -> Path:
  name = "out_kernel_hotpath_bench"
  if os.name == "nt":
    name += ".exe"
  return root / name


def _compile(root: Path, compiler: str, output: Path) -> None:
  sources = [
      root / "tools" / "benchmarks" / "kernel_hotpath_bench.c",
      root / "kernel" / "src" / "kernel_main.c",
      root / "kernel" / "src" / "process_checkpoint.c",
      root / "kernel" / "src" / "secure_time_attestation.c",
  ]
  cmd = [
      compiler,
      "-std=c11",
      "-O2",
      "-Wall",
      "-Wextra",
      "-Wpedantic",
      "-Ikernel/include",
      *[str(s) for s in sources],
      "-o",
      str(output),
  ]
  subprocess.run(cmd, cwd=root, check=True)


def run_benchmark(iterations: int, compiler: str | None = None) -> dict:
  root = _repo_root()
  output = _binary_path(root)
  compile_errors: List[str] = []

  for c in _pick_compiler(compiler):
    try:
      _compile(root, c, output)
      break
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
      compile_errors.append(f"{c}: {exc}")
  else:
    raise RuntimeError("failed to compile benchmark binary: " + " | ".join(compile_errors))

  result = subprocess.run([str(output), str(iterations)], cwd=root, check=True, text=True, capture_output=True)
  data = json.loads(result.stdout)
  if not isinstance(data, dict) or data.get("schema_version") != 1:
    raise RuntimeError("unexpected benchmark JSON schema")
  return data


def main() -> int:
  parser = argparse.ArgumentParser(description="Run kernel cross-module hotpath benchmark and emit JSON.")
  parser.add_argument("--iterations", type=int, default=200000)
  parser.add_argument("--compiler", default=None)
  parser.add_argument("--output", default=None, help="Optional output JSON path")
  args = parser.parse_args()

  if args.iterations <= 0:
    raise ValueError("iterations must be > 0")

  data = run_benchmark(iterations=args.iterations, compiler=args.compiler)
  payload = json.dumps(data, sort_keys=True, separators=(",", ":"))
  if args.output:
    Path(args.output).write_text(payload + "\n", encoding="utf-8")
  print(payload)
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
