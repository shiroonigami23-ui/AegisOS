#!/usr/bin/env python3
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ASAN_SUPPRESSIONS = ROOT / "tests" / "sanitizers" / "asan.supp"
UBSAN_SUPPRESSIONS = ROOT / "tests" / "sanitizers" / "ubsan.supp"
IS_WINDOWS = os.name == "nt"
ASAN_SUPPRESSIONS_REL = "tests/sanitizers/asan.supp"
UBSAN_SUPPRESSIONS_REL = "tests/sanitizers/ubsan.supp"


def run(cmd, extra_env=None):
  env = os.environ.copy()
  if extra_env:
    env.update(extra_env)
  return subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True, check=False, env=env)


def main():
  artifact_suffix = ".exe" if IS_WINDOWS else ""
  run_capability = f"out_capability_san{artifact_suffix}" if IS_WINDOWS else "./out_capability_san"
  run_engine = f"out_sandbox_engine_san{artifact_suffix}" if IS_WINDOWS else "./out_sandbox_engine_san"
  asan_options = f"suppressions={ASAN_SUPPRESSIONS_REL}:halt_on_error=1"
  if not IS_WINDOWS:
    asan_options += ":detect_leaks=1"
  suppress_env = {
      "ASAN_OPTIONS": asan_options,
      "UBSAN_OPTIONS": f"suppressions={UBSAN_SUPPRESSIONS_REL}:print_stacktrace=1:halt_on_error=1",
  }

  commands = [
      [
          "clang",
          "-std=c11",
          "-Wall",
          "-Wextra",
          "-Wpedantic",
          "-fsanitize=address,undefined",
          "-fno-omit-frame-pointer",
          "-Iuserland/include",
          "userland/security/capability.c",
          "tests/capability_test.c",
          "-o",
          f"out_capability_san{artifact_suffix}",
      ],
      [run_capability],
      [
          "clang",
          "-std=c11",
          "-Wall",
          "-Wextra",
          "-Wpedantic",
          "-fsanitize=address,undefined",
          "-fno-omit-frame-pointer",
          "-Iuserland/include",
          "userland/security/capability.c",
          "userland/security/sandbox_policy.c",
          "userland/security/sandbox_engine.c",
          "tests/sandbox_engine_test.c",
          "-o",
          f"out_sandbox_engine_san{artifact_suffix}",
      ],
      [run_engine],
  ]

  if not ASAN_SUPPRESSIONS.exists() or not UBSAN_SUPPRESSIONS.exists():
    print("[fail] sanitizer suppression baseline files are missing")
    return 1

  for cmd in commands:
    result = run(cmd, extra_env=suppress_env)
    if result.returncode != 0:
      print(f"[fail] {' '.join(cmd)}")
      if result.stdout.strip():
        print(result.stdout.strip())
      if result.stderr.strip():
        print(result.stderr.strip())
      return 1
    print(f"[ok] {' '.join(cmd)}")

  for artifact in [f"out_capability_san{artifact_suffix}", f"out_sandbox_engine_san{artifact_suffix}"]:
    try:
      (ROOT / artifact).unlink()
    except FileNotFoundError:
      pass

  return 0


if __name__ == "__main__":
  sys.exit(main())
