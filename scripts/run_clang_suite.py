#!/usr/bin/env python3
import argparse
import os
import subprocess
import sys


def run(cmd):
  return subprocess.run(cmd, capture_output=True, text=True, check=False)


def suite_commands(c_standard, artifact_suffix):
  warn_flags = ["-Wall", "-Wextra", "-Wpedantic"]
  kernel_out = f"out_kernel_test{artifact_suffix}"
  capability_out = f"out_capability_test{artifact_suffix}"
  sandbox_policy_out = f"out_sandbox_policy_test{artifact_suffix}"
  sandbox_engine_out = f"out_sandbox_engine_test{artifact_suffix}"
  return [
      [
          "clang",
          f"-std={c_standard}",
          *warn_flags,
          "-Ikernel/include",
          "kernel/src/kernel_main.c",
          "tests/kernel_sim_test.c",
          "-o",
          kernel_out,
      ],
      [kernel_out],
      [
          "clang",
          f"-std={c_standard}",
          *warn_flags,
          "-Iuserland/include",
          "userland/security/capability.c",
          "tests/capability_test.c",
          "-o",
          capability_out,
      ],
      [capability_out],
      [
          "clang",
          f"-std={c_standard}",
          *warn_flags,
          "-Iuserland/include",
          "userland/security/sandbox_policy.c",
          "tests/sandbox_policy_test.c",
          "-o",
          sandbox_policy_out,
      ],
      [sandbox_policy_out],
      [
          "clang",
          f"-std={c_standard}",
          *warn_flags,
          "-Iuserland/include",
          "userland/security/capability.c",
          "userland/security/sandbox_policy.c",
          "userland/security/sandbox_engine.c",
          "tests/sandbox_engine_test.c",
          "-o",
          sandbox_engine_out,
      ],
      [sandbox_engine_out],
  ]


def cleanup_artifacts(artifact_suffix):
  for artifact in [
      f"out_kernel_test{artifact_suffix}",
      f"out_capability_test{artifact_suffix}",
      f"out_sandbox_policy_test{artifact_suffix}",
      f"out_sandbox_engine_test{artifact_suffix}",
  ]:
    try:
      os.remove(artifact)
    except FileNotFoundError:
      pass


def main():
  parser = argparse.ArgumentParser(description="Build and run AegisOS clang test suite.")
  parser.add_argument("--std", default="c11", help="C standard (for example: c11, c17)")
  parser.add_argument(
      "--artifact-suffix",
      default=(".exe" if os.name == "nt" else ""),
      help="Executable suffix used for emitted artifacts",
  )
  parser.add_argument(
      "--keep-artifacts",
      action="store_true",
      help="Do not remove built test binaries after execution",
  )
  args = parser.parse_args()

  commands = suite_commands(args.std, args.artifact_suffix)
  for cmd in commands:
    result = run(cmd)
    if result.returncode != 0:
      print(f"[fail] {' '.join(cmd)}")
      if result.stdout.strip():
        print(result.stdout.strip())
      if result.stderr.strip():
        print(result.stderr.strip())
      return 1
    print(f"[ok] {' '.join(cmd)}")

  if not args.keep_artifacts:
    cleanup_artifacts(args.artifact_suffix)

  return 0


if __name__ == "__main__":
  raise SystemExit(main())
