#!/usr/bin/env python3
import shutil
import subprocess
import sys


def run(cmd):
  return subprocess.run(cmd, capture_output=True, text=True, check=False)


def has_tool(name):
  return shutil.which(name) is not None


def main():
  required = ["git", "python", "clang"]
  optional = ["cmake", "ninja"]
  missing = [t for t in required if not has_tool(t)]

  print("AegisOS onboarding check")
  print("------------------------")
  for t in required:
    print(f"[{'ok' if t not in missing else 'missing'}] required: {t}")
  for t in optional:
    print(f"[{'ok' if has_tool(t) else 'warn'}] optional: {t}")

  if missing:
    print("")
    print("Missing required tools:", ", ".join(missing))
    return 1

  commands = [
      ["python", "scripts/validate_packages.py"],
      [
          "clang",
          "-std=c11",
          "-Wall",
          "-Wextra",
          "-Wpedantic",
          "-Ikernel/include",
          "kernel/src/kernel_main.c",
          "tests/kernel_sim_test.c",
          "-o",
          "out_kernel_test.exe",
      ],
      ["out_kernel_test.exe"],
      [
          "clang",
          "-std=c11",
          "-Wall",
          "-Wextra",
          "-Wpedantic",
          "-Iuserland/include",
          "userland/security/capability.c",
          "tests/capability_test.c",
          "-o",
          "out_capability_test.exe",
      ],
      ["out_capability_test.exe"],
      [
          "clang",
          "-std=c11",
          "-Wall",
          "-Wextra",
          "-Wpedantic",
          "-Iuserland/include",
          "userland/security/sandbox_policy.c",
          "tests/sandbox_policy_test.c",
          "-o",
          "out_sandbox_policy_test.exe",
      ],
      ["out_sandbox_policy_test.exe"],
      [
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
          "out_sandbox_engine_test.exe",
      ],
      ["out_sandbox_engine_test.exe"],
  ]

  print("")
  print("Running baseline validations...")
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

  for artifact in [
      "out_kernel_test.exe",
      "out_capability_test.exe",
      "out_sandbox_policy_test.exe",
      "out_sandbox_engine_test.exe",
  ]:
    run(["cmd", "/c", "del", "/q", artifact])

  print("")
  print("Onboarding check completed successfully.")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
