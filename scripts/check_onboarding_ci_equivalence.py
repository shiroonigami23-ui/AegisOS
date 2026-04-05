#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def must_contain(path, needle):
  text = path.read_text(encoding="utf-8")
  if needle not in text:
    raise SystemExit(f"[fail] expected to find `{needle}` in {path}")
  print(f"[ok] {path.name} contains `{needle}`")


def main():
  onboarding_path = ROOT / "scripts" / "onboarding_check.py"
  workflow_path = ROOT / ".github" / "workflows" / "clang-tests.yml"

  must_contain(onboarding_path, "scripts/run_clang_suite.py")
  must_contain(onboarding_path, "--std")
  must_contain(onboarding_path, "c11")

  must_contain(workflow_path, "python3 scripts/run_clang_suite.py --std ${{ matrix.c_standard }}")
  must_contain(workflow_path, "python3 scripts/check_onboarding_ci_equivalence.py")
  print("[ok] onboarding/ci equivalence guard passed")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
