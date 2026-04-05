#!/usr/bin/env python3
import json
import subprocess
import sys


def run(args):
  return subprocess.run(args, capture_output=True, text=True, check=False)


def main():
  if len(sys.argv) != 2:
    print("usage: configure_branch_protection.py <owner/repo>")
    return 1
  repo = sys.argv[1]
  payload = {
      "required_status_checks": {
          "strict": True,
          "checks": [
              {"context": "CI / build-kernel-sim"},
              {"context": "Docs / markdown-lint"},
              {"context": "Clang Matrix / clang-build-and-test (c11)"},
              {"context": "Clang Matrix / clang-build-and-test (c17)"},
              {"context": "Clang Matrix / clang-sanitizers"},
          ],
      },
      "enforce_admins": False,
      "required_pull_request_reviews": {
          "dismiss_stale_reviews": True,
          "require_code_owner_reviews": True,
          "required_approving_review_count": 1,
      },
      "restrictions": None,
      "allow_force_pushes": False,
      "allow_deletions": False,
      "required_linear_history": True,
  }
  print("Dry-run payload for branch protection:")
  print(json.dumps(payload, indent=2))
  print("")
  print("To apply manually, run:")
  print(
      f"gh api --method PUT repos/{repo}/branches/main/protection "
      "--input - < payload.json"
  )
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
