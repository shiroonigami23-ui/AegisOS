# Branch Protection Profile

This profile defines recommended protection rules for `main` in AegisOS.

## Recommended Rules

- Require pull request reviews before merging.
- Require at least `1` approving review.
- Dismiss stale pull request approvals on new commits.
- Require status checks to pass before merge.
- Require branches to be up to date before merge.
- Restrict direct pushes to `main`.
- Block force pushes and branch deletions.
- Enable linear history.
- Include administrators in enforcement once the contributor flow is stable.

## Required Checks (Initial Set)

- `CI / build-kernel-sim`
- `Docs / markdown-lint`
- `Clang Matrix / clang-build-and-test (c11)`
- `Clang Matrix / clang-build-and-test (c17)`
- `Clang Matrix / clang-sanitizers`

## Why This Matters

- Keeps `main` always releasable.
- Prevents accidental bypass of tests and reviews.
- Improves trust for external collaborators.

## Safe Rollout

1. Start with review + checks, without admin enforcement.
2. Observe for one week of contributor activity.
3. Enable admin enforcement and stricter review rules.

