# Contributor Onboarding

Use this checklist for first-time contributors to AegisOS.

## Day 0 Setup

- Fork the repository and clone locally.
- Install toolchain:
  - `clang`
  - `cmake`
  - `ninja` (recommended)
  - `python3`
- Run package validation:
  - `python scripts/validate_packages.py`
- Build and run core local tests:
  - kernel test
  - capability test
  - sandbox policy test
  - sandbox engine test
- One-command onboarding runner:
  - `python scripts/onboarding_check.py`

## Read Before Coding

- [`README.md`](../README.md)
- [`docs/ARCHITECTURE.md`](ARCHITECTURE.md)
- [`docs/SECURITY_MODEL.md`](SECURITY_MODEL.md)
- [`docs/IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md)
- [`EXPLAIN.md`](../EXPLAIN.md)

## Pick First Work

- Open GitHub issues labeled `good-first-task`.
- Prefer docs, test coverage, and tooling improvements for first PR.
- Keep first PR scoped and small.

## PR Checklist

- Add/adjust tests for behavioral changes.
- Run local validation before opening PR.
- Keep commit messages focused by logical change.
- Reference the issue number in PR description.
- Ensure CI checks pass before requesting review.

## Communication Norms

- Ask architecture questions in issue discussion before large refactors.
- Prefer small iterative PRs over large monolithic changes.
- Document tradeoffs and security impact in PR notes.

