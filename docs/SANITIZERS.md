# Sanitizer Baseline

AegisOS uses ASAN + UBSAN in CI to catch memory safety and undefined behavior regressions.

## Baseline Files

- `tests/sanitizers/asan.supp`
- `tests/sanitizers/ubsan.supp`

These files are intentionally minimal. They should only contain suppressions for investigated
false positives, never for unknown crashes or real defects.

## Local Run

- `python scripts/run_sanitizer_suite.py`

## Policy

- Fix root causes first.
- Add suppressions only when the signal is confirmed false-positive or third-party noise.
- Keep suppression entries narrow (specific symbol/file/type), with follow-up issue references in PR notes.
