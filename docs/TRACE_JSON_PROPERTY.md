# Trace JSON Property Profiling

This guide covers deterministic replay and runtime profiling for the sandbox network trace JSON
property-style tests.

## Reproduction Knobs

- `AEGIS_TRACE_JSON_FUZZ_SEED`: sets deterministic generator seed.
- `AEGIS_TRACE_JSON_FUZZ_ITERS`: overrides property loop iterations.
- `AEGIS_TRACE_JSON_FUZZ_REPLAY_SEED`: runs a single deterministic replay case.

## Seed Corpus

- canonical corpus: `tests/trace_json_seed_corpus.txt`
- use this file to preserve high-entropy regression cases over time.

## Profiling Script

- full profile:
  - `python scripts/profile_trace_json_property.py --summary-json out_trace_json_profile.json`
- CI smoke profile:
  - `python scripts/profile_trace_json_property.py --smoke --summary-json trace-json-profile-summary.json`

Outputs include median baseline runtime plus per-seed replay timings to speed regression triage.
