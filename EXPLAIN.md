# EXPLAIN

Auto-updated project explainer for contributors.
Last generated: 2026-04-05 12:41:19Z

## What AegisOS Is Building

AegisOS is a security-first operating system designed to combine the strongest traits of major platforms in one coherent product:

- iOS: secure defaults, trusted update path, cohesive platform behavior.
- Linux: customization, openness, privacy-first control.
- Windows: practical compatibility strategy for apps and workflows.
- macOS: polish, consistency, and efficiency.
- Android: broad device profile flexibility.

## How We Build It

We implement in vertical slices:

1. Core kernel and scheduler primitives.
2. Security controls (capabilities, sandbox policies, enforcement engine).
3. Packaging and update integrity.
4. UX and compatibility layers.
5. Observability, reliability, and contributor scale-out.

## Current Technical Baseline

- Kernel simulation target with round-robin scheduler skeleton and tests.
- Capability token lifecycle (`issue`, `revoke`, authorization checks).
- Sandbox policy schema validator and test suite.
- CI/docs workflows and contributor-ready GitHub templates.

## Live Backlog Snapshot

### Priority P0
- none

### Priority P1
- #77 Trace_json_property_seed_replay_harness (priority-p1, security)
- #70 Actor_registry_persistent_backing_store (priority-p1, security)
- #69 Scheduler_reason_histogram_custom_window_query (priority-p1, kernel)
- #53 Package_graph_rendering_guide (priority-p1)
- #48 Docs_heatmap_trend_window (priority-p1)
- #40 Apply_branch_protection_profile_on_main (priority-p1)
- #38 Package_signature_metadata_fields (priority-p1, security)
- #37 Package_profile_compatibility_matrix (priority-p1)
- #35 Package_schema_migration_helper (priority-p1)
- #34 Sanitizer_suppressions_baseline (priority-p1)
- #29 Scheduler_aging_policy_for_fairness (priority-p1, kernel)
- #27 Symlink_resolution_filesystem_backend (priority-p1, security)

### Security
- none

### Kernel
- none

### Good First Task
- #50 Onboarding_runner_ci_equivalence_check (good-first-task)
- #9 Toolchain_bootstrap_for_contributors (good-first-task)

### Other
- none

## Component Activity Heatmap

Recent commit touches (higher means more active recently):

- kernel: 9
- userland: 36
- packages: 0
- docs: 40
- workflows: 0
- tests: 23
- tools: 0
- platform: 0
- scripts: 9
- other: 0

Open issue pressure by component signal:

- security: 4
- kernel: 2
- packages: 3
- docs: 1
- other: 4

## Recent Engineering Changes

- `63ab58e` (2026-04-05): "Add_custom_window_scheduler_reason_histogram_query_api"
- `b2060fd` (2026-04-05): docs: auto-update explain and changelog
- `36f49b1` (2026-04-05): "Add_property_style_network_trace_json_generator_tests"
- `41c9387` (2026-04-05): docs: auto-update explain and changelog
- `967570c` (2026-04-05): "Add_batch_migration_filters_shards_and_trace_json_fuzz_tests"
- `089484e` (2026-04-05): docs: auto-update explain and changelog
- `2da5998` (2026-04-05): "Add_migration_dry_run_diff_preview_and_manifest_incremental_diff"
- `046e182` (2026-04-05): docs: auto-update explain and changelog
- `15c20a4` (2026-04-05): "Add_audit_sink_retention_manifest_generator_and_tests"
- `b11b997` (2026-04-05): docs: auto-update explain and changelog
- `1acc1f2` (2026-04-05): "Harden_network_trace_json_string_escaping"
- `aec6f73` (2026-04-05): docs: auto-update explain and changelog
- `1bd30e4` (2026-04-05): "Add_batch_sandbox_policy_migration_cli_with_summary_and_exit_codes"
- `7dd0f88` (2026-04-05): docs: auto-update explain and changelog
- `982db4a` (2026-04-05): "Add_trace_schema_versioning_and_audit_retention_planning_helpers"
