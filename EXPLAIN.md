# EXPLAIN

Auto-updated project explainer for contributors.
Last generated: 2026-04-05 12:59:48Z

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
- #79 "Trace_json_property_perf_baseline_and_seed_corpus" (priority-p1, security)
- #70 Actor_registry_persistent_backing_store (priority-p1, security)
- #40 Apply_branch_protection_profile_on_main (priority-p1)
- #37 Package_profile_compatibility_matrix (priority-p1)
- #35 Package_schema_migration_helper (priority-p1)
- #34 Sanitizer_suppressions_baseline (priority-p1)
- #27 Symlink_resolution_filesystem_backend (priority-p1, security)

### Security
- none

### Kernel
- none

### Good First Task
- #9 Toolchain_bootstrap_for_contributors (good-first-task)

### Other
- none

## Component Activity Heatmap

Recent commit touches in `weekly` window (higher means more active recently):

- kernel: 47
- userland: 86
- packages: 38
- docs: 151
- workflows: 13
- tests: 55
- tools: 1
- platform: 1
- scripts: 26
- other: 14

Open issue pressure by component signal:

- security: 3
- kernel: 0
- packages: 2
- docs: 0
- other: 3

## Recent Engineering Changes

- `dfb3685` (2026-04-05): "Add_package_profile_to_hardware_compatibility_matrix_docs"
- `de08c6f` (2026-04-05): docs: auto-update explain and changelog
- `15c3fc8` (2026-04-05): "Add_package_signature_placeholder_fields_and_schema_validation"
- `fe4102e` (2026-04-05): docs: auto-update explain and changelog
- `6eb55d1` (2026-04-05): "Add_scheduler_aging_boost_policy_for_low_priority_fairness"
- `f0b77b3` (2026-04-05): docs: auto-update explain and changelog
- `9a56599` (2026-04-05): "Add_configurable_docs_heatmap_trend_windows"
- `8c49c14` (2026-04-05): docs: auto-update explain and changelog
- `42f5deb` (2026-04-05): "Add_graphviz_rendering_guide_for_package_dependency_graph"
- `7b57902` (2026-04-05): docs: auto-update explain and changelog
- `02df452` (2026-04-05): "Add_onboarding_ci_command_equivalence_guardrails"
- `4a96fa2` (2026-04-05): docs: auto-update explain and changelog
- `4926515` (2026-04-05): "Add_seed_replay_harness_for_trace_json_property_tests"
- `2827cf3` (2026-04-05): docs: auto-update explain and changelog
- `469b842` (2026-04-05): "Add_json_endpoint_for_custom_window_histogram_query"
