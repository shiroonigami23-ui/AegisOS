# EXPLAIN

Auto-updated project explainer for contributors.
Last generated: 2026-04-05 11:46:16Z

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
- #71 Audit_sink_retention_manifest_generator (priority-p1, security)
- #70 Actor_registry_persistent_backing_store (priority-p1, security)
- #69 Scheduler_reason_histogram_custom_window_query (priority-p1, kernel)
- #68 Trace_JSON_string_escaping_hardening (priority-p1, security)
- #65 Sandbox_policy_migration_batch_tool (priority-p1, security)
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

- kernel: 15
- userland: 47
- packages: 3
- docs: 40
- workflows: 0
- tests: 23
- tools: 0
- platform: 0
- scripts: 3
- other: 0

Open issue pressure by component signal:

- security: 6
- kernel: 2
- packages: 3
- docs: 1
- other: 4

## Recent Engineering Changes

- `1bd30e4` (2026-04-05): "Add_batch_sandbox_policy_migration_cli_with_summary_and_exit_codes"
- `7dd0f88` (2026-04-05): docs: auto-update explain and changelog
- `982db4a` (2026-04-05): "Add_trace_schema_versioning_and_audit_retention_planning_helpers"
- `8cf8915` (2026-04-05): docs: auto-update explain and changelog
- `42bd665` (2026-04-05): "Add_actor_registry_lifecycle_and_scheduler_histogram_window"
- `0b244e0` (2026-04-05): docs: auto-update explain and changelog
- `2f44a9a` (2026-04-05): "Add_windowed_switch_reason_histogram_to_scheduler_snapshot"
- `bd68b5e` (2026-04-05): docs: auto-update explain and changelog
- `9f37adb` (2026-04-05): "Add_dns_dual_stack_trace_evidence_and_fs_wildcard_lint_compile"
- `f56fd91` (2026-04-05): docs: auto-update explain and changelog
- `206412e` (2026-04-05): Add_machine_readable_json_network_trace_api
- `cc19e78` (2026-04-05): docs: auto-update explain and changelog
- `c29ca17` (2026-04-05): Add_dns_dual_stack_strict_mode_enforcement
- `afeccb8` (2026-04-05): docs: auto-update explain and changelog
- `fcf7371` (2026-04-05): Add_sandbox_policy_legacy_migration_adapter_and_report
