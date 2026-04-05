# EXPLAIN

Auto-updated project explainer for contributors.
Last generated: 2026-04-05 11:08:44Z

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
- #54 Scheduler_wait_report_snapshot_endpoint (priority-p1, kernel)
- #53 Package_graph_rendering_guide (priority-p1)
- #52 Sandbox_policy_hot_reload_version_guard (priority-p1, security)
- #51 Sandbox_policy_versioned_json_schema (priority-p1, security)
- #49 Scheduler_reason_code_metrics_breakdown (priority-p1, kernel)
- #48 Docs_heatmap_trend_window (priority-p1)
- #46 Scheduler_metrics_snapshot_serialization (priority-p1, kernel)
- #45 Capability_audit_actor_identity_model (priority-p1, security)
- #44 DNS_pin_ipv6_support (priority-p1, security)
- #43 Network_scope_precedence_debug_trace (priority-p1, security)
- #42 Filesystem_scope_wildcard_validation_rules (priority-p1, security)
- #40 Apply_branch_protection_profile_on_main (priority-p1)
- #39 Capability_audit_export_api (priority-p1, security)
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

### Other
- none

## Component Activity Heatmap

Recent commit touches (higher means more active recently):

- kernel: 15
- userland: 22
- packages: 14
- docs: 49
- workflows: 3
- tests: 13
- tools: 0
- platform: 0
- scripts: 6
- other: 0

Open issue pressure by component signal:

- security: 9
- kernel: 4
- packages: 3
- docs: 1
- other: 3

## Recent Engineering Changes

- `b3e272f` (2026-04-05): Add_capability_audit_export_and_scheduler_reason_metrics
- `faca1c9` (2026-04-05): docs: auto-update explain and changelog
- `0533870` (2026-04-05): Add_package_dependency_graph_exports_and_scheduler_wait_report
- `2079757` (2026-04-05): docs: auto-update explain and changelog
- `f860e26` (2026-04-05): Add_sandbox_policy_hot_reload_with_safe_validation
- `4c84428` (2026-04-05): docs: auto-update explain and changelog
- `c9cfff6` (2026-04-05): Add_sandbox_policy_json_serialization_and_parsing_support
- `e14edc6` (2026-04-05): docs: auto-update explain and changelog
- `97c06b2` (2026-04-05): Add_one_command_onboarding_bootstrap_runner
- `0f6d8a0` (2026-04-05): docs: auto-update explain and changelog
- `72a0881` (2026-04-05): Add_context_switch_reason_codes_for_scheduler_ticks
- `f0a640c` (2026-04-05): docs: auto-update explain and changelog
- `2208524` (2026-04-05): Improve_docs_heatmap_with_local_issue_fallback_and_component_signals
- `087521a` (2026-04-05): docs: auto-update explain and changelog
- `3895338` (2026-04-05): Add_tick_based_wait_latency_metrics_for_scheduler
