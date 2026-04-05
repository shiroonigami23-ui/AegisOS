# EXPLAIN

Auto-updated project explainer for contributors.
Last generated: 2026-04-05 10:57:08Z

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
- #48 Docs_heatmap_trend_window (priority-p1)
- #47 Scheduler_wait_latency_aggregation_report (priority-p1, kernel)
- #46 Scheduler_metrics_snapshot_serialization (priority-p1, kernel)
- #45 Capability_audit_actor_identity_model (priority-p1, security)
- #44 DNS_pin_ipv6_support (priority-p1, security)
- #43 Network_scope_precedence_debug_trace (priority-p1, security)
- #42 Filesystem_scope_wildcard_validation_rules (priority-p1, security)
- #40 Apply_branch_protection_profile_on_main (priority-p1)
- #39 Capability_audit_export_api (priority-p1, security)
- #38 Package_signature_metadata_fields (priority-p1, security)
- #37 Package_profile_compatibility_matrix (priority-p1)
- #36 Package_dependency_visualizer_output (priority-p1)
- #35 Package_schema_migration_helper (priority-p1)
- #34 Sanitizer_suppressions_baseline (priority-p1)
- #33 Scheduler_context_switch_reason_codes (priority-p1, kernel)
- #29 Scheduler_aging_policy_for_fairness (priority-p1, kernel)
- #27 Symlink_resolution_filesystem_backend (priority-p1, security)
- #14 Sandbox_policy_hot_reload (priority-p1, security)
- #13 Sandbox_policy_serialization_format (priority-p1, security)

### Security
- none

### Kernel
- none

### Good First Task
- #41 Onboarding_bootstrap_script_runner (good-first-task)

### Other
- none

## Component Activity Heatmap

Recent commit touches (higher means more active recently):

- kernel: 18
- userland: 16
- packages: 15
- docs: 50
- workflows: 4
- tests: 12
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

- `72a0881` (2026-04-05): Add_context_switch_reason_codes_for_scheduler_ticks
- `f0a640c` (2026-04-05): docs: auto-update explain and changelog
- `2208524` (2026-04-05): Improve_docs_heatmap_with_local_issue_fallback_and_component_signals
- `087521a` (2026-04-05): docs: auto-update explain and changelog
- `3895338` (2026-04-05): Add_tick_based_wait_latency_metrics_for_scheduler
- `b9c15ac` (2026-04-05): docs: auto-update explain and changelog
- `1cd4bc7` (2026-04-05): Add_scheduler_metrics_snapshot_endpoint_and_tests
- `81fda8b` (2026-04-05): docs: auto-update explain and changelog
- `67fc1c3` (2026-04-05): Add_rotation_actor_reason_metadata_to_capability_audit
- `5e0463e` (2026-04-05): docs: auto-update explain and changelog
- `cc26bce` (2026-04-05): Add_dns_pinning_guard_for_network_rebinding_defense
- `854afc1` (2026-04-05): docs: auto-update explain and changelog
- `33b3b00` (2026-04-05): Add_deterministic_network_scope_precedence_with_tie_break_rules
- `3206f06` (2026-04-05): docs: auto-update explain and changelog
- `40c23d8` (2026-04-05): Add_filesystem_wildcard_scope_matching_and_tests
