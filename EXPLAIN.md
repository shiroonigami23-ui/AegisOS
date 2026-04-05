# EXPLAIN

Auto-updated project explainer for contributors.
Last generated: 2026-04-05 11:27:39Z

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
- #65 Sandbox_policy_migration_batch_tool (priority-p1, security)
- #64 Capability_audit_sink_rotation_retention_policy (priority-p1, security)
- #63 Scheduler_snapshot_reason_histogram_window (priority-p1, kernel)
- #62 Capability_actor_registry_and_revocation_hooks (priority-p1, security)
- #61 Filesystem_scope_wildcard_compiler_and_lint (priority-p1, security)
- #60 Network_scope_trace_machine_readable_mode (priority-p1, security)
- #59 DNS_pin_dual_stack_consistency_policy (priority-p1, security)
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

- kernel: 21
- userland: 36
- packages: 3
- docs: 44
- workflows: 0
- tests: 20
- tools: 0
- platform: 0
- scripts: 3
- other: 0

Open issue pressure by component signal:

- security: 8
- kernel: 2
- packages: 3
- docs: 1
- other: 4

## Recent Engineering Changes

- `fcf7371` (2026-04-05): Add_sandbox_policy_legacy_migration_adapter_and_report
- `7d5960e` (2026-04-05): docs: auto-update explain and changelog
- `78336af` (2026-04-05): Add_capability_audit_pagination_and_file_sink_helpers
- `14b141d` (2026-04-05): docs: auto-update explain and changelog
- `cfb4817` (2026-04-05): Add_scheduler_snapshot_schema_version_and_reason_breakdown
- `9caf674` (2026-04-05): docs: auto-update explain and changelog
- `6934178` (2026-04-05): Add_capability_actor_identity_model_and_validation
- `bd9e491` (2026-04-05): docs: auto-update explain and changelog
- `2606126` (2026-04-05): Add_filesystem_wildcard_validation_rules
- `c93539f` (2026-04-05): docs: auto-update explain and changelog
- `2ce62d0` (2026-04-05): Add_network_scope_precedence_debug_trace_api
- `e5bb38d` (2026-04-05): docs: auto-update explain and changelog
- `d669e1f` (2026-04-05): Add_dns_pinning_ipv6_support_and_guard_checks
- `30c8c0e` (2026-04-05): docs: auto-update explain and changelog
- `8a231e6` (2026-04-05): Add_policy_schema_versioning_and_hot_reload_revision_guard
