# EXPLAIN

Auto-updated project explainer for contributors.
Last generated: 2026-04-05 11:16:26Z

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
- #59 DNS_pin_dual_stack_consistency_policy (priority-p1, security)
- #58 Sandbox_policy_schema_migration_adapter (priority-p1, security)
- #57 Scheduler_snapshot_schema_version_tag (priority-p1, kernel)
- #56 Scheduler_reason_metrics_snapshot_endpoint_extension (priority-p1, kernel)
- #55 Capability_audit_export_file_sink_and_pagination (priority-p1, security)
- #53 Package_graph_rendering_guide (priority-p1)
- #48 Docs_heatmap_trend_window (priority-p1)
- #45 Capability_audit_actor_identity_model (priority-p1, security)
- #43 Network_scope_precedence_debug_trace (priority-p1, security)
- #42 Filesystem_scope_wildcard_validation_rules (priority-p1, security)
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

- kernel: 18
- userland: 26
- packages: 3
- docs: 48
- workflows: 2
- tests: 16
- tools: 0
- platform: 0
- scripts: 4
- other: 0

Open issue pressure by component signal:

- security: 8
- kernel: 3
- packages: 3
- docs: 1
- other: 4

## Recent Engineering Changes

- `d669e1f` (2026-04-05): Add_dns_pinning_ipv6_support_and_guard_checks
- `30c8c0e` (2026-04-05): docs: auto-update explain and changelog
- `8a231e6` (2026-04-05): Add_policy_schema_versioning_and_hot_reload_revision_guard
- `16b9f0a` (2026-04-05): docs: auto-update explain and changelog
- `f6168cd` (2026-04-05): Add_scheduler_wait_snapshot_endpoint_and_json_serializers
- `7ba1c60` (2026-04-05): docs: auto-update explain and changelog
- `b3e272f` (2026-04-05): Add_capability_audit_export_and_scheduler_reason_metrics
- `faca1c9` (2026-04-05): docs: auto-update explain and changelog
- `0533870` (2026-04-05): Add_package_dependency_graph_exports_and_scheduler_wait_report
- `2079757` (2026-04-05): docs: auto-update explain and changelog
- `f860e26` (2026-04-05): Add_sandbox_policy_hot_reload_with_safe_validation
- `4c84428` (2026-04-05): docs: auto-update explain and changelog
- `c9cfff6` (2026-04-05): Add_sandbox_policy_json_serialization_and_parsing_support
- `e14edc6` (2026-04-05): docs: auto-update explain and changelog
- `97c06b2` (2026-04-05): Add_one_command_onboarding_bootstrap_runner
