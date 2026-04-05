# EXPLAIN

Auto-updated project explainer for contributors.
Last generated: 2026-04-05 10:40:00Z

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
- #39 Capability_audit_export_api (priority-p1, security)
- #38 Package_signature_metadata_fields (priority-p1, security)
- #37 Package_profile_compatibility_matrix (priority-p1)
- #36 Package_dependency_visualizer_output (priority-p1)
- #35 Package_schema_migration_helper (priority-p1)
- #34 Sanitizer_suppressions_baseline (priority-p1)
- #33 Scheduler_context_switch_reason_codes (priority-p1, kernel)
- #32 Scheduler_tick_counter_usage (priority-p1, kernel)
- #31 Scheduler_metrics_export_endpoint (priority-p1, kernel)
- #30 Docs_enrichment_component_heatmap (priority-p1)
- #29 Scheduler_aging_policy_for_fairness (priority-p1, kernel)
- #28 Capability_rotation_audit_metadata (priority-p1, security)
- #27 Symlink_resolution_filesystem_backend (priority-p1, security)
- #26 Network_scope_dns_rebinding_guard (priority-p1, security)
- #25 Network_scope_priority_and_specificity (priority-p1, security)
- #24 Workflow_branch_protection_profile (priority-p1)
- #21 Filesystem_scope_glob_patterns (priority-p1, security)
- #14 Sandbox_policy_hot_reload (priority-p1, security)
- #13 Sandbox_policy_serialization_format (priority-p1, security)

### Security
- none

### Kernel
- none

### Good First Task
- #9 Toolchain_bootstrap_for_contributors (good-first-task)

### Other
- none

## Recent Engineering Changes

- `65fc46c` (2026-04-05): Add_branch_protection_profile_and_configuration_helper
- `abdd8a3` (2026-04-05): docs: auto-update explain and changelog
- `0b4425a` (2026-04-05): Add_project_board_automation_and_capability_audit_pipeline
- `1ab272f` (2026-04-05): docs: auto-update explain and changelog
- `8d1da52` (2026-04-05): Add_expanded_core_packages_and_install_profiles
- `c454d23` (2026-04-05): docs: auto-update explain and changelog
- `fa8d88a` (2026-04-05): Add_package_dependency_cycle_detection_to_validator
- `309e75f` (2026-04-05): docs: auto-update explain and changelog
- `a728fcd` (2026-04-05): Add_package_manifest_schema_version_1_validation
- `0908d44` (2026-04-05): docs: auto-update explain and changelog
- `887ffdd` (2026-04-05): Add_ASAN_UBSAN_sanitizer_jobs_to_clang_workflow
- `6269434` (2026-04-05): docs: auto-update explain and changelog
- `4f20083` (2026-04-05): Add_timer_tick_preemption_simulation_with_quantum_hooks
- `c181e22` (2026-04-05): docs: auto-update explain and changelog
- `0e65665` (2026-04-05): Add_scheduler_metrics_tracepoints_and_tests
