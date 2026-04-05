# EXPLAIN

Auto-updated project explainer for contributors.
Last generated: 2026-04-05 10:48:11Z

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
- #32 Scheduler_tick_counter_usage (priority-p1, kernel)
- #31 Scheduler_metrics_export_endpoint (priority-p1, kernel)
- #30 Docs_enrichment_component_heatmap (priority-p1)
- #29 Scheduler_aging_policy_for_fairness (priority-p1, kernel)
- #28 Capability_rotation_audit_metadata (priority-p1, security)
- #27 Symlink_resolution_filesystem_backend (priority-p1, security)
- #26 Network_scope_dns_rebinding_guard (priority-p1, security)
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

## Recent Engineering Changes

- `cc26bce` (2026-04-05): Add_dns_pinning_guard_for_network_rebinding_defense
- `854afc1` (2026-04-05): docs: auto-update explain and changelog
- `33b3b00` (2026-04-05): Add_deterministic_network_scope_precedence_with_tie_break_rules
- `3206f06` (2026-04-05): docs: auto-update explain and changelog
- `40c23d8` (2026-04-05): Add_filesystem_wildcard_scope_matching_and_tests
- `cc8fe1d` (2026-04-05): docs: auto-update explain and changelog
- `1ffc333` (2026-04-05): Fix_project_automation_workflow_syntax_and_token_fallback
- `4a6bd9b` (2026-04-05): docs: auto-update explain and changelog
- `9ebe78b` (2026-04-05): Fix_project_automation_with_PAT_secret_and_github_script_v8
- `6f279cc` (2026-04-05): docs: auto-update explain and changelog
- `43de16a` (2026-04-05): Add_contributor_onboarding_checklist_and_reference
- `d8ee84a` (2026-04-05): docs: auto-update explain and changelog
- `65fc46c` (2026-04-05): Add_branch_protection_profile_and_configuration_helper
- `abdd8a3` (2026-04-05): docs: auto-update explain and changelog
- `0b4425a` (2026-04-05): Add_project_board_automation_and_capability_audit_pipeline
