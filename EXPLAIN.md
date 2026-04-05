# EXPLAIN

Auto-updated project explainer for contributors.
Last generated: 2026-04-05 10:15:26Z

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

- #22 Filesystem_scope_symlink_resolution (priority-p0, security)
- #21 Filesystem_scope_glob_patterns (priority-p1, security)
- #20 Package_dependency_cycle_detection (priority-p1)
- #19 Package_manifest_schema_versioning (priority-p1)
- #18 Auto_docs_issue_enrichment (priority-p1)
- #17 Sandbox_engine_network_scopes (priority-p1, security)
- #15 CI_add_clang_build_matrix (priority-p1)
- #14 Sandbox_policy_hot_reload (priority-p1, security)
- #13 Sandbox_policy_serialization_format (priority-p1, security)
- #12 Scheduler_metrics_and_tracepoints (priority-p1, kernel)
- #10 Capability_token_expiry_and_rotation (priority-p1, security)
- #9 Toolchain_bootstrap_for_contributors (good-first-task)
- #8 Capability_audit_log_pipeline (priority-p1, security)
- #7 Scheduler_preemption_tick_simulation (priority-p1, kernel)
- #6 Scheduler_priority_policy_v1 (priority-p1, kernel)
- #5 Contributor_onboarding_checklist (good-first-task)

## Recent Engineering Changes

- `44e7fac` (2026-04-05): Add_clang_matrix_workflow_for_core_module_tests
- `e0f7189` (2026-04-05): docs: auto-update explain and changelog
- `abdd8fa` (2026-04-05): Add_path_scoped_filesystem_enforcement_with_deny_override
- `7b72999` (2026-04-05): docs: auto-update explain and changelog
- `7ce10dc` (2026-04-05): Add_package_manifest_validator_and_ci_workflow
- `e3d506e` (2026-04-05): docs: auto-update explain and changelog
- `613b123` (2026-04-05): Add_auto_docs_workflow_and_sandbox_policy_engine_mvp
- `242200b` (2026-04-05): Add_sandbox_policy_schema_validator_and_tests
- `cccdb53` (2026-04-05): Add_capability_token_lifecycle_issue_revoke_access_checks
- `64be98e` (2026-04-05): Add_round_robin_scheduler_skeleton_with_tests
- `594b792` (2026-04-05): Add_capability_security_module_and_execution_plan
- `2c02b03` (2026-04-05): Initialize_AegisOS_scaffold
