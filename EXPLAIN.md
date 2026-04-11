# EXPLAIN

Auto-updated project explainer for contributors.
Last generated: 2026-04-11 15:53:29Z

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
- #140 Sandbox_escape_property_fuzz_seed_corpus_expansion (enhancement, priority-p0, security)
- #137 Package_signature_verifier_real_crypto_path (enhancement, priority-p0, security)
- #136 Kernel_secure_time_source_attestation (enhancement, priority-p0, security, kernel)

### Priority P1
- #142 Kernel_checkpoint_journal_persistence_and_replay (enhancement, priority-p1, kernel)
- #141 Supervisor_restart_budget_health_probe_and_metrics_export (enhancement, priority-p1)
- #139 Userland_permission_center_change_approval_flow (enhancement, priority-p1, security)
- #138 Device_profile_power_budget_optimizer (enhancement, priority-p1)

### Security
- none

### Kernel
- none

### Good First Task
- none

### Other
- none

## Component Activity Heatmap

Recent commit touches in `weekly` window (higher means more active recently):

- kernel: 68
- userland: 131
- packages: 47
- docs: 185
- workflows: 25
- tests: 128
- tools: 1
- platform: 1
- scripts: 84
- other: 17

Open issue pressure by component signal:

- security: 4
- kernel: 1
- packages: 0
- docs: 0
- other: 2

## Recent Engineering Changes

- `fcdecfb` (2026-04-11): feat_secure_time_signature_and_permission_approval_flow (#143)
- `8003e8b` (2026-04-11): Add_checkpoint_supervisor_and_sandbox_escape_regression_suite
- `fe651fa` (2026-04-11): Add_key_rotation_enforcer_and_close_issue_131
- `c00e203` (2026-04-11): Remove_accidental_pycache_artifacts
- `ac90dac` (2026-04-11): Implement_permission_center_diff_installer_state_machine_and_delta_apply_simulator
- `010ef42` (2026-04-11): Complete_permission_center_diff_and_installer_state_machine_close_122_129
- `293e480` (2026-04-11): Sync_massive_security_and_kernel_batch_closing_issues_124_125_126_127_128_130
- `68082c9` (2026-04-10): "Canonicalize_secret_snapshot_digest_by_sorted_keys" (#117)
- `bcd8826` (2026-04-10): "Add_capability_audit_summary_counters_endpoint" (#116)
- `bd61a43` (2026-04-10): "Add_atomic_txn_file_checksum_verification" (#115)
- `038b040` (2026-04-10): "Refine_security_policy_wording_for_poc_clarity" (#114)
- `b94b13a` (2026-04-10): "Reduce_auto_docs_workflow_token_scope" (#109)
- `d8464db` (2026-04-10): "Harden_atomic_txn_file_persistence_with_atomic_writes" (#107)
- `9677e10` (2026-04-10): "Add_secret_snapshot_input_size_and_line_guardrails" (#108)
- `807ed28` (2026-04-09): "Harden_github_workflows_for_node24_actions_runtime"
