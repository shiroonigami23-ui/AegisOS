# EXPLAIN

Auto-updated project explainer for contributors.
Last generated: 2026-04-09 18:19:16Z

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
- none

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

- kernel: 62
- userland: 119
- packages: 42
- docs: 172
- workflows: 17
- tests: 85
- tools: 1
- platform: 1
- scripts: 48
- other: 14

Open issue pressure by component signal:

- security: 0
- kernel: 0
- packages: 0
- docs: 0
- other: 0

## Recent Engineering Changes

- `098345b` (2026-04-09): "Fix_auto_docs_protected_branch_flow_and_clang_runner_exec"
- `baf00b4` (2026-04-06): "Harden_secret_snapshot_schema_inventory_and_txn_resume_invariants"
- `deb0b99` (2026-04-06): "Harden_secret_snapshot_restore_duplicate_key_guard"
- `0ba96fb` (2026-04-06): "Add_secret_snapshot_digest_verification_and_txn_json_resume"
- `c03bf00` (2026-04-06): "Add_redacted_secret_inventory_fingerprint_endpoint"
- `3ed3c40` (2026-04-06): "Add_secret_snapshot_restore_and_timestamp_metadata"
- `8b1eba4` (2026-04-06): "Harden_sandbox_policy_json_parser_with_field_tolerant_decode"
- `94d9e9f` (2026-04-06): "Enhance_profile_advisor_with_manifest_package_preview"
- `fbf3288` (2026-04-06): "Fix_permission_center_summary_to_use_policy_gates"
- `b2f59bc` (2026-04-06): "Add_permission_center_policy_summary_endpoint_and_profile_tuning_advisor"
- `26ea167` (2026-04-06): "Add_atomic_update_transaction_state_machine_skeleton"
- `f591d9a` (2026-04-06): "Add_repository_index_trust_policy_validator_and_tests"
- `b603c7e` (2026-04-05): "Add_policy_evaluation_trace_summary_counters_and_json"
- `7345405` (2026-04-05): "Add_secrets_key_storage_service_skeleton"
- `e252ca8` (2026-04-05): "Add_ipc_payload_guard_helper_for_max_frame_enforcement"
