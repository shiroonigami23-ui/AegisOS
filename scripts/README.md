# scripts

Helper scripts for local development and automation live here.

- `bootstrap.bat`: Windows cmd bootstrap (toolchain check + onboarding validation).
- `bootstrap.ps1`: Windows PowerShell bootstrap (toolchain check + onboarding validation).
- `bootstrap.sh`: Linux/macOS bootstrap (toolchain check + onboarding validation).
- `migrate_policies_batch.py`: batch-migrates legacy sandbox policy JSON files, supports `--dry-run`, per-file `--diff-preview`, include/exclude filters, and shard execution mode for large rollouts.
- `migrate_package_manifests.py`: migrates legacy package/profile YAML manifests to current schema + signature placeholders.
- `generate_audit_retention_manifest.py`: emits machine-readable keep/prune chunk manifest and supports `--prev-manifest-json` incremental diff output for retention automation.
- `run_clang_suite.py`: shared compile/test runner for core C targets.
- `run_sanitizer_suite.py`: ASAN/UBSAN test runner with suppression baseline.
- `profile_trace_json_property.py`: seed-corpus replay and runtime profile utility for trace JSON property tests.
- `validate_repo_index.py`: validates repository index trust policy, signature metadata, and manifest alignment.
- `atomic_update_txn.py`: atomic update transaction state machine skeleton (`begin/stage/commit/rollback/reset`) with JSON/file persistence helpers (`summary_json`, `load_from_json`, `save_to_file`, `load_from_file`), file checksum verification, and state invariant checks.
- `low_resource_profile_advisor.py`: recommends package profile by CPU/RAM class with rationale, tuning advice, and profile-manifest package preview JSON output.
- `compat_runtime_allowlist.py`: compatibility runtime syscall allowlist scaffold with per-runtime counters and violation log export.
- `telemetry_redaction_engine.py`: redacts sensitive fields from logs/metrics/traces and emits redaction summary telemetry.
- `device_profile_boot_budget_enforcer.py`: enforces per-profile cold/warm boot budgets and emits pass/fail severity reports.
- `installer_bootstrap_state_machine.py`: installer bootstrap state machine with recovery paths and attestation hook gating.
- `package_repo_delta_apply_simulator.py`: simulates delta apply with digest validation and full-package fallback path.
- `security_key_rotation_schedule_enforcer.py`: evaluates key age against rotation policy and emits warning/critical reports.
- `service_restart_budget_supervisor.py`: enforces per-service restart budgets with sliding windows, backoff, escalation, and incident reports.
- `package_signature_verifier.py`: verifies HMAC-SHA256 package signatures from repository index entries using keyring input.
- `sandbox_escape_fuzz_corpus.py`: generates deterministic path+DNS sandbox-escape fuzz corpus from seed sets with reason-coded expected blocks.
