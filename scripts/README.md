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
- `atomic_update_txn.py`: atomic update transaction state machine skeleton (`begin/stage/commit/rollback/reset`) with JSON/file persistence helpers (`summary_json`, `load_from_json`, `save_to_file`, `load_from_file`) and state invariant checks.
- `low_resource_profile_advisor.py`: recommends package profile by CPU/RAM class with rationale, tuning advice, and profile-manifest package preview JSON output.
