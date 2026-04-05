# EXPLAIN

Auto-updated project explainer for contributors.
Last generated: 2026-04-05 13:14:30Z

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
- #70 Actor_registry_persistent_backing_store (priority-p1, security)
- #40 Apply_branch_protection_profile_on_main (priority-p1)

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

- kernel: 47
- userland: 92
- packages: 39
- docs: 169
- workflows: 15
- tests: 63
- tools: 1
- platform: 1
- scripts: 33
- other: 14

Open issue pressure by component signal:

- security: 1
- kernel: 0
- packages: 0
- docs: 0
- other: 1

## Recent Engineering Changes

- `5707523` (2026-04-05): "Add_actor_registry_snapshot_and_restore_persistence_api"
- `b49f9a3` (2026-04-05): docs: auto-update explain and changelog
- `1091117` (2026-04-05): "Add_cross_platform_toolchain_bootstrap_scripts_for_contributors"
- `5312e24` (2026-04-05): docs: auto-update explain and changelog
- `f8fd4c7` (2026-04-05): "Add_trace_json_property_perf_baseline_and_seed_corpus_tooling"
- `395429a` (2026-04-05): docs: auto-update explain and changelog
- `16a0ad2` (2026-04-05): "Add_filesystem_resolver_backend_hook_for_symlink_resolution"
- `b458e87` (2026-04-05): docs: auto-update explain and changelog
- `3fbc4c2` (2026-04-05): "Add_sanitizer_suppressions_baseline_and_runner"
- `264139e` (2026-04-05): docs: auto-update explain and changelog
- `294a3fe` (2026-04-05): "Add_package_manifest_schema_migration_helper_with_tests"
- `fdc9706` (2026-04-05): docs: auto-update explain and changelog
- `dfb3685` (2026-04-05): "Add_package_profile_to_hardware_compatibility_matrix_docs"
- `de08c6f` (2026-04-05): docs: auto-update explain and changelog
- `15c3fc8` (2026-04-05): "Add_package_signature_placeholder_fields_and_schema_validation"
