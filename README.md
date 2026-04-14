# AegisOS

Secure like iOS, lightweight and customizable like Linux, compatible like Windows, polished like macOS, and hardware-flexible like Android.

[![CI](https://github.com/shiroonigami23-ui/AegisOS/actions/workflows/ci.yml/badge.svg)](https://github.com/shiroonigami23-ui/AegisOS/actions/workflows/ci.yml)
[![Docs](https://github.com/shiroonigami23-ui/AegisOS/actions/workflows/docs.yml/badge.svg)](https://github.com/shiroonigami23-ui/AegisOS/actions/workflows/docs.yml)

## Mission

Build a modern, privacy-first operating system that combines the strongest qualities of existing ecosystems into one cohesive platform.

## Core Goals

- Strong security-by-default and verified software distribution.
- Fast, lightweight runtime that works well on both modern and older hardware.
- Deep customization without sacrificing stability.
- Strong app compatibility strategy for users and developers.
- Clean, premium user experience with predictable behavior.

## Repo Layout

- `kernel/` core kernel direction and interfaces.
- `userland/` shell, services, package/runtime utilities.
- `platform/` device abstraction and hardware support layers.
- `tools/` developer tools, SDK/CLI direction.
- `packages/` package definitions and core bundle manifests.
- `build/` build system and release engineering notes.
- `scripts/` helper scripts for local setup and CI.
- `docs/` product, architecture, security, and roadmap docs.
- `.github/` workflows, templates, and collaboration automation.

## Quick Start

1. Read [`docs/VISION.md`](docs/VISION.md).
2. Read [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
3. Read [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md).
4. Follow milestone plan in [`docs/ROADMAP.md`](docs/ROADMAP.md).
5. Use execution backlog in [`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md).
6. Read contributor explainer in [`EXPLAIN.md`](EXPLAIN.md).
7. Read branch governance profile in [`docs/BRANCH_PROTECTION.md`](docs/BRANCH_PROTECTION.md).
8. Follow new contributor checklist in [`docs/ONBOARDING.md`](docs/ONBOARDING.md).
9. Run bootstrap validation: `python scripts/onboarding_check.py`.
10. Check hardware/profile mapping in [`docs/PROFILE_COMPATIBILITY.md`](docs/PROFILE_COMPATIBILITY.md).
11. Use platform bootstrap scripts in [`scripts/README.md`](scripts/README.md) for first-time setup.

## Current Status

This repository contains:

- Product and architecture blueprint.
- CI workflows and contribution templates.
- Package metadata scaffold for core OS components.
- Initial compilable kernel simulation target for pipeline validation.
- Scheduler admission control primitives with per-priority limits, drop counters, and JSON snapshots.
- Namespace isolation simulator with local/global PID translation and visibility checks.
- Atomic update rollback-index monotonic guard store with tamper-checked persistence.
- Syscall capability gate matrix with decision-cache fast path, enforcement counters, and JSON snapshot.
- IPC channel quota/backpressure simulator with inflight accounting and drop metrics.
- Memory zone accounting with reclaim hooks and low-memory deny telemetry.
- Update release channel pinning policy with downgrade rejection guardrails.
- Compatibility runtime syscall allowlist scaffold with violation log export.
- Delta update manifest schema validation (payload digest, base version, and fallback digest).
- Telemetry privacy redaction engine for logs, metrics, and trace exports.
- Device-profile boot budget enforcer with low-battery/thermal optimizer recommendations for CI gates.
- Service restart budget supervisor with health-probe and metrics-export JSON endpoints for ops dashboards.
- Kernel checkpoint journal persistence + replay path for crash-recovery boot restore.
- Scheduler hot-path optimization via live priority/runnable-credit counters for faster dispatch bookkeeping.
- Adaptive scheduler quantum autotuner for improved latency vs switch-overhead balance under load.
- Scheduler admission/ready bitmaps + turbo candidate cache reuse for lower dispatch computation overhead.
- Permission center policy diff endpoint plus policy-change audit exports (JSON/CSV).
- Installer secure bootstrap state machine with recovery and attestation hook gates.

## Feature Strategy

- Secure by default (inspired by iOS trust chain and app isolation).
- Lightweight and configurable (Linux-style modularity and control).
- Compatibility-forward (Windows-like pragmatic app strategy).
- Polished user flow (macOS-style consistency and efficiency).
- Hardware profile flexibility (Android-like device breadth).

## Automation

- [`Auto Docs workflow`](.github/workflows/auto-docs.yml) updates `EXPLAIN.md` and `CHANGELOG.md`.
  - supports configurable heatmap trend windows via `scripts/update_project_docs.py --heatmap-window weekly|monthly|custom --heatmap-days N`.
- Recursion protection is enabled: updates to these markdown files are ignored by workflow triggers.
- [`Package Validation workflow`](.github/workflows/packages.yml) enforces package/profile manifest integrity.
- [`Clang Matrix workflow`](.github/workflows/clang-tests.yml) compiles/tests core modules across C standard variants.
  - includes ASAN/UBSAN sanitizer jobs for memory and undefined behavior checks.
  - sanitizer suppression baseline and policy docs: [`docs/SANITIZERS.md`](docs/SANITIZERS.md).
  - includes trace JSON property smoke profiling for regression triage: [`docs/TRACE_JSON_PROPERTY.md`](docs/TRACE_JSON_PROPERTY.md).

## Collaboration

- Contribution guide: [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Collaborator roles: [`COLLABORATORS.md`](COLLABORATORS.md)
- Security policy: [`SECURITY.md`](SECURITY.md)
- Code ownership: [`.github/CODEOWNERS`](.github/CODEOWNERS)
- Project board: [AegisOS_Roadmap](https://github.com/users/shiroonigami23-ui/projects/2)

## Project Board

The GitHub `Projects` tab is the execution board for roadmap tracking.

- New/reopened issues are auto-added with `Todo` status.
- Closed issues are auto-moved to `Done`.
- Use it as the single queue for priorities, owners, and sprint slices.
