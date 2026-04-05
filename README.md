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

## Current Status

This repository contains:

- Product and architecture blueprint.
- CI workflows and contribution templates.
- Package metadata scaffold for core OS components.
- Initial compilable kernel simulation target for pipeline validation.

## Feature Strategy

- Secure by default (inspired by iOS trust chain and app isolation).
- Lightweight and configurable (Linux-style modularity and control).
- Compatibility-forward (Windows-like pragmatic app strategy).
- Polished user flow (macOS-style consistency and efficiency).
- Hardware profile flexibility (Android-like device breadth).

## Automation

- [`Auto Docs workflow`](.github/workflows/auto-docs.yml) updates `EXPLAIN.md` and `CHANGELOG.md`.
- Recursion protection is enabled: updates to these markdown files are ignored by workflow triggers.
- [`Package Validation workflow`](.github/workflows/packages.yml) enforces package/profile manifest integrity.
- [`Clang Matrix workflow`](.github/workflows/clang-tests.yml) compiles/tests core modules across C standard variants.
  - includes ASAN/UBSAN sanitizer jobs for memory and undefined behavior checks.

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
