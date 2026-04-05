# Implementation Plan (v0)

## Epic 1: Boot + Kernel Base

- Process model and scheduler skeleton.
- Virtual memory abstraction.
- IPC channel contract and message format.

## Epic 2: Security Core

- Capability token lifecycle.
- Sandbox policy schema and evaluator.
- Secrets and key storage service.

## Epic 3: Package + Update System

- Package format and metadata validation.
- Atomic update transaction engine.
- Signed repository index and trust policy.

## Epic 4: UX + Device Profiles

- Desktop compositor prototype.
- Settings and permission center.
- Profile tuning for low-resource hardware.

## Epic 5: Compatibility

- Runtime boundary model.
- App ABI gateway and syscall mediation.
- Observability for compatibility failures.
