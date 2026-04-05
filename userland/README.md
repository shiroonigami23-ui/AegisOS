# userland

Core userspace services, shell tools, and runtime components live here.

## Current Modules

- `capability`: capability validation plus lifecycle operations (issue, revoke, access check).
- `sandbox_policy`: policy schema validation for filesystem/network/device permissions.
- `sandbox_engine`: action-level enforcement using policy gates + capability tokens.
  - includes path-level filesystem scopes (`deny`, `read-only`, `read-write`) with deny override behavior.
  - includes network scopes (host/port/protocol rules with explicit allow/deny).
  - includes symlink mapping resolution before filesystem scope checks.
