# userland

Core userspace services, shell tools, and runtime components live here.

## Current Modules

- `capability`: capability validation plus lifecycle operations (issue, revoke, access check).
  - includes token expiry (TTL) and rotation APIs.
  - includes in-memory audit event pipeline for allow/deny/issue/rotate/revoke.
  - rotation events persist `actor_id` and `reason` metadata for incident traceability.
  - includes audit export API for JSON/CSV snapshots (latest ring window).
- `sandbox_policy`: policy schema validation for filesystem/network/device permissions.
  - includes JSON serialization/deserialization helpers for distribution and storage.
  - includes `schema_version` and `policy_revision` fields for versioned policy rollouts.
- `sandbox_engine`: action-level enforcement using policy gates + capability tokens.
  - includes path-level filesystem scopes (`deny`, `read-only`, `read-write`) with deny override behavior.
  - supports simple wildcard patterns (`*`) in filesystem scope rules.
  - includes network scopes (host/port/protocol rules with explicit allow/deny).
  - network rule precedence is deterministic: most specific match wins; tie -> deny.
  - includes optional DNS pinning guard (`host -> pinned IPv4`) for rebinding defense.
  - includes symlink mapping resolution before filesystem scope checks.
  - supports policy hot reload with validation and safe replacement semantics.
  - hot reload enforces monotonic `policy_revision` to block stale policy rollback.
