# userland

Core userspace services, shell tools, and runtime components live here.

## Current Modules

- `capability`: capability validation plus lifecycle operations (issue, revoke, access check).
  - includes token expiry (TTL) and rotation APIs.
  - includes in-memory audit event pipeline for allow/deny/issue/rotate/revoke.
  - rotation events persist actor identity (`actor_id`, `actor_source`, `actor_label`) and `reason` metadata.
  - includes audit export API for JSON/CSV snapshots (latest ring window), pagination cursors, and sink chunk naming.
- `sandbox_policy`: policy schema validation for filesystem/network/device permissions.
  - includes JSON serialization/deserialization helpers for distribution and storage.
  - includes `schema_version` and `policy_revision` fields for versioned policy rollouts.
  - includes legacy JSON migration adapter with structured migration report output.
- `sandbox_engine`: action-level enforcement using policy gates + capability tokens.
  - includes path-level filesystem scopes (`deny`, `read-only`, `read-write`) with deny override behavior.
  - supports simple wildcard patterns (`*`) in filesystem scope rules.
  - wildcard rules are validated (`/`-rooted, no `..`, no `**`, wildcard must be a full segment).
  - includes wildcard lint/compile diagnostics API for operator feedback on invalid patterns.
  - includes network scopes (host/port/protocol rules with explicit allow/deny).
  - network rule precedence is deterministic: most specific match wins; tie -> deny.
  - includes optional network precedence debug trace output for diagnostics.
  - includes machine-readable JSON network trace output for tooling integrations.
  - includes optional DNS pinning guard (`host -> pinned IPv4`) for rebinding defense.
  - DNS pinning guard now supports pinned IPv6 literals for dual-stack protection.
  - supports strict dual-stack mode requiring both IPv4 and IPv6 resolutions when both are pinned.
  - network trace JSON includes DNS dual-stack evidence (`ipv4/ipv6 presence`, `pin families`, strict gate pass/block).
  - includes symlink mapping resolution before filesystem scope checks.
  - supports policy hot reload with validation and safe replacement semantics.
  - hot reload enforces monotonic `policy_revision` to block stale policy rollback.
