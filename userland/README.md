# userland

Core userspace services, shell tools, and runtime components live here.

## Current Modules

- `capability`: capability validation plus lifecycle operations (issue, revoke, access check).
  - includes token expiry (TTL) and rotation APIs.
  - includes in-memory audit event pipeline for allow/deny/issue/rotate/revoke.
  - rotation events persist actor identity (`actor_id`, `actor_source`, `actor_label`) and `reason` metadata.
  - includes actor registry (`register`, `lookup`, `revoke`) and identity lifecycle enforcement hooks.
  - rotate/revoke identity paths now require active non-revoked actor registry entries.
  - includes actor registry snapshot/restore APIs for persistence across reboot/restart boundaries.
  - includes in-memory secret key storage skeleton (`put`, `put_at`, `get`, `metadata_get`, `delete`, `list_json`) for key-service evolution.
  - includes secret snapshot export/restore format for reboot continuity with `created_at`/`updated_at` metadata timestamps.
  - snapshot export includes deterministic digest header; restore verifies digest and enforces strict `schema_version=1` header.
  - snapshot restore enforces input-size, line-count, and per-record length guardrails to fail closed on malformed oversized payloads.
  - includes redacted secret inventory JSON endpoint with deterministic `fingerprint64` and sorted key order for stable drift checks.
  - includes audit export API for JSON/CSV snapshots (latest ring window), pagination cursors, and sink chunk naming.
  - includes audit summary counters endpoint (`snapshot` + JSON) for issue/rotate/revoke/allow/deny distribution visibility.
  - includes timestamp-based audit cursor seek helper for faster export triage in large rings.
  - includes audit sink retention planning helpers for chunk rotation/pruning guidance.
- `sandbox_policy`: policy schema validation for filesystem/network/device permissions.
  - includes JSON serialization/deserialization helpers for distribution and storage.
  - deserializer now supports field-order-tolerant JSON parsing with numeric type/range guards.
  - includes `schema_version` and `policy_revision` fields for versioned policy rollouts.
  - includes legacy JSON migration adapter with structured migration report output.
  - includes permission-center summary JSON endpoint for settings UX visibility of allow/deny actions.
- `sandbox_engine`: action-level enforcement using policy gates + capability tokens.
  - includes path-level filesystem scopes (`deny`, `read-only`, `read-write`) with deny override behavior.
  - supports simple wildcard patterns (`*`) in filesystem scope rules.
  - wildcard rules are validated (`/`-rooted, no `..`, no `**`, wildcard must be a full segment).
  - includes wildcard lint/compile diagnostics API for operator feedback on invalid patterns.
  - includes network scopes (host/port/protocol rules with explicit allow/deny).
  - network rule precedence is deterministic: most specific match wins; tie -> deny.
  - includes optional network precedence debug trace output for diagnostics.
  - includes machine-readable JSON network trace output for tooling integrations.
  - JSON trace includes `trace_schema_version` and `trace_format_version` for consumer stability.
  - JSON trace string fields are escaped for quotes/backslashes/control chars.
  - includes optional DNS pinning guard (`host -> pinned IPv4`) for rebinding defense.
  - DNS pinning guard now supports pinned IPv6 literals for dual-stack protection.
  - supports strict dual-stack mode requiring both IPv4 and IPv6 resolutions when both are pinned.
  - network trace JSON includes DNS dual-stack evidence (`ipv4/ipv6 presence`, `pin families`, strict gate pass/block).
  - includes symlink mapping resolution before filesystem scope checks.
  - supports pluggable filesystem resolver backend hook for real metadata/symlink lookup integration.
  - supports policy hot reload with validation and safe replacement semantics.
  - hot reload enforces monotonic `policy_revision` to block stale policy rollback.
  - includes policy-evaluation trace summary counters and JSON endpoint for allow/deny cause aggregation.
