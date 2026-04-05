# packages

Package metadata for AegisOS base components.

- `core/` fundamental base-system package definitions.
- `profiles/` install bundles for desktop/server/minimal variants.

Core package groups:

- Kernel and scheduling: `aegis-kernel`, `aegis-scheduler`
- Security stack: `aegis-security-core`, `aegis-sandbox-engine`
- System services: `aegis-userland-base`, `aegis-update-service`
- UX and dev: `aegis-desktop-shell`, `aegis-developer-sdk`

Profile targets:

- `minimal`: lowest-resource install base.
- `desktop`: default end-user profile.
- `developer`: desktop plus SDK bundle.
- `server`: hardened non-desktop profile.

Validation command:

- `python scripts/validate_packages.py`
  - also exports graph files:
    - `packages/dependency-graph.json`
    - `packages/dependency-graph.dot`

Graph rendering (Graphviz):

- Regenerate graph artifacts first:
  - `python scripts/validate_packages.py`
- Render PNG from DOT:
  - Linux/macOS: `dot -Tpng packages/dependency-graph.dot -o packages/dependency-graph.png`
  - Windows (PowerShell/cmd): `dot -Tpng packages\\dependency-graph.dot -o packages\\dependency-graph.png`
- Render SVG (preferred for docs/PRs):
  - `dot -Tsvg packages/dependency-graph.dot -o packages/dependency-graph.svg`
- Quick sanity check:
  - open the image and verify expected nodes like `aegis-kernel`, `aegis-security-core`, and `aegis-update-service`.

Manifest note:

- `schema_version: 1` is required in each core/profile manifest.
- signature placeholders are currently required in each manifest:
  - `signature_format: placeholder-v1`
  - `signature_key_id: aegis-placeholder-*`
  - `signature_digest: sha256:<64-hex-placeholder>`
  - `signature_value: UNSIGNED_PLACEHOLDER`
