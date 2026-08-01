# clusterctl CLI reference (v0.1.0)

`clusterctl` is the sole business-logic entry point for daimon-cluster
fleet state (issue #10). v0.1.0 is **read-only**: no command writes to
the state dir or mutates incus.

Config: `configs/clusterctl.yaml` (schema `clusterctl-config/v1`):
`host_id`, `incus_project`, `managed_prefix`, `profile`, `state_dir`
(default `/var/lib/daimon-cluster`). Global flags: `--config <path>`,
`--state-dir <path>` (override; used by tests).

Declared state: `<state_dir>/instances/<name>.yaml` (schema
`instance-spec/v1`: `name`, `species`, `image_version`,
`budgets {cpu, memory_mib, disk_gib}`, `created_ms`, `created_by`).
Actual state: incus instances using the configured profile.

Classification: `running` · `stopped` · `missing` (declared, absent in
incus) · `undeclared` (in incus, not declared) · `drifted` (declared
budgets or image differ from actual incus config).

## Commands

### `clusterctl list [--json]`

Plain aligned table (default) or a JSON array of `instance-status/v1`
records.

```
NAME    SPECIES  STATE       IMAGE_VERSION  CPU  MEM_MIB  DISK_GIB  UPTIME_S
iso-a   unknown  undeclared  debian-trixie-amd64-default-20260731_05:24  1  1536  8  3600
```

### `clusterctl status <name> [--json]`

Single instance status. Exit 3 when the name is neither declared nor
present in incus. When drifted, the record includes a `drift` array of
`{field, declared, actual}` entries.

### `clusterctl config-show [--json]`

Resolved configuration (YAML by default, JSON with `--json`).

## JSON schema: `instance-status/v1`

Example (`clusterctl status iso-a --json`):

```json
{
  "schema": "instance-status/v1",
  "name": "iso-a",
  "species": "unknown",
  "host": "daimonmatrix",
  "state": "undeclared",
  "lease_state": "unknown",
  "image_version": "debian-trixie-amd64-default-20260731_05:24",
  "budgets": {
    "cpu": 1,
    "memory_mib": 1536,
    "disk_gib": 8
  },
  "durable_bytes": null,
  "hmk_integrity": "unknown",
  "uptime_s": 3600,
  "last_audit_event": null
}
```

Notes for v0.1.0: `lease_state` and `hmk_integrity` are pinned to
`"unknown"`; `durable_bytes` and `last_audit_event` are `null` until the
audit log (issue #19) lands. Consumers must ignore unknown fields.

Drifted example (fragment):

```json
{
  "state": "drifted",
  "drift": [
    {"field": "cpu", "declared": 2, "actual": 1},
    {"field": "image_version", "declared": "tribe-base-2026-08-01.1", "actual": "debian-trixie-amd64-default-20260731_05:24"}
  ]
}
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | success |
| 2 | usage error (argparse) |
| 3 | not found (`status` of an unknown name) |
| 6 | conflict (reserved; unused at v0.1.0) |
| 10 | internal error (config/spec/incus failure, bug) |

## Provision (issue #12; design: `docs/design/provisioning-flow.md` §2)

```
clusterctl provision prepare <name> --species <s> \
    --requested-by <human> --sponsor <sponsor> \
    [--seed-manifest <path>] --idempotency-key <uuid> [--json]
clusterctl provision confirm --token <token> [--json]
```

`prepare` creates the container + durable home volume (`<name>-home`),
generates the tribe v1 ed25519 identity **inside** the container (private
material never leaves the volume; host sees only pubkey + SHA256
fingerprint), optionally stages a `seed-manifest/v1` seed, writes the
spec with state `provisioned-pending-activation`, and emits a single-use
confirmation token at `<state_dir>/confirmations/<token>.json`. It then
HALTs — nothing is registered.

Token file shape (`confirmation/v1`):

```json
{
  "schema": "confirmation/v1",
  "token": "6f4b2f2c-0c6a-4b0e-9f6d-9f2f3b1f7a0a",
  "operation": "provision-activate",
  "target": "daimon-x",
  "created_ms": 1785600000000,
  "ttl_s": 900,
  "used": false,
  "artifacts": {
    "directory_entry": {
      "identity": "daimon-x@daimonmatrix",
      "pubkey": "ssh-ed25519 AAAA... daimon-x@daimonmatrix",
      "fingerprint": "SHA256:abc...",
      "host_broker": "10.10.20.69:8685"
    }
  }
}
```

`confirm` consumes the token (exit 3 unknown, 6 expired, replay of a used
token is an idempotent exit-0 "already confirmed"), flips the spec to
`active-pending-directory`, and prints the `directory_entry` artifact —
the actual directory activation is **governance's** act, not clusterctl's.

Admission failures exit 6 (duplicate name, sponsor == requester, seed
checksum mismatch — all before any effect). Any post-creation failure
triggers full reversal (stop+delete container, delete volume, spec marked
`creation-failed`) and exits 10.

## Invocation

`scripts/clusterctl` is a thin wrapper that execs the repo venv
(`repo/.venv/bin/python -m clusterctl.cli "$@"`). Runtime deps: Python
3.13 stdlib + PyYAML only.
