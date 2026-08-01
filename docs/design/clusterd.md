# clusterd design (M4: issues #17-#20 input)

Status: design v0.1 (2026-08-01). Inputs: ADR-001 D2 (steward holds scoped
clusterd credentials; clusterd wraps clusterctl wraps incus), contracts #4
(idempotency, confirmations, audit events, error classes), threat model
B6/B7 (stolen bearer, clusterd compromise).

## 1. Shape

`clusterd` is a thin HTTP service on the host, bound ONLY to the anyVPN
interface (10.10.20.69:8785) — never public. systemd unit, runs as a
dedicated unprivileged user `clusterd` with sudoers scoped EXACTLY to
`/home/debian/Projects/daimon-cluster/scripts/clusterctl *` (or its
installed path). No business logic beyond: auth, validation, audit,
delegation. Every mutating endpoint maps 1:1 to a clusterctl command; read
endpoints map to `clusterctl list/status --json`.

```
steward agent (Hermes plugin) ──┐
                                ├─ HTTPS(anyVPN) ─> clusterd ──exec──> clusterctl ──> incus
dashboard (M7, later) ─────────┘                     │
                                                     └─ append-only audit log (hash-chained, #19)
```

## 2. API surface (v1)

| Endpoint | clusterctl | Scope |
|----------|-----------|-------|
| GET /v1/instances | list --json | fleet:read |
| GET /v1/instances/{name} | status --json | fleet:read |
| POST /v1/instances | provision prepare | provision:write |
| POST /v1/instances/{name}/confirmations | confirm (any op) | per-op scope + token |
| POST /v1/instances/{name}/stop /start /restart | stop/start/restart | lifecycle:write |
| POST /v1/instances/{name}/snapshot | snapshot (M3) | backup:write |
| POST /v1/instances/{name}/updates | update prepare (M5) | update:write |
| DELETE /v1/instances/{name} | destroy (archive-first, #8 §3) | destroy:write + token |
| GET /v1/audit?since= | audit tail | audit:read |

All mutations: idempotency-key header required; two-step prepare/confirm
for anything destructive per contracts #4; responses are the clusterctl
JSON verbatim plus `{audit_id}`.

## 3. Auth (issue #18) — anyVPN + scoped bearer, replay-resistant

- Bearer tokens: ed25519-signed JWT-like macaroons, issued by the cluster
  owner offline (no OIDC until product phase — ADR D4). Claims: sub
  (identity), scopes[], exp (short), jti.
- Replay resistance: jti cache with exp horizon + strict clock check +
  per-mutation idempotency-key uniqueness (#18 acceptance). TLS optional
  inside anyVPN (the mesh is already encrypted); add TLS when any
  non-mesh path appears.
- Confirmation tokens (#4 §5) are single-use and bound to one operation
  fingerprint; a stop-confirmation never authorizes destroy.

## 4. Audit (issue #19)

- Append-only JSONL, one event per accepted request AND per rejected
  request (denials are auditable too — threat model).
- Hash chain: event.prev_sha256 links the previous event; daily anchor
  (sha256 of the day's last event) posted to public-agents — tampering
  after anchorage is publicly detectable. This is the cheap, honest
  tamper-evidence for a single-host v1.
- Reconciliation: a nightly job diffs `clusterctl list --json` against the
  audit trail's declared mutations; drift (container changed without an
  audit event) raises an alert event and a public-agents notice (#19).

## 5. Deploy & harden (issue #20)

- systemd unit: clusterd.service (after incus, zerotier; restart on-failure;
  NoNewPrivileges, ProtectSystem=strict except state dir).
- Contract tests: the same pytest suite style as clusterctl — fake adapter
  for unit, live fixture hitting the real service on anyVPN.
- Reboot test: part of the host restart drill checklist (add one row:
  `curl http://10.10.20.69:8785/v1/instances` returns JSON after reboot).
- Fail-closed: if the audit log can't append, mutations refuse (reads
  still serve) — an unaudited control plane is worse than a paused one.

## 6. Explicit non-goals (v1)

- No dashboard (M7). No multi-host (fleet phase). No OIDC (product).
- No agent-specific logic: clusterd knows containers and manifests, not
  Hermes, HMK, or tribe semantics beyond health probes.
