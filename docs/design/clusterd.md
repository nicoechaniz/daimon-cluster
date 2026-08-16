# clusterd design (M4: issues #17-#20 input)

Status: pre-release RC design (2026-08-16). Inputs: ADR-001 D2 (steward holds scoped
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
| POST /v1/instances/{name}/stop /start /restart | stop/start/restart | lifecycle:write |
| POST /v1/instances/{name}/snapshot | snapshot (M3) | backup:write |
| POST /v1/instances/{name}/restore | restore placeholder | restore:write |
| POST /v1/instances/{name}/destroy | destroy placeholder | destroy:write + confirmation |
| GET /v1/audit | audit tail | fleet:read |

All mutations: idempotency-key header required; two-step prepare/confirm
for anything destructive per contracts #4; responses are the clusterctl
JSON verbatim plus `{audit_id}`.

## 3. Auth and human authority

- Bearer tokens are opaque random values stored only as SHA-256 digests. A
  token receives exact operation scopes. There is no generic `mutate` scope:
  `lifecycle:write` cannot snapshot, restore, destroy or confirm a dashboard
  mutation, and `fleet:read` cannot mutate.
- Owner-scoped tokens fail closed unless the target spec has a non-empty
  `created_by` equal to the token owner. Missing or malformed ownership never
  widens access.
- `X-Attended` and similar caller assertions carry no authority. A
  `steward@*` mutation without a cryptographic approval returns a persisted
  `clusterd-human-approval-intent/v1` and performs no adapter call.
- A separate process/key holder signs that exact intent. It binds token id,
  actor, route, method, target, request body hash, current target-spec hash,
  nonce and expiry. The server stores public authority keys only and consumes
  each approval exactly once under a lock. Replay, substitution, stale target,
  expiry and revocation fail before effects.
- Destructive confirmation remains an additional single-use gate; it never
  substitutes for the separate human approval required by an unattended
  steward.

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

- No OIDC. No claim that bearer auth or human approval alone provides
  cross-host resource fencing; shared embodiment admission is a separate
  authority.
- No agent-specific logic: clusterd knows containers and manifests, not
  Hermes, HMK, or tribe semantics beyond health probes.
