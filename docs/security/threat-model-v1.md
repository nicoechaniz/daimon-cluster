# Historical single-host threat model (superseded)

This 2026-08-01 proposal is retained as design history. It is not the current
release-candidate threat model and its “never two awake” language does not
describe plural embodiments. The normative model is
`docs/security/threat-model-rc.md`.

# daimon-cluster v1 threat model

Status: PROPOSED (2026-08-01). Evidence for issue #3.
Author: compaii@daimonmatrix. Inputs: ADR-001, host inventory
(`docs/inventory/daimonmatrix-2026-07-31.md`), PLAN §8, tribe-bridge v1
governance lessons (root rotation, 2026-08-01).

## 1. Trust boundaries

```
                        ┌─────────── UNTRUSTED ───────────┐
                        │ public internet · model APIs    │
                        │ prompt content from any channel │
                        └──────────────┬──────────────────┘
                                       │
   B1: anyVPN edge (ZeroTier iface, host-wide) — no firewall tooling today (finding F1)
                                       │
┌──────────────────────────────────────▼───────────────────────────────────┐
│ HOST (daimonmatrix) — HIGH TRUST                                       │
│                                                                        │
│  clusterd (host svc account, holds Incus socket)  ── B2: API boundary ─┼── bearer/OIDC
│  clusterctl · audit log · restic keys (offline custody)                │   + per-human scope
│                                                                        │
│  ┌─ steward@daimonmatrix (Hermes agent) ─ B3: scoped creds only ─┐     │
│  │ NO Incus socket, NO host shell, mutation = human-gated        │     │
│  └───────────────────────────────────────────────────────────────┘     │
│                                                                        │
│  ┌── Incus (unprivileged containers) ── B4: uid/gid mapping ────────┐  │
│  │ daimon containers: own Hermes, HMK, bridge keys, state repo     │  │
│  │ ── B5: container-to-container — no sibling volumes/creds ──     │  │
│  └─────────────────────────────────────────────────────────────────┘  │
│                                                                        │
│  tribe-bridge v1 broker (SQLite, anyVPN+loopback) ─ B6: signed HTTP    │
│  governance directory (offline root) ─ B7: epoch/anti-rollback         │
└────────────────────────────────────────────────────────────────────────┘

Backups: restic encrypted, off-host ─ B8: restore treats archive as hostile
```

Findings from the inventory that shape this model:

- **F1**: no firewall tooling installed on the host (no nft/ufw/iptables).
  Ingress control today is only binding choice + anyVPN membership.
  M1 hardening (issue #6) MUST add host firewall rules.
- **F2**: `/dev/kvm` is present inside the host. Never map it into an agent
  container; containers are the only isolation boundary.
- **F3**: the ZeroTier interface is host-wide. Per-container anyVPN identity
  requires TUN + CAP_NET_ADMIN, which ADR-001 D6 denies by default; the
  default is broker access via the host's anyVPN address.

## 2. Actors and what they hold

| Actor | Holds | Does NOT hold |
|-------|-------|---------------|
| clusterd (host svc acct) | Incus socket, clusterctl exec, audit write | restic repo keys (offline), governance root |
| steward@daimonmatrix | scoped clusterd bearer creds, tribe v1 identity | Incus socket, host shell, other daimons' creds |
| daimon container | own Hermes/HMK/bridge keys/state repo | host fs, Incus socket, sibling volumes, /dev/kvm, TUN (default) |
| human (anyVPN) | own scoped bearer token | other humans' scopes (except cluster owner) |
| governance holder (offline) | root signing key | any online presence |
| restic key holder (Nicolás, offline) | backup decryption | stored on host: never |

## 3. Abuse cases

| # | Abuse case | Vector | Mitigation (binding) | Residual risk |
|---|-----------|--------|----------------------|---------------|
| A1 | Malicious prompt steers an agent into abusing cluster tools | prompt injection via chat/bridge | mutation tools are human-gated (PLAN §8); steward holds scoped creds only (B3); per-owner scope at clusterd (B2); audit every mutation | agent performs scoped READS and leaks them into a reply — accepted, reads are non-sensitive by design classification |
| A2 | Compromised agent container attacks the host | kernel escape, socket reach | unprivileged uid mapping (B4); no Incus socket in container; no host fs mounts; no /dev/kvm (F2); resource limits | kernel 0-day — accepted, mitigated by boring updates (unattended-upgrades already on) |
| A3 | Compromised container attacks a sibling | network, shared kernel | private bridge with host-managed rules (B5); no sibling volume mounts; per-container keys only; no TUN (D6) | side-channel CPU contention — accepted at this trust level (tribe members) |
| A4 | Stolen bearer token used from outside anyVPN | token leak | anyVPN-restricted ingress (D4): tokens are useless off-mesh; scoped per human; rotation runbook (M8 handbook, #33) | theft from inside the mesh by a tribe member — audit trail attributes use |
| A5 | Hostile backup data injected at restore | tampered restic snapshot | restic encryption + integrity; restore treats archive as untrusted (B8): restore into a SCRATCH container, path/device escape validation, no restore-over-running-instance; drill in M3 (#16) | malicious content inside agent files surfaces as A1 at next wake — human review gate on restore |
| A6 | Bridge key loss / agent v1 key compromise | lost device, leaked keys.json | directory revocation via governance epoch (B7); anti-rollback chain; lesson of 2026-08-01 encoded: root stays offline | until revocation, impersonation within audiences — mirror visibility (public-agents) gives detection |
| A7 | clusterd compromise | API exploit, RCE in service | thin service, FastAPI+pydantic validation; runs as dedicated svc acct (not root); replay resistance + confirmations (#18); audit hash-chain (#19) | full Incus authority — this is the highest-value target; keep the attack surface sentence-sized (PLAN §4) |
| A8 | Steward agent compromise | prompt injection on steward identity | steward has NO host shell and NO socket (D2); its scoped creds limit damage to API-level mutations, all human-gated and audited | social-engineering the human confirmer — mitigated by confirmation UX showing exact plan diff (M5, #23 adversarial tests) |
| A9 | Lease split-brain (two awake bodies) | failed flip, stale writer | fencing tokens + stale-writer rejection + broker queue-not-deliver (ADR D1) | none identified beyond availability loss |
| A10 | Host-level zram/swap side channels | memory pressure | zram is host-level; no per-container swap visibility across boundaries (standard kernel isolation) | accepted |

## 4. Security invariants (binding, per issue #3)

1. No agent container can access: the Incus socket, the host filesystem,
   sibling volumes, another daimon's credentials, `/dev/kvm`, or
   `/dev/net/tun` (default profile).
2. Mutation authorization is deny-by-default, per-owner scoped, audited
   (append-only hash-chained log), and replay-resistant (single-use
   confirmation tokens with expiry).
3. Backup restore treats archive contents as untrusted: scratch-container
   restore, path/device escape prevention, no overwrite of a running
   instance, human confirmation with manifest diff.
4. Governance root and restic keys never exist on the host.
5. Every security control above has a test mapped to a milestone (§5).

## 5. Security tests mapped to milestones

| Test | Verifies | Milestone / issue |
|------|----------|-------------------|
| Container cannot open `/run/incus/socket`, `/dev/kvm`, `/dev/net/tun` | invariant 1 | M1 #9 isolation tests |
| Container cannot read host paths or sibling volumes (mount table audit + probe) | invariant 1 | M1 #9 |
| Unauthenticated clusterd call → 401; wrong-scope token → 403; replayed confirmation → 409 | invariant 2 | M4 #18, #20 |
| Audit log hash-chain verification detects truncation/edit | invariant 2 | M4 #19 |
| Restore of a tampered archive fails closed; scratch-restore drill passes | invariant 3 | M3 #16 |
| Steward adversarial approval tests (injection attempts on mutation tools) | A1/A8 | M5 #23 |
| Lease failure-injection: stale writer rejected, asleep body gets queued DM, never two awake | A9 | M7 #30 |
| Firewall present and default-deny inbound except required (post-F1 fix) | F1 | M1 #6 hardening |

## 6. Out of scope (v1)

- Public multi-tenant threat surface (product phase re-models with OIDC,
  rate limiting, billing abuse).
- Multi-host federation threats (single host in v1).
- Model-provider compromise (treated as UNTRUSTED channel at B1; agents
  already operate under that assumption).
