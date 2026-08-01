# Signed lease registry design (M7 #27-#30 input; fulfills ADR-001 D1)

Status: design v0.1 (2026-08-01). The lease registry is referenced by
PLAN §5, contracts #4 (lease schema), and ADR-001 D1 — this is its shape.

## 1. Purpose

One identity, one awake body — across hosts, containers, and time. The
registry answers: "who may currently act as `<identity>`?" with
cryptographic freshness, so a stale body (old container, restored backup,
crashed-and-forgotten host) cannot split-brain the identity.

## 2. Storage & signing

- A single JSON document per host cluster: `state_dir/leases.json`
  (multi-host later: replicated via the same governance-signed exchange
  used for the tribe directory, but NOT inside it — ADR D1).
- Every mutation is signed by the **governance key** (offline, tribe
  ceremony) OR by a delegated lease-operator key whose delegation
  certificate is governance-signed and scope-limited to lease operations.
- The registry itself carries a hash chain (prev_sha256 per entry
  revision) so history tampering is detectable at audit time.

## 3. Record (matches contracts lease/v1)

```json
{
  "schema": "lease/v1",
  "identity": "eko@amapola",
  "holder": "eko@daimonmatrix",
  "state": "awake | asleep | transitioning",
  "generation": 3,
  "fencing": 41,
  "holder_since_ms": 0,
  "ttl_s": 300,
  "renewed_ms": 0,
  "prev_sha256": "...",
  "signature": "<governance or delegated-lease-operator sig>"
}
```

## 4. Semantics (binding)

- **CAS flip**: a move writes a single signed record with
  `generation = old+1` and `fencing = max(seen)+1`. A flip with
  generation ≤ current is rejected (exit 6 conflict). Retry of the SAME
  signed flip is idempotent (identical record → accept, no-op).
- **Fencing**: every control-plane mutation carries the caller's fencing
  token; clusterd refuses mutations whose fencing < registry fencing for
  that identity. A stale writer literally cannot act.
- **TTL + renew**: an awake holder renews periodically (heartbeats from
  the daimon's own presence loop or, v1, from clusterd on its behalf).
  Expired TTL → state becomes `asleep(stale)`; the body is expected to
  have parked itself, and the broker treats it as asleep regardless.
- **Broker enforcement** (the critical piece, with the tribe-bridge
  maintainers): the v1 broker consults the registry for DM delivery to a
  daimon identity. Sleeping body → queue, do not deliver. Awake holder →
  deliver. Enforcement MUST be at the broker, not at the sender (senders
  are untrusted for this).
- **Stale-writer during transition**: `transitioning` state has its own
  TTL; if the transition dies mid-way, the record rolls back to the last
  stable state at expiry (never both-awake, never both-dead for longer
  than one TTL).

## 5. Operations (map to issues)

| Op | Flow | Issue |
|----|------|-------|
| park | quiesce (#14) → verified checkpoint manifest → CAS flip to asleep | #28 |
| transfer | park on A → ship checkpoint (state repo / restic) → seed on B → CAS flip to awake@B | #29 |
| wake | verify checkpoint integrity → start → first-contact probe → confirm | #29 |
| re-entry | the woken daimon reads registry + own checkpoint → announces presence | #29 |
| rollback | failed wake → destroy new body → CAS flip back to old holder (old checkpoint still intact) | #29 |
| split-brain test | two bodies claim one identity → fencing rejects the stale one, broker queues to it | #30 |

## 6. v1 simplifications (recorded)

- Single-host registry file (daimonmatrix), signed per revision; multi-host
  replication is a fleet-phase upgrade.
- Renewal driven by clusterd on behalf of containers (not by the daimons
  themselves) — daimon-side renewal lands with the steward/presence work.
- Registry public key distribution: piggybacks on the tribe directory's
  governance key (already distributed); the delegated lease-operator key
  is published in the directory as a governance-signed metadata entry
  (public material only — allowed by ADR D1, which excludes lease STATE,
  not lease KEYS, from the directory).
