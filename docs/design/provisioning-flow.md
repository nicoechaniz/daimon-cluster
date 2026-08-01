# Provisioning flow: governed identity, bridge keys, curated seed (issue #12 design)

Status: design v0.1 (2026-08-01), implementation lands in clusterctl #12.
Inputs: ADR-001 (D3 one state repo per daimon, D6 anyVPN, onboarding D8),
contracts (#4), tribe-agent profile + volume layout (#8), tribe bridge v1
protocol (tribe-bridge repo docs/v1-cutover.md).

## 1. What provisioning a daimon means

Creating a distinct `<agent>@daimonmatrix` embodiment = container + durable
volume + **identity material generated inside the durable volume** +
**governance-reviewed directory change** + optional **curated seed** +
human-supplied provider credentials. clusterctl orchestrates; nothing is
copied implicitly from another daimon — ever.

## 2. Sequence (mutating steps are prepare/confirm per contracts #4)

```
clusterctl provision prepare <agent> --species <species> \
    [--seed-manifest <path>] --requested-by <human> --sponsor <sponsor>
  1. create container <agent> from tribe-base/latest, profile tribe-agent
  2. create+attach durable volume <agent>-home at /home/agent
  3. INSIDE the container: generate tribe v1 identity keys
     (ed25519 signing + HPKE) under /home/agent/.tribe-bridge/v1/keys/
     — private material never leaves the volume, never touches host fs,
     logs, audit payloads, image layers, or git
  4. export ONLY public material: pubkey + proposed directory entry JSON
     (identity <agent>@daimonmatrix, host broker 10.10.20.69, pubkey)
  5. write instance spec (instance-spec/v1) into state_dir/instances/
  6. if seed manifest given: stage seed (§4), verify checksums, record
     provenance in /home/agent/.hermes/agent-memory/state/SEED-PROVENANCE
  7. emit confirmation token (single-use, 15 min TTL, names operation
     "provision-activate") + audit event (actor = requester)
  → HALT. Container is stopped. Nothing is reachable or registered.

clusterctl provision confirm <token>
  8. apply the governance-reviewed directory change (epoch bump — executed
     by governance, NOT by clusterctl: the token's artifact is handed to
     the governance operator; activation is a separately authorized step,
     safe to retry — the directory CAS makes duplicates impossible)
  9. start container; first-boot service writes READY marker
 10. health: hermes --version OK, tribe client self-test OK
 11. audit event: active
```

Directory activation being a separate, retryable, governance-authorized
step is the binding answer to "do not silently self-register" (#12).

## 3. Key custody rules (binding)

- Private keys are written only into the durable volume, by processes
  running inside the container, with umask 077.
- Host-side tooling sees only: pubkeys, fingerprints, directory entries.
- Audit events carry `key_fingerprint`, never key material.
- Image layers contain no keys (build-time secret scan, #7, enforces).
- State repos (D3) receive: SOUL/config/skills — and explicitly NOT
  `.tribe-bridge/v1/keys/` (path excluded in the repo template's
  .gitignore, generated at seed time).

## 4. Seed manifests (curated, provenance-tracked)

```yaml
schema: seed-manifest/v1
target: <agent>@daimonmatrix
curated_by: <human>
items:
  - kind: soul            # -> /home/agent/.hermes/SOUL.md
    source: file|git      # path or repo@commit
    sha256: <hex>
  - kind: hmk             # -> agent-memory/library.db (verified snapshot)
    source: file
    sha256: <hex>
  - kind: state-repo      # -> Projects/<agent>-state (git clone@commit)
    source: git
    ref: <commit>
  - kind: skills
    source: git
    ref: <commit>
```

Rules: every item carries a checksum or immutable ref; provisioning records
provenance (source, curator, checksum, timestamp) into the durable volume;
a first boot with NO manifest starts clean (blank HMK, template SOUL
marking the daimon as unborn-but-ready); provider credentials are NEVER in
a manifest — the owning human adds them post-provisioning inside the
container (#12 acceptance).

## 5. Failure semantics

Any step 1–6 failure → clean rollback: container deleted, volume deleted,
spec removed, no directory change, no keys anywhere. The confirm step is
idempotent via the directory CAS + the single-use token. A provisioned but
unconfirmed instance is visible in `clusterctl list` as state
`provisioned-pending-activation` (distinct from running/stopped).

## 6. Onboarding ceremony mapping (ADR D8)

| Role | Acts at step |
|------|--------------|
| member (human) | `--requested-by`; supplies provider credentials after step 11 |
| human sponsor | `--sponsor` (must differ from requester) |
| cluster owner | approves capacity (step 1 admission check vs cohort headroom) |
| governance | signs/apply directory change (step 8) |
| steward@daimonmatrix | executes provision prepare/confirm (scoped clusterd creds) |
| member again | verifies first contact over the bridge |
