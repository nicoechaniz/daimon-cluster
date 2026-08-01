# Runbook: steward identity custody (issue #21)

steward@daimonmatrix — the tribe's conversational operator. Lives in an
unprivileged container with NO host authority; all power flows through
scoped clusterd tokens.

## What exists (provisioned 2026-08-01)

- Container `steward` (tribe-agent profile, species steward), provisioned
  via `clusterctl provision prepare/confirm` (requested-by compaii,
  sponsor nico). Identity key born in-container (ed25519), durable
  volume `steward-home` at /home/agent.
- clusterd credentials in the durable volume (0600):
  `/home/agent/.clusterd/read-token` (scopes: read) and
  `/home/agent/.clusterd/mutate-token` (scopes: read+mutate,
  actor steward@daimonmatrix → unattended mutations denied without the
  X-Attended human marker).
- clusterd reachable from the container at http://10.105.93.1:8785
  (bridge gateway socket; loopback socket for host ops).

## Verified invariants (live, 2026-08-01)

| Invariant | Check | Result |
|-----------|-------|--------|
| no Incus socket | /var/lib/incus/unix.socket in container | absent |
| no Incus CLI | `incus list` in container | command not found |
| no sibling volumes | attached mounts | only steward-home |
| no host shell | container, tribe-agent profile | inherent |
| no backup keys | /var/lib/daimon-cluster in container | absent |
| no governance private keys | ~/.tribe-bridge/keys in container | absent |
| read token cannot mutate | POST /v1/instances/x/stop with read token | 403 |
| steward unattended denied | mutation without X-Attended | 403 |

## Token rotation (30d TTL)

1. Create the replacement (as clusterd user on the host):
   `auth.create_token(..., actor='steward@daimonmatrix', scopes=[...], ttl_days=30)`
2. Stage into the container volume, atomically:
   `incus exec steward -- bash -c 'printf %s NEW > /home/agent/.clusterd/read-token.new && mv ... read-token'`
3. Verify a read through the new token; then revoke the old token-id.
   Revocation is effective on the next request (mtime-checked store).

## Revocation / compromise response

- Suspected token leak: revoke BOTH steward token-ids immediately
  (`scripts/clusterd --token-revoke --token-id ...`). The steward loses
  all API power; clusterctl on the host is unaffected (break-glass).
- Suspected container compromise: `clusterctl stop steward` + quiesced
  snapshot for forensics + provision a replacement container with fresh
  identity keys; the old identity gets a tombstone in the directory
  (governance act, see ceremonies design).
- Every mutation the steward ever made is attributable: audit events
  carry actor=steward@daimonmatrix + request_id; the hash chain proves
  the trail wasn't rewritten.

## Break-glass human path (acceptance: revoking the steward leaves
clusterctl available)

With all steward tokens revoked and/or the steward container destroyed,
the human operator keeps full control:

    ssh debian@daimonmatrix
    sudo -E ~/Projects/daimon-cluster/scripts/clusterctl list
    sudo -E ~/Projects/daimon-cluster/scripts/clusterctl <any mutation>

…and scoped API access via the human token at
/var/lib/daimon-cluster/.nico-token (or a fresh one minted as the
clusterd user). The steward is a convenience, never a single point.
