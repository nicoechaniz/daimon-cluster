# Offline physical RC rehearsal preflight

This runbook prepares a plan; it does not authorize or execute one. Host
selection, real custody, external contact and every physical effect remain
human gates.

First generate the canonical `daimon-release-candidate/v1` manifest described
in `release-candidate-freeze.md`. Then create a canonical JSON
`dm.cluster.physical-rehearsal-plan/v1` document with:

- the exact Matrix, Cluster and Tribe commits/trees from the final RC manifest;
- its exact `rc_manifest_sha256`, exact component commits/trees and the complete
  component-qualified artifact name/SHA-256 inventory from that manifest;
- exactly three distinct purpose-built, non-production roles: `source`,
  `target`, `backup`;
- ordered `preflight`, `backup-export`, `volume-transfer`, `restore`,
  `start-reboot`, `loss-fence` and `rollback` stages. `backup-export` executes
  on the independent `backup` role; restore/start/reboot/fencing execute on the
  `target`; the remaining stages execute on the `source`;
- argv arrays (never shell snippets), bounded effects, success observations and
  rollback argv for every stage; and
- all approval booleans false except `exact_go_required=true`.

The operator then freezes it offline:

```bash
python tools/build_physical_preflight.py \
  --plan rehearsal-plan.json \
  --rc-manifest daimon-v0.1.0rc1.json \
  --output physical-preflight.json
```

The tool rejects any component or artifact drift from the supplied manifest,
including a missing backup-stage assignment. The output remains
`execution_authorized=false` and includes both the manifest digest and a
domain-separated `plan_sha256` plus the only acceptable future token,
`GO <plan_sha256>`. The tool performs no DNS, network, SSH, service, access or
custody operation.

Before requesting that GO, an independent reviewer must verify the exact file,
artifact hashes, purpose-built ownership, effects, observations, rollback and
recovery access. Any byte change produces a different token. A GO for an older
or similar plan is invalid.

Even with a matching GO, a separate execution procedure must keep recovery
access open, enforce rollback deadlines and stop on the first observation
mismatch. This repository intentionally contains no auto-execute command.
