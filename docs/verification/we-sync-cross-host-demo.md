# First cross-host /we.sync demonstration — runbook (M10, goal Done)

The goal's last verification: /we.sync between two REAL embodiments of
one being — `compaii@daimonmatrix` and `compaii@legion` — woven over
tribe-bridge v1. Every step is mechanical; the semantics are already
proven (tests/test_wesync.py, tests/test_merge.py, live CLI drill
2026-08-02 with the deployed code).

Preconditions: legion has pulled daimon-cluster main (>= f5937d0).

## 0. The seed (ONE chain, ONE genesis — DM-070 rule)

The census on daimonmatrix was bootstrapped 2026-08-02: being `compaii`,
genesis `7b0e19109b8f`, cursor 1 (`compaii@daimonmatrix` awake). A chain
that starts independently elsewhere has a DIFFERENT genesis and sync
will refuse it (a different being, not a conflict). So legion's chain
is seeded FROM daimonmatrix's:

```bash
# daimonmatrix — append legion's embodiment to the census (awake)
sudo -u clusterd env PYTHONPATH=/opt/daimon-cluster \
  /opt/daimon-cluster/venv/bin/python -c "
from clusterctl.registry import EmbodimentRegistry
r = EmbodimentRegistry('/var/lib/daimon-cluster')
r.register('compaii', 'compaii@legion', 'legion', 'awake', actor='wesync-demo')
print('cursor:', r.current_cursor('compaii'))"

# daimonmatrix — ship the chain + nothing else to legion (tribe-bridge v1)
sudo cat /var/lib/daimon-cluster/registry/compaii.history.jsonl | base64
# send via send_v1.py --to compaii --classification private (payload)
```

```bash
# legion — install the chain as its own registry (SAME genesis)
mkdir -p /var/lib/daimon-cluster/registry
# (decode the payload into compaii.history.jsonl, owner clusterd)
```

## 1. Both sides live independently (the partition is optional)

```bash
# daimonmatrix
clusterctl wesync record compaii --origin compaii@daimonmatrix \
  --kind observation --payload '{"text": "..."}'
# legion (its own deployments, its own experiences)
clusterctl wesync record compaii --origin compaii@legion \
  --kind observation --payload '{"text": "..."}'
```

## 2. Weave (bundles ride tribe-bridge v1 messages)

```bash
# daimonmatrix
clusterctl wesync export compaii --from compaii@daimonmatrix > /tmp/w-ab.json
# send the JSON as a tribe-bridge message to compaii@legion
# legion
clusterctl wesync import --file <received-bundle>
# and symmetrically legion -> daimonmatrix
```

Expected: experiences converge by union with origin attribution intact,
chain appends link onto the tip, re-import shows all-duplicates
(no duplicates, ever). `clusterctl wesync status compaii` on both sides
shows the same chain cursor.

## 3. Acceptance (the goal's Done)

- [ ] both `wesync status` show identical chain cursors and genesis
      `7b0e19109b8f`
- [ ] experiences on both sides: union, each entry with its true origin
- [ ] re-sync: 0 appended, all duplicates
- [ ] dashboard /we card on daimonmatrix shows both embodiments,
      coherente
- [ ] (optional) partition drill: both append chain transitions while
      out of contact, then heal → branch flagged on both sides →
      `clusterctl wesync merge` both sides → byte-identical chains

## Notes

- Bundle transport is deliberately manual (tribe-bridge messages) for
  this first demonstration; automation (a wesync cron exchanging via
  the bridge) is a later milestone.
- If `merge` refuses with "requires a full-chain bundle", re-export
  WITHOUT peer cursors (full chain) and retry.
