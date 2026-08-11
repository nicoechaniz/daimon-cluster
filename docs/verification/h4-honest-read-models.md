# H4 honest read-model verification

Date: 2026-08-10  
Issue: daimon-cluster #67  
Branch: `issue-67-honest-read-models`  
Base: H3 exact-volume-relocation candidate `82c6227e0665821bfefae7d6fbacce8cf3920f5c`

## Candidate guarantees

- `instance-status/v2` separates declared, runtime, embodiment,
  incarnation, and actual Matrix-process observations. Every observation has
  an observation time or an explicit unavailable/not-observed reason.
- Instances, audit activity, and Matrix differences use immutable bounded
  snapshots. Signed opaque cursors bind endpoint, owner and filters. Invalid
  and cross-owner cursors return 400; expired/evicted cursors return 409.
- Snapshot traversal is stable across concurrent append: no skip, duplicate,
  or insertion of post-snapshot events.
- Owner scope is applied before snapshot creation. Instances, audit,
  embodiments, resource fences, backups, Matrix membership, and difference
  pages do not expose another owner's records.
- Matrix status distinguishes owner-local ledger integrity and queue state from
  peer reachability, known differences and last-successful-sync availability.
  `caught_up=yes` requires all of those observations; local cleanliness alone
  never means peer convergence.
- Status is bounded to 100 rows/members/targets/summaries, 64 KiB per row and
  1 MiB of admitted rows. Difference and general snapshot limits are 200 per
  page, 5,000 per snapshot and 4 MiB. Audit reads only the newest 4 MiB / ten
  thousand lines.
- Matrix payloads, routes, endpoints, sync requests, private paths and failure
  details do not cross the HTTP boundary.
- Dashboard and steward tools consume the new model and preserve typed alerts
  for process, owner-local, peer, partial-view, and known-difference states.

The normative shape and inference rules are in
`docs/contracts/read-models-v2.md`. The committed OpenAPI document is generated
from the route table.

## Local evidence

Run from a clean H4 worktree with the shared Python 3.13 virtual environment:

```text
PYTHONPATH=. PYTHONWARNINGS='error::ResourceWarning' pytest -q
425 passed, 2 skipped in 60.67s
```

The H4-specific and Matrix-status set passed 13/13. It covers:

- stopped, missing and drifted runtime observations;
- Matrix process down and stopped embodiment;
- locally corrupt, peer offline, locally clean/peer behind, and fully caught-up
  states as distinct results;
- owner scope on every read surface;
- append-concurrent snapshot traversal and cursor integrity/scope/expiry;
- 450 redacted differences across three pages;
- a 1,000-peer oversized view under the hard status response budget.

Additional checks:

```text
ruff check <changed Python modules and H4 tests>     All checks passed
mypy <seven changed source modules>                 Success: no issues found
python -m compileall -q clusterctl clusterd steward_tools
git diff --check                                    clean
OpenAPI/workflow YAML safe_load                     clean
changed-scope secret-pattern scan                   no material found
scripts/h4-read-model-drill.py --json               ok=true
```

## Remote isolated HTTP drill

The exact candidate archive was streamed over SSH to a `mktemp` directory on
`daimonmatrix`. It was not installed and did not read or mutate the live
clusterd state. The committed `scripts/h4-read-model-drill.py` created:

- a temporary state directory;
- a real clusterd HTTP server on an ephemeral loopback port;
- Alice and Bob owner-scoped read tokens (never printed);
- two declared/registered/running fake embodiments plus an undeclared runtime
  instance;
- 450 Matrix difference records containing canary payload/route values that
  must not cross the response boundary.

Receipt:

```json
{"audit_snapshot_append_boundary":"verified","cursor_integrity_scope_expiry":"verified","difference_items":450,"difference_pages":3,"instance_owner_scope":"verified","matrix_local_peer_separation":"verified","ok":true,"redaction":"verified","schema":"h4-read-model-drill/v1","server":"ephemeral-loopback","state":"temporary-removed"}
```

Post-drill checks:

```text
scratch=absent
clusterd=active
iso-a,RUNNING
iso-b,RUNNING
steward,RUNNING
```

No live service was restarted, no live token was read, and no Incus resource
was created, stopped, attached, detached, or modified.
