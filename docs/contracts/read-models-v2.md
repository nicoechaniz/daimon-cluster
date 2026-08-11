# clusterd honest read models v2

Status: normative H4 candidate. The API is forward-only while the V0
infrastructure is not in service.

## Snapshot pages

`GET /v1/instances`, `GET /v1/audit`, and
`GET /v1/weave/differences?embodiment_id=...` return:

```json
{
  "schema": "clusterd-page/v1",
  "items": [],
  "page": {
    "limit": 50,
    "count": 0,
    "has_more": false,
    "next_cursor": null,
    "snapshot_id": "opaque-random-id",
    "observed_at_ms": 1786412400000,
    "expires_in_s": 299,
    "truncated": false
  }
}
```

The first request creates an immutable, already owner-scoped and redacted
snapshot. `next_cursor` is signed, opaque, bound to endpoint + owner + filters,
and valid for five minutes. Concurrent appends or inventory changes are not
inserted into that snapshot, so traversal has no skips or duplicates. Invalid
or cross-scope cursors return 400. Expired, evicted, or pre-restart cursors
return 409 and the caller restarts at page one.

Limits are 1–200 items per page. A snapshot admits at most 5,000 items and
4 MiB of canonical JSON. The audit reader scans at most the newest 4 MiB / ten
thousand lines. `truncated=true` means the bounded source or snapshot excluded
older/additional items; it is never permission to infer that the returned page
is complete.

## Instance observations

`instance-status/v2` retains aggregate reconciliation `state` for CLI use and
adds a common `observed_at_ms` plus independent `observations`:

- `declared`: `declared | absent | unavailable`, including declared owner;
- `runtime`: `running | stopped | missing | unknown | unavailable` and
  `present`;
- `embodiment`: registry `running | stopped | retired`, `missing`, `absent`,
  or `unavailable`;
- `incarnation`: `open | absent | contradictory | unavailable`;
- `matrix_process`: `available | down | not-configured | not-observed |
  absent | unavailable`.

Clusterctl itself cannot observe registry or Matrix process state and says
`unavailable` with a reason. Clusterd augments those two observations from the
owner-only registry and an actual authenticated Matrix status call. It never
infers identity, incarnation, fence ownership, or process availability from an
instance name or Incus presence.

Owner-scoped tokens see only declared instances whose `created_by` matches.
They do not see undeclared runtime instances or registry membership belonging
to another owner. Owner scoping is applied before snapshot creation and is
checked again through cursor binding.

## Matrix status

`GET /v1/weave/status` is a bounded summary (100 embodiments, 100 topology
members, 100 sync targets, 100 origin summaries, 64 KiB per embodiment row and
1 MiB admitted rows per response). Oversized rows become explicit
`read-model-overflow` unavailable summaries. Each embodiment has separate:

- `embodiment_observation` and `matrix_process`;
- `owner_local.ledger_integrity` and `owner_local.queue`;
- `peer_sync.reachability`, `last_successful_sync`, known difference count,
  and a conservative `caught_up {state, reason}`.

Typed `alerts` preserve the same boundaries (`matrix-process-down`,
`owner-local-ledger-not-ok`, `owner-local-queue-attention`, `peer-offline`,
`peer-partial`, `known-peer-differences`, and `matrix-view-partial`). The
dashboard renders those exact codes; it does not manufacture a single health
badge from local presence.

`caught_up=yes` requires an OK owner-local ledger, a clean owner-local queue,
at least one observed peer, all observed peers available, no partial Matrix
view, and zero known differences. Local cleanliness alone is never convergence.
The current pinned Matrix contract does not expose a last-success timestamp;
the field therefore says `unavailable` instead of inventing one.

Difference entries are excluded from status and fetched through their page
endpoint. Only projection metadata fields are admitted. Payloads, endpoints,
routes, sync requests, private paths, and client failures are redacted at the
HTTP boundary.
