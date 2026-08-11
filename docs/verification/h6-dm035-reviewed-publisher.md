# H6 DM-035 reviewed publisher verification

Date: 2026-08-10. Candidate only; not merged or deployed.

## Scope

This receipt covers Cluster issue #69 on top of H5. All publication bytes,
reviews, Wiki/state roots and HMK databases were synthetic and isolated. No live
Wiki, compaii-state projection, Matrix request, credential or production fence
was read or changed.

## Automated gates

```text
Cluster stacked suite: 434 passed, 2 skipped in 61.85s
Matrix DM-035 exact integration: 22 passed, 25 subtests passed
ruff check / format: clean
mypy changed source modules: clean
py_compile / git diff --check / scoped secret scan: clean
```

Cluster tests prove exact outer apply/replay and full receipt reconstruction;
final-byte preview and signed-review binding; changed review/self-review,
intent, inner observer, postcondition and fence refusal; response-loss recovery;
unknown-route refusal; redaction of final text/logical/deployment paths; and
distinct per-embodiment roots.

The Matrix normative suite used detached exact provider/HMK checkouts and real
filesystem/SQLite state. Its 25 subtests cover every provider and Matrix crash
phase. The suite also covers both targets, secret rejection, inert hostile text,
exact-byte review, source/checkpoint/predecessor drift, response loss,
successor, reviewed tombstone, rollback, target/HMK drift, unknown manifest,
historical queue cutoff, two-process writer exclusion and unrelated-content
survival.

## Real provider transport drill

The Cluster transport ran the exact clean provider
`cf56e9de703f68f44b85fdf21f503d55a5557984` and HMK
`f10fd5c3089c0962920314c97e14bc024feffa7a` in bounded minimal-env child
processes over temporary real Wiki/state/runtime/HMK roots. It verified:

```json
{"concurrent_publisher":"refused","effect_reconciliation":"verified","exact_replay":"verified","ok":true,"schema":"h6-reviewed-publication-drill/v1","state":"temporary-removed","unrelated_target":"unchanged"}
```

The full machine receipt additionally contained only exact commits and
manifest/plan/receipt hashes. Temporary roots were removed by the drill.

The same transport drill passed over SSH on the authorized `daimonmatrix` host
using its installed exact Matrix pin. It ran entirely below one unique
`/tmp/daimon-h6-remote.*` root, did not activate an executor route or touch a
live Wiki/state/HMK root, and the scratch was removed after success. Post-check:
`clusterd=active`; `iso-a`, `iso-b`, and `steward` remained `RUNNING`.

## Remaining gate

Independent review is required before merge. The route is not configured in a
live host. A future canary requires an exact current Matrix request, separate
human signature over its final-byte hash, and explicit operator selection of
the fixed non-production target; this candidate itself authorizes none of
those effects.
