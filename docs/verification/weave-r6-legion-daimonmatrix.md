# R6 Legion–daimonmatrix plural-presence canary

Date: 2026-08-02  
Result: PASS

This receipt records the redacted operational acceptance journey for Cluster
issue #43 and Matrix DM-072. The canary activated two isolated Weave runtimes,
one on Legion and one on daimonmatrix. It did not stop either host, modify a
production service, copy a writable database, or transmit private key bytes.

## Versions and common root

- Matrix merge: `5074a4fd4e8719d30449b368fd644c6580c1f2f7`
- Cluster merge: `9e656f3f9df2d1d7812e0e37d46c0ec5e272ffaa`
- Tribe Bridge merge: `d2f3c9e64b8a5ef4ca5f3e75798e4b028f5e8b7a`
- provisional `being_ref`: `being:00000000-0000-4000-8000-000000000100`
- canonical manifest hash: `affb39da401f3cd9fb1ab4157019dc69fed4367770ba058069b04ea9253cb37b`
- manifest file SHA-256 on both hosts:
  `1362ba6cd1028c83da7456e430b859a3f284136d485c50a4766cbe60f6f96ed4`
- runtime/key files were mode `0600`; each embodiment had a different
  Ed25519 key and an independent SQLite WAL ledger.

The manifest declared active embodiments for `compaii@legion` and
`compaii@daimonmatrix`. Both runtimes used the same manifest hash while keeping
different body, embodiment, incarnation, signing-key, and database state.

## Journey evidence

1. Both runtimes reported configured and awake without an exclusivity error.
2. While partitioned, Legion appended `environment.weather`; daimonmatrix
   appended `deployment.state` and then a `github.identity` proposal containing
   only a `secret_slot_ref`.
3. Legion previewed the first remote event (`received=1`, `missing=1`), pulled
   it, then resumed from remote sequence 1. The second page reported
   `received=2`, `missing=1`.
4. The reverse pull admitted the Legion branch on daimonmatrix. A complete
   retry after process restart reported `received=3`, `missing=0`. Both sides
   had the same three content hashes and preserved both origins.
5. One `/we` request, `fd9d461a-ab7c-4e70-9fc6-e87ae6fd2de7`, received separate
   `ok` responses from `compaii@legion` and `compaii@daimonmatrix`. Replaying the
   request against each handler returned its cached response and did not invoke
   the responder again.
6. Legion saw proposal `993c36d9-edaa-4787-91de-33517c7bed7e` as `pending`,
   adopted it with decision `e5be940f-ab5c-415e-89cd-a9e53ca6c115`, and then
   reverted it with decision `e69dc9b2-34a9-47ee-882b-4cc249079ae7`. The
   decision was local to the Legion embodiment; no projection or provider
   mutation was performed.
7. daimonmatrix restarted into incarnation
   `incarnation:00000000-0000-4000-8000-000000000113` and emitted event
   `11e6015b-e469-47ef-9067-470ff5702be2` at sequence 1. Legion retained the old
   incarnation cursor at sequence 2, added the new cursor at sequence 1, and a
   repeated pull reported `missing=0`.
8. Final ledgers contained the same six event hashes. The last remote
   incarnation tip was
   `dc9b22b260bd8d4364ad3bf3e16b6a75040aec1c3bb65ad67fe4e07223eb6166`.
9. For `canary-shared-volume`, a second holder was rejected while epoch 0 was
   active. After release and reacquisition by the other embodiment, the epoch
   advanced to 1 and `_check_stale_acquisition` rejected the epoch-0 writer.

## Event receipt

| Origin | Incarnation / sequence | Kind | Content hash |
|---|---|---|---|
| compaii@legion | `...111` / 1 | experience.observed | `c73f885858612674ded42cedf1dcc418a31a93b78d659cdda89eed787b1e0ba3` |
| compaii@daimonmatrix | `...112` / 1 | experience.observed | `8bf269254926dbc45a27e084a4c07fe43e837fffe74c25cc99f2053a5223d992` |
| compaii@daimonmatrix | `...112` / 2 | configuration.proposed | `f1717a04d4e2a2835d2fa30edf956c9e74988ff72a7fb42dc97b86f20a4b46a7` |
| compaii@legion | `...111` / 2 | adoption.decided | `993754762344d80d08beb6b3555d86c0911ddec7e0a73131c428276b39a2e409` |
| compaii@legion | `...111` / 3 | adoption.decided | `3010a31c16ea3132a459201bb821c9586fded11dbae8abf1a475f954ca4bd797` |
| compaii@daimonmatrix | `...113` / 1 | lifecycle.announced | `dc9b22b260bd8d4364ad3bf3e16b6a75040aec1c3bb65ad67fe4e07223eb6166` |

## Rollback and custody

No production configuration changed, so service rollback is a no-op. Stop any
canary process, archive the two independent ledgers if further audit is wanted,
then remove the temporary runtime/key material on each host. Do not copy or
merge the SQLite files. A future run resumes by reinstalling an authorized
manifest/runtime and exchanging signed delta pages. Canonical ledgers, if any,
must be retained; rollback revokes routing/key authorization rather than
deleting history.

This document deliberately omits private seeds, complete runtime JSON, and
writable database bytes.
