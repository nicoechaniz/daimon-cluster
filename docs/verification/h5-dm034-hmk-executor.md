# H5 DM-034 HMK executor verification

Date: 2026-08-10. Candidate only; not merged or deployed.

## Scope

This receipt covers Cluster issue #68 on top of H4. It exercises synthetic
personal-memory vectors only. No live Matrix ledger, HMK memory, CompAII state,
credential or production fence was read or changed.

## Automated gates

The exact candidate passed:

```text
430 passed, 2 skipped in 61.77s
ruff check: clean
ruff format --check: clean
mypy (changed source modules, imported modules skipped): clean
py_compile: clean
git diff --check: clean
```

H5 unit coverage proves exact apply/replay, crash after inner effect, crash
after outer staging, immutable outer receipt, current-intent and preview
and source-review binding, changed postcondition and inner-observer refusal,
holder/epoch refusal, unknown observer refusal, exact rebuild-plan binding,
fresh namespace verification, payload-free SQLite evidence and distinct
per-embodiment roots.

The pinned Matrix normative DM-034 suite also ran against the same detached
HMK checkout: `14 passed, 3 subtests passed`. That library-level gate covers
assert/correct/retract, exact response-loss replay, current-head drift,
concurrent conflict, rebuild repair, pre-cutover backup/restore and native-row
survival. Cluster invokes those public DM-034 methods rather than duplicating
their protocol.

## Exact real-HMK drill

The drill used detached checkout
`f10fd5c3089c0962920314c97e14bc024feffa7a` and two temporary HMK bases. The
closed Cluster transport invoked the real pinned `daimon_projection.py` and
real SQLite implementation. It verified:

```json
{"atomic_rebuild":"verified","exact_replay":"verified","hmk_commit":"f10fd5c3089c0962920314c97e14bc024feffa7a","ok":true,"peer_independence":"verified","schema":"h5-hmk-projection-drill/v1","snapshot_restore":"verified","state":"temporary-removed"}
```

The complete machine receipt additionally contained only the synthetic
projection/rebuild receipt hashes and snapshot byte length/SHA-256/integrity
counts. Temporary bases were removed by the drill. The exact detached checkout
contains no private state and may be removed independently.

The same drill then passed over SSH on the authorized `daimonmatrix` host using
its installed Matrix pin. It ran under a unique `/tmp/daimon-h5-remote.*`
scratch, did not stop or reload any service, and the scratch was removed after
success. Post-check: `clusterd=active`; `iso-a`, `iso-b`, and `steward` all
remained `RUNNING`.

## Remaining gate

Independent review is required before merge. A later canary must explicitly
configure one per-embodiment executor and content resolver; the generic host
does not activate a route by ambient configuration. DM-035 publication remains
out of scope for H5 and is the next stacked milestone.
