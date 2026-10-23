# Selected same-being behavior materialization

Cluster#294 supplies the receiving child adapter for
[Matrix#376](https://github.com/AlterMundi/daimon-matrix/issues/376).
The integration parent owns source/content closure, semantic three-way comparison,
exact Weave proposal/local adoption references, selection and consumption evidence.
This adapter neither reads peer inboxes nor adopts a proposal by receiving it.
It is not a standalone completed sync workflow or an onboarding replacement.

Use `clusterctl.behavior_delta.BehaviorDelta` with the existing owner-private
`OperationJournal`, the verified receiving binding and its maintained native
client. Supply the receiving configuration file and cwd locally. Both source and
receiver bindings contain `being_ref`, `body_ref`, `embodiment_id`,
`incarnation_id`, `principal_id`; different beings are refused. These arguments
are the caller's authenticated observations, not peer-granted credentials.

`prepare(operation_id, source=..., source_refs=[sha256, ...], files=..., edits=...)`
retains selected preimages and a content-bound selection without changing targets.
`files` maps explicitly selected local absolute destinations to exact bytes or
`None` for removal; `edits` contains `(key_segments, value)` pairs. `None` removes
an explicit native setting. Nested and literal dotted key segments remain
separate; overlapping edits are refused. Preserve deliberate bindings and do not
select credentials, account/access policy, hooks, attention or other changes
outside the human's task. A source path never selects a receiving destination.
Resolve an intentional installed alias through receiving discovery before using
its owned real path; this adapter refuses symlink destinations.

`apply` and its `recover` alias resume the original child. `status` reobserves the
actual selected state, including after historical completion. It exposes hashes,
match flags and uncertainty, not source text or private paths. A later edit is a
conflict; retry does not restore it to an older completed postimage. Untouched
native settings can change independently. Selected native values are compared
before each batch, then `config/batchWrite` uses the fresh exact user-layer
`expectedVersion` and requests `reloadUserConfig`. It never rewrites TOML or uses
initial enrollment's identity renderer. Native API/version incompatibility stays
unsupported instead of falling back to a whole-file restoration.

File effects use owned bounded originals, preserved mode, atomic replacement and
directory fsync. Cluster's existing journal serializes the operation and retains
its dispatch boundary before external I/O. Recovery accepts an exact observed
postimage after a lost return, without repeating that effect. If a native return
was lost, the saved state can be verified while reload acknowledgment stays
unknown. Neither readback nor a successful reload request proves an existing model
context consumed new instruction text. Results deliberately report consumption as
unverified; the parent supplies actual receiving-use evidence separately.

`rollback(operation_id)` retains an inverse child after completed application.
It restores only unchanged selected files/settings and preserves unrelated later
native edits. Repeat that same call after a lost rollback return; it resumes the
same inverse child. Partial application stays resumable; it is not silently
compensated or discarded. If its selected state conflicts, preserve both retained
originals and current edits for the parent's explicit reconciliation. No global
Stop, native thread/model request, credentials or background worker is involved.

The journal contains private originals and local bindings. Keep it owner-private;
retain it as operation history and compatible rollback, never publish it as an
artifact. No automatic retirement is authorized here. Different receiving
incarnations require their own explicit recovery decision rather than reusing an
old binding by label alone.

## Qualification

Normal CI selects this adapter, operation-journal and CI contract tests; shared or
unknown source edits still select the full suite. No provider/model is needed.
For an explicitly selected installed Codex executable, run:

```sh
BEHAVIOR_NATIVE_BINARY=/absolute/path/to/codex python -m pytest \
  tests/test_behavior_native.py -q
```

This creates an isolated temporary home, initializes only its disposable stdio
app-server, writes synthetic selected settings through the real native API,
loses the return deliberately, recovers without another write and reverses the
selection while preserving a later unrelated native setting. The original native
server, live home, sessions and credentials are untouched. Cleanup closes only
the fixture-owned process. CI without that exact binary explicitly skips this
actual-native case; synthetic tests are not presented as native proof.
