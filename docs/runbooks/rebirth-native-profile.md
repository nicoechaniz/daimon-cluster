# Native Matrix group hosting after H7

H8 can supervise either its ordinary `matrix-host` profile or the maintained
native Source profile. Use the latter when the receiving body needs its approved
Tribe applications. Both profiles use the same installed H7 identity, distributed
predecessor admission, shared holder lease, Registry and admission supervisor.
This is not another identity enrollment or a model-harness startup.

Select `--native-source-profile PATH` on `clusterctl.rebirth_host`. The selected
owner-private canonical JSON document has exactly these fields:

```json
{
  "schema": "dm.cluster.rebirth-native-profile/v1",
  "config": "/absolute/owner/source-configuration.json",
  "code": "/absolute/root-owned/qualified-runtime-code",
  "code_digest": "qualified-release-digest",
  "home": "/absolute/owner/sdk-home"
}
```

`home` is the private SDK installation home, which can differ from the account
home when existing account directories have shared traversal. Reuse the maintained
SDK installer and its immutable generations. The release must carry a qualified
V4 SDK selection; do not install dependencies into an existing generation.

The ordinary Source configuration, also owner-private canonical JSON, selects
the exact H7 `matrix_root(state, embodiment_id)`, existing password file,
native visibility, outputs and approved applications. Its expected digest is
checked against the actual parsed settings passed to Source before serving.
The supplied password descriptor must match that existing password. Source
retains its real runtime writer lock. Do not select the preparation/package copy
as a second writable body or copy another body's integration binding.

The fresh child imports only the selected qualified code/SDK. Kernel parent-death
fencing kills it if its admission supervisor disappears. H8 also terminates it
when the shared lease cannot be renewed. Readiness authenticates the loaded
identity, manifest, physical root, actual spawned PID and selected SDK. A native
profile does not synthesize a harness lifecycle card or claim a model turn.

Native visibility and resource grants remain those of the selected Source
configuration. `--production-fence-verifier` and the ordinary profile's separate
visibility option are rejected with this profile rather than silently ignored.
An SDK-only successor with unchanged Source config can use the existing native
start-record successor path: it anchors the completed predecessor and retains
the original identity/admission history. Unrelated intent changes still refuse.
Do not overwrite or reset a start record to force startup; a known unready
attempt uses only its explicitly retained recovery operation.

For maintenance selection, use `rebirth_native.select_profile(path, candidate,
previous=retained_previous)` under the existing operation. It reuses the canonical
writer and Matrix selection lock, preserves config/home, rejects a concurrent
successor and reconciles replacement before acknowledgment without rewriting it.
The operation retains its original profile; this helper creates no growing series
of backup files. Qualify the successor through `prepare` before the scoped stop.
Selection alone does not stop/start a service, migrate catalogs, establish body
admission or qualify readers.

## Routine H8 maintenance through the existing fleet command

Use the same `python -B -m clusterctl.onboarding_managed --spec PATH` operator
with an owner-private `cluster-native-profile-maintenance/v1` spec. Its required
fields are `operation_id` (a canonical UUID), `profile`, `candidate` (the exact
profile document above), `unit`, `journal` and `max_seconds` (1–180). The selected
SDK/import generation must already be prepared. The service's existing owner is
resolved from the private profile; no login, account or unit directive is changed.

The command qualifies the successor reader against the serving body, binds its
actual admission parent to the selected system unit, retains the operation, stops
that Matrix unit, migrates through the successor SDK, selects the canonical
profile and observes the successor. It preserves config/home, native identity,
authority, history and unrelated harness/goal services. A matching profile is a
no-op: observation does not justify a restart.

Include `reader_completion` using the existing maintained reader-route contract
to finish current cohort qualification in the same command. Job-backed reader
routes reuse `host_config` and optional `vm_qualification`, exactly as ordinary
managed-job maintenance. All routes are inspected before lifecycle effects. On exact recovery of an
operation-owned stopped service, its frozen authenticated predecessor supplies
preflight selection until that same native operation restores it; other owners
are still inspected. The updated body's expected selection comes from its actual receipt. Other owners
retain their expected selections. The existing cohort completer performs any
needed controls and distinguishes `qualified-local-projection` from message or
model acceptance. Omit reader completion only for an explicitly code-only result,
which reports `receiving_readiness: unobserved`.

`--check-only` inspects the live owner, service and configured reader routes
without creating an operation, selecting software or dispatching lifecycle or
reader controls. Every owner call and the cohort share the invocation's single
absolute deadline. Retry the same spec/operation: confirmed effects are retained.
Pinned process-exit waits respect their60-second primitive limit within the
original overall deadline. An accepted start may need time to expose its owner
reader: observe readiness under that same deadline without starting again.
A lost start acknowledgment with an active candidate is observed, not started
again. An inactive unit with an unresolved start intent stays explicitly
unconfirmed; inspect the actual native start journal/service outcome through the
existing recovery route before another startup, rather than guessing dispatch.

Use a dedicated maintenance journal, retaining completed history and every
uncertain effect. New operations stop before lifecycle admission at64records or
when the64MiB working budget cannot reserve8MiB for each in-flight operation.
Exact resumptions and unchanged-profile observation remain available. This is a
bounded stop path, not automatic history deletion; never replace an unfinished
journal or redirect an old operation to an empty one to bypass its outcome.

Keep the serving configuration, code selection and startup result in the owning
host record. Install the supervisor through the existing bounded service route;
preserve rollback and coordinate singleton Telegram/VPN/shared writers separately.
H8 readiness alone does not prove group delivery, application dispatch or
independence from the old host. Verify those actual receiving effects before
cutover, without replaying uncertain inputs.
