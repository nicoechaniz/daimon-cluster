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

For a read-only loaded-view check, use the selected qualified Source CLI with
`--observe --require-loaded`. It verifies both the running base and its loaded
application with one deadline. Use `--observation-deadline-ns` to share the
calling operation’s monotonic deadline. Use `--owner-status` when verifying
that the active group reader is also under receiving control.

Native visibility and resource grants remain those of the selected Source
configuration. `--production-fence-verifier` and the ordinary profile's separate
visibility option are rejected with this profile rather than silently ignored.
An SDK-only successor with unchanged Source config can use the existing native
start-record successor path: it anchors the completed predecessor and retains
the original identity/admission history. Unrelated intent changes still refuse.
Do not overwrite or reset a start record to force startup; a known unready
attempt uses only its explicitly retained recovery operation.

An ordinary signed enrollment or retirement can advance the runtime authority
of an existing active embodiment without issuing a new install or holder
binding. H8 verifies the exact authority chain from its original installation
and uses that original manifest for its distributed admission and hosting
lease. The native child must prove readiness under the current manifest. The
startup journal retains the completed predecessor and accepts the verified
authority advance only with the same incarnation and identical native profile.
Recovery and unrelated history still require their own installation and
admission authority.

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

The default manager is the system manager. For an existing Matrix-only
systemd user service, add `"manager": "user"` to the receiving owner's own
mode-0600 spec and run the command as that same non-root owner. This scope
supports the local profile operation; fleet reader completion uses the
root-managed command. The user unit's fragment and drop-ins must belong to
the same owner. The check ties the authenticated child to that unit's actual
admission supervisor.

To provision the first receiving controller on an already loaded owner-local
profile, keep `candidate` equal to the active profile and add
`controller_helper` (an immutable helper profile with the same SDK, config,
and home) and `controller_expires_at_ms` (the Matrix issuance horizon).
Run the same command with `--check-only` before applying. The operation pins
the child and admission supervisor, preserves the signed group selection, and
uses the native capability and visibility writers while those processes are
observably stopped. It restarts the same supervisor and requires authenticated
readback of the new controller. Retain the original spec and journal after an
interrupted acknowledgment. A loaded controller does not prove a message or
model turn.

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

`--check-only` authenticates the loaded application and associates its child
process with the admission supervisor before a receiving controller is issued.
This check reports `receiving_readiness: unobserved`. A configured reader
completion still checks its required reader routes. The check creates no
operation and dispatches no lifecycle or reader controls. Every owner call and
the cohort share the invocation's single absolute deadline. Retry the same spec/operation: confirmed effects are retained.
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
