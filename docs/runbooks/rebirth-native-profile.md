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
An existing `rebirth-start` intent selecting a different profile remains a real
journal conflict; never overwrite it to force a new startup.

Keep the serving configuration, code selection and startup result in the owning
host record. Install the supervisor through the existing bounded service route;
preserve rollback and coordinate singleton Telegram/VPN/shared writers separately.
H8 readiness alone does not prove group delivery, application dispatch or
independence from the old host. Verify those actual receiving effects before
cutover, without replaying uncertain inputs.
