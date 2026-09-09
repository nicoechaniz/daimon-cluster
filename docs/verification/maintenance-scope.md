# Issue 106: installed-line Matrix hosting maintenance slice

## Frozen scope, not deployment approval

Base: installed Cluster `4a2571a6b22c6e504c1f78ce6594f1a2ad445097`.
Modern source: exact Git objects at `48caa742c212345783cad94537184adcfd2c439b`.
Matrix: whole genuine noneditable VCS installation of
`0a80cc5c38d3c7f5cad98d440153f0cf9706686b`.
This is a complete maintenance checkout, not an installation overlay and not
modern Cluster main. No commit, publication or deployment occurred.
Issue 106's installed-line scope does not authorize replacing unrelated fleet
code or bypassing main branch policy. The CI modification is a local draft.

The V1 external-client migration helper is deliberately ABSENT. Its independent
writer/reviewer and parent own integration. No mutable files were copied from
that writer. Its addition must extend the explicit composition allowlist and
receive a new freeze and full qualification. This slice alone cannot start the
actual installed V1 runtime/client pair. The current actual MCP configuration
correction does not require a Matrix repin (parent-supplied update).

## Exact runtime composition and imports

- `clusterctl/matrix_host.py`: modern complete source, with exactly one change:
  `from .fences import FenceError, ResourceFenceStore` becomes
  `from .matrix_fencing.fences import FenceError, ResourceFenceStore`.
- `matrix_fencing/fences.py`: modern `clusterctl/fences.py`, byte-identical.
- `matrix_fencing/production_fences.py`: modern `clusterctl/production_fences.py`,
  byte-identical. Both modules' relative imports remain inside the private
  namespace. No extraction or reimplementation of crypto/authorization logic.
- `matrix_fencing/__init__.py`: docstring only.
- `requirements-weave.txt`: byte-identical to modern source, including exact pin.

**Signing discovery:** neither exact tree has `clusterctl/signing.py`. Modern
fences defines its own `Signer`, `Ed25519Signer`, `_canonical`; production_fences
imports them from `.fences`, now correctly private. There is no `.signing` import
requiring `..signing`, and no assumed old signing API compatibility. The old
fleet signer types remain in the unchanged global fences module. No cross-type
adapter, global class edit or monkeypatch links these namespaces.

All 30 baseline runtime Python files are inventoried in maintenance-baseline.json;
only matrix_host changes. Global fences, leases, embodiments, fleet lifecycle,
provision/park/transfer, clusterd and steward modules remain byte-identical.
All baseline configs, scripts (except the additive test runner), assets and
historical docs remain untouched. Full baseline hashes cover more than runtime.
The sole runtime dependency of the host outside the private fence modules is
old Registry's existing read interface; genuine host/process/HTTP tests use it.
No new IPC bridge, curator executor, shared admission service or rebirth launcher
is introduced. Modern host optional messaging remains explicit opt-in.

The two fence namespaces are code isolation, NOT a global overlapping-resource
exclusion scheme. Modern verification uses its own SQLite authority, trusted
host owner policy and signatures. Legacy APIs retain their historical limits.
Messaging does not need enrolled holders or acquisitions; synthetic empty real
Ed25519 authority is accepted, absent authority is refused without DB creation.
Separate production custody and no-overlapping-grants gates remain mandatory.

## Snapshot semantic boundary

The host's direct portable snapshot APIs now enforce modern V7 contracts:
complete signed canonical runtime/client-profile bindings, safe file names and
owner metadata, strict closed inventory and exact Matrix commit. Host-local
plaintext status/curator keys and operator/profile client files are excluded;
the encrypted runtime custody remains part of a full snapshot.
Signed runtime/public bundle, encrypted runtime custody and canonical persistent
state have their modern distinctions; this is not an old generic fleet backup
compatibility promise. Live sockets/locks are rejected, destination publication
is no-replace, integrity is checked before restore, and derivative recovery
snapshots are not silently accepted as full restores.

The inherited modern snapshot suite exercises required members, schema/profile
refusals, tamper, symlinks, interrupted copying, no-replace contender races and
host-client exclusion. Whole runtime relocation/restart is also tested with
real synthetic authority. None proves live production restore, V1 sidecar
conversion, production custody recovery or permission to rewind authority.
The old fleet snapshot implementation and its original tests are unchanged.

## Test origin and explicit adaptations

Copied from exact modern Git objects (not mutable worktree):
`tests/test_matrix_host.py`, `tests/test_matrix_host_process.py`,
`tests/test_production_fences.py`, `tests/test_matrix_messaging_host.py`.
Fence imports are changed to the private namespace, and otherwise source is
retained except:

1. Modern host's outside-repository launcher test is replaced by the actual
   installed service invocation `python -m clusterctl.matrix_host --help` from
   the complete checkout. The old `scripts/matrix-host` is byte-identical; its
   known outside-checkout import limitation is NOT fixed or claimed supported.
2. Modern messaging test relying on rebirth/admission modules is replaced by
   a real signed host startup-refusal/restart test using the included process
   fixtures. It proves host-lock cleanup, NOT modern shared-admission cleanup.
   Those unrelated modules are intentionally not imported into this release.
3. Original `tests/test_clusterd.py` changes ONLY the expected Matrix commit.
4. Original `tests/test_matrix_parity.py` changes ONLY V2 constant/test name to
   V3, matching the new genuine dependency; other historical parity stays.

New tests cover whole baseline byte parity, closed runtime additions, exact
modern-source composition, missing-authority noncreation and actual five-method
client tuple responses through the unchanged old clusterd HTTP consumer. A real
root-signed runtime and real Ed25519 fence authority provide successful
admission. Unauthenticated HTTP gets 401, read-only old bearer cannot mutate
(403), projection keeps expected fields and redacts private paths/payloads.
No FakeVerifier or provenance override is used for successful authority tests.
Inherited deliberate negative metadata/schema monkeypatch tests remain; the
wrong-pin gate is additionally proven using a genuinely different installed
Matrix VCS distribution, without metadata or guard monkeypatching.

## TDD and evidence limits

`maintenance-red-namespace.log`: before production edits the test failed because
host and fleet used the SAME global fence class; full baseline parity passed.
The modern implementations were then composed wholesale (no new algorithm).
`maintenance-first-green-attempt.log`: 353 passed, 2 skipped, four failures
identifying old pin assertion, modern launcher assumption, absent rebirth fixture
and obsolete V2 fixture constant. Each is explicitly reconciled above.
`maintenance-green-boundary.log`: 95 passed after those adaptations.
`maintenance-http-first.log` and `maintenance-http-green.log` retain unsuccessful
fixture-authoring runs: expected exception class, missing required `limit`, then
wrong old HTTP route. These are NOT evidence of product defects or valid TDD RED
for a production change; only tests were corrected to existing contracts.
`maintenance-full-green.log` / XML: 360 passed, 2 skipped, strict ResourceWarning
and unraisable-warning gates. `maintenance-static-green.log`: exact declared
ruff/mypy versions and CI commands pass, plus compileall.

Python 3.13 used the supplied read-only `/tmp/dm132-real-pair-venv`, not a new
selective Matrix installation. `maintenance-dependency-parity.json` inventories
actual distribution and source hashes. `maintenance-genuine-wrong-pin.log`
records independent installed Matrix52945123 refusal. No production APIs were
contacted. Tests start only disposable localhost services and synthetic stores.
The runner suppresses only exact collection probe `[sudo, incus, list]`, returning
unavailable, and clears disposable Docker opt-ins; multiprocessing entry is
main-guarded. Two live Incus tests are honestly skipped. No actual Docker or Incus
operation was run. Python 3.11/3.12/3.14 hosted CI is unexecuted locally; unchanged
matrix remains a future CI gate. No unrelated lint refactor was attempted.

This is author composition/self-check, not independent review. Parent must
review this freeze, integrate reviewed V1 migration, regenerate exact hashes,
run future CI and resolve final release/custody/production gates before use.
