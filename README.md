# daimon-cluster

`daimon-cluster` owns bodies, lifecycle, storage and concrete-resource
fencing for root-authorized Daimon embodiments. It hosts the exact pinned
`daimon-matrix` runtime; Matrix owns being identity, authority, canonical
events, `/me`, `/we` and semantic receipts. Tribe Bridge is a retired historical
experiment and absent from the current runtime: Cluster neither
installs it, creates its keys, opens its broker route nor offers a fallback.
Matrix's native tribe/relationship governance is a separate semantic feature.

Current three-VPS membership-group deployment and exact receiving evidence are
recorded in [RESUME.md](RESUME.md). Its dated RC evidence remains separate from
that live state. The reviewed three-repository freezer reproduces historical
RC qualification only; it does not select a current runtime or require Bridge.

## Core invariants

- Generic containers do not manufacture Matrix identity.
- The removed legacy `clusterctl provision` path cannot mint Bridge identity;
  new embodiments use the root-authorized Matrix/Cluster birth and rebirth
  ceremonies.
- Each embodiment has root-authorized credentials, a distinct incarnation and
  fresh private custody. Creating a new embodiment is not cloning a private
  database, key store or writable runtime.
- Multiple authorized embodiments of one being may run concurrently. Shared
  admission prevents two physical launches of the same embodiment credential.
- CAS/TTL fences exclude stale writers only for the same concrete resource.
- Runtime mutations require enrolled holder authorization and fail before
  adapter/storage effects when authority is absent, stale or revoked.
- Recovery transfer contains only the manifest-bound public runtime bundle and
  canonical ledger events. Client keys, custody and journals do not cross it.
- Host status and curator clients are separate least-authority capabilities;
  neither is an operator signer oracle.

## Current state

Read [`RESUME.md`](RESUME.md) for current selections and remaining work, and
[Matrix current architecture/profiles](https://github.com/AlterMundi/daimon-matrix/blob/main/docs/current-architecture.md)
for the shared navigation index. Dated verification and old provisioning pages
retain history; they are not present installation instructions. The normative architecture boundary is
[`docs/design/matrix-convergence.md`](docs/design/matrix-convergence.md); the
current threat model is
[`docs/security/threat-model-rc.md`](docs/security/threat-model-rc.md).

The complete unit/integration suite, exact Matrix pin check, lint, typing and
compile gates run in CI on Python 3.13.5, matching the deployed host and
receiving containers. Onboarding changes run every onboarding test plus the
existing authority, registry, API and access contracts. Workflow-only changes
test the workflow and selector; shared or unrecognized changes run the full
suite. Manual workflow runs also select the full suite. Timings identify slow
checks, and superseded runs are cancelled. Separate runtime jobs exercise:

- isolated recovery/rebirth with read-only two-file transfer; and
- encrypted backup export, offline repository verification and restore.

Those jobs prove software behavior on disposable infrastructure. They do not
prove live physical singleton, independent real custody or an authorized
cutover.

## Authorized operation

An authorized task includes its routine scoped deployment and repair; it does
not require another same-plan GO. Use the current receiving binding, preserve
identity, live data, active work and a practical rollback, then verify the
changed behavior. Start routine SDK updates with the
[short maintenance path](docs/runbooks/tribu-sdk-successor.md#routine-maintenance-path).

Administrative access, custody/governance changes, the production-host
exclusion and coordinated global Stop retain their explicit boundaries in
[`AGENTS.md`](AGENTS.md). Routine software authorization does not expand them.

## Development

Install the exact dependencies from `requirements-dev.txt` under
`constraints.txt`, then run:

```bash
python -m ruff check clusterctl clusterd steward_tools tests
python tools/check_rc_types.py
python -m pytest -q \
  -W error::ResourceWarning \
  -W error::pytest.PytestUnraisableExceptionWarning
```

`tools/check_rc_types.py` is the single authoritative type-check file list used
by both this command and CI. Docker E2E tests are opt-in and must run only
against local disposable state.

## Daimon Field coordination

Cross-repository decisions and repository-specific implications are indexed in
[the Daimon Field projection](docs/daimon-field.md). The existing private
[AlterMundi Project 13](https://github.com/orgs/AlterMundi/projects/13) is the canonical decision and roadmap surface;
repository access and Project access are separate.
