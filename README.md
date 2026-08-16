# daimon-cluster

`daimon-cluster` owns bodies, lifecycle, storage and concrete-resource
fencing for root-authorized Daimon embodiments. It hosts the exact pinned
`daimon-matrix` runtime; Matrix owns being identity, authority, canonical
events, `/me`, `/we` and semantic receipts. Tribe Bridge is a transitional
human-message transport and its ACK never substitutes for Matrix intake or
semantic delivery.

The release candidate assumes no current deployment. All qualification is
local or runs in disposable, network-disabled containers. Historical host
inventory and operational receipts remain under `docs/`, but they are not the
current architecture or evidence for this RC.

## Core invariants

- Generic containers do not manufacture Matrix identity.
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

Read [`RESUME.md`](RESUME.md) for exact commits, trees, completed evidence and
remaining gates. The normative architecture boundary is
[`docs/design/matrix-convergence.md`](docs/design/matrix-convergence.md); the
current threat model is
[`docs/security/threat-model-rc.md`](docs/security/threat-model-rc.md).

The complete unit/integration suite, exact Matrix pin check, lint, typing and
compile gates run in CI for Python 3.11–3.14. Separate jobs exercise:

- isolated recovery/rebirth with read-only two-file transfer; and
- encrypted backup export, offline repository verification and restore.

Those jobs prove software behavior on disposable infrastructure. They do not
prove live physical singleton, independent real custody or an authorized
cutover.

## Safety

No broad roadmap permission authorizes SSH, administrative access changes,
real custody, service mutation, production or external contact. Physical work
requires a reviewed content-addressed preflight and an exact GO for that same
plan. The production exclusion and administrative-access invariant in
[`AGENTS.md`](AGENTS.md) are binding.

## Development

Install the exact dependencies from `requirements-dev.txt` under
`constraints.txt`, then run:

```bash
python -m ruff check clusterctl clusterd steward_tools tests
python -m mypy --follow-imports=skip --ignore-missing-imports clusterctl clusterd
python -m pytest -q \
  -W error::ResourceWarning \
  -W error::pytest.PytestUnraisableExceptionWarning
```

The workflow contains the authoritative narrower lint/type file lists used by
the current baseline. Docker E2E tests are opt-in and must run only against
local disposable state.
