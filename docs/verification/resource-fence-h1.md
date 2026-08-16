# H1 production resource-fence verification

Issue: #64. Candidate branch: `issue-64-production-fences`.

## Executable coverage

`tests/test_production_fences.py` exercises the production backend with real
Ed25519 keys and real SQLite processes:

- exact body/embodiment/incarnation/resource/operation/key/position binding;
- invalid signatures, fingerprints, future authorization/observation, expiry,
  holder revocation, signer rotation and signer revocation;
- eight concurrent same-resource processes with exactly one winner;
- concurrent different-resource acquisition without resource conflict;
- a concurrent renew/release race with one signed winner;
- process termination before begin, after begin, before commit and after
  commit, followed by restart and position verification;
- a forced failure on the second transactional write (disk-full analogue),
  proving current record and high-water roll back together;
- release tombstones, monotonic reacquire and refusal of byte restore;
- explicit offline retirement of expired V1 synthetic fixtures;
- the unchanged Matrix verifier and the real curator daemon process consuming
  a verifier-only production store, with no signing custody, for a fenced
  claim/effect refusal and exact response-loss replay.

`tests/test_handoff_production.py` now covers park, wake and transfer through
the shared authority with an enrolled holder, real Ed25519 manifest/evidence
signatures and an exact prepared CAS successor. Production handoff commands
never open the authority SQLite database and never select the V1 fixture.
`FakeSigner`, `SSHSigner` and the file store remain test-fixture surfaces only.

Missing configuration, a fake/unregistered holder, a revoked holder, replay or
a wrong predecessor position refuses before any adapter call or spec write.
The former `--no-fence` assertion was removed: a handoff is accepted only with
authority-signed current evidence for the exact holder and resource.

## Reproduction

```console
python -W error::ResourceWarning -m pytest -q tests/test_production_fences.py
python -W error::ResourceWarning -m pytest -q tests/test_handoff_production.py \
  tests/test_admission.py
python -W error::ResourceWarning -m pytest -q
python -m ruff check clusterctl/fences.py clusterctl/production_fences.py \
  clusterctl/admission.py clusterctl/handoff_auth.py clusterctl/park.py \
  clusterctl/transfer.py tests/test_production_fences.py \
  tests/test_admission.py tests/test_handoff_production.py
python -m mypy --follow-imports=skip --ignore-missing-imports \
  clusterctl/fences.py clusterctl/production_fences.py clusterctl/admission.py \
  clusterctl/handoff_auth.py clusterctl/park.py clusterctl/transfer.py
python -m compileall -q clusterctl clusterd steward_tools tests
```

No live host configuration or private key was copied into the evidence. The
candidate remains subject to independent review before merge or deployment.

On 2026-08-16 the production handoff wiring passed 127 focused tests and the
complete Cluster/Matrix V0 suite: 534 passed, 4 intentional skips. Ruff, mypy,
compileall and `git diff --check` were clean. This is local pre-release
qualification only: no host, SSH path, physical shared resource or deployment
was exercised or claimed.

## Candidate result

On 2026-08-10, the stacked DM-031/H1 candidate passed 50 focused Matrix/fence
tests and the complete suite: 324 passed, 2 intentional skips. Focused ruff,
mypy, compileall and `git diff --check` were clean. The multiprocess race/crash
subset also passed five consecutive repetitions after fixing a WAL-sidecar
disappearance race in the security-mode check.
