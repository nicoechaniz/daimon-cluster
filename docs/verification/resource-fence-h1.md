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

The compatibility suite continues to cover park, wake, transfer and V1
fixtures. Production operations do not silently fall back to that backend.

## Reproduction

```console
python -W error::ResourceWarning -m pytest -q tests/test_production_fences.py
python -W error::ResourceWarning -m pytest -q
python -m ruff check clusterctl/fences.py clusterctl/production_fences.py \
  clusterctl/leases.py tests/test_production_fences.py
python -m mypy --follow-imports=skip --ignore-missing-imports \
  clusterctl/fences.py clusterctl/production_fences.py clusterctl/matrix_host.py
python -m compileall -q clusterctl clusterd steward_tools tests
```

No live host configuration or private key was copied into the evidence. The
candidate remains subject to independent review before merge or deployment.
