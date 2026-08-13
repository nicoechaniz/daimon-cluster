# H7 fresh-embodiment verification receipt

Date: 2026-08-11. Candidate only; not deployed or independently reviewed.

## Exact boundary

- Cluster base: integration PR #78 head
  `a2de10be5ec359925b096c217afa9fbb2bfa7118`.
- Matrix fresh-embodiment contract:
  `0a5fd3383aeb391488888d397a3d3296a71f98db` (Matrix draft PR #116).
- Cluster issue: #79.

Cluster verifies the installed Matrix source commit through distribution
metadata before importing the rebirth API. No fallback enrollment parser or
signer exists in Cluster.

## Local gate

The focused suite constructs a disposable two-embodiment being, creates fresh
target custody, authorizes only its public request with offline root custody,
activates a V7 target package, and installs it through Cluster. It proves:

- a loadable target with an empty ledger and the root-authorized origin;
- exact forward update of both old peers and retention of authority history;
- stopped Cluster admission and a separately installed host client;
- exact replay under a new caller key and under two concurrent callers;
- recovery after plan, dispatch, target install, first peer update, runtime
  observation, registry commit, audit and completed-response loss;
- one journal row and one audit event after every retry path; and
- pre-mutation refusal of an incomplete peer set or tampered receipt.

Current focused result:

```text
ruff: clean
mypy: clean
pytest tests/test_rebirth.py: 13 passed
complete Cluster suite: 449 passed, 2 skipped
```

The four-version CI matrix and an isolated remote process drill remain release
gates. No live Incus instance, installed service, production state root,
authority custody or root manifest was changed by this receipt.
