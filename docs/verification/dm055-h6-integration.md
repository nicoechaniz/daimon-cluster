# DM-055 plus DM-031/H1-H6 integration receipt

Date: 2026-08-11. Candidate only; not deployed or independently reviewed.

## Exact boundary

- H6 stack head: `26fcfafdf2721440563aff428614adfba2cc471e`.
- DM-055 branch head: `b719cbbc7fa79d28a94263997d091f1f1bb06daf`;
  runtime code `94d80baca05f468287b7d2bf99c577350d654a36`.
- Matrix dependency: `915c56c8899fd53d683bd7c7c81c3465b600bed9`.
- Provider: `cf56e9de703f68f44b85fdf21f503d55a5557984`.
- HMK: `f10fd5c3089c0962920314c97e14bc024feffa7a`.

The semantic merge retains every DM-031 curator, memory-projection and
publication contract check and adds the exact five-method DM-055 status
observer check. The H4 bounded read model V2 remains canonical; the older
empty unconfigured response was not reintroduced. No route was enabled and no
live service, state root, Wiki, HMK database or provider target was changed.

## Clean automated gate

The candidate was installed in a fresh Python 3.13 environment directly from
the exact Matrix Git pin. `direct_url.json` and MIT package metadata matched.

```text
focused parity/clusterd/operational gate: 58 passed
complete Cluster suite: 436 passed, 2 skipped in 61.18s
ruff boundary lint: clean
mypy boundary type check: no issues in 10 source files
compileall: clean
git diff --check: clean
```

Tests reject a wrong Matrix commit, a missing V7/client-V2 contract, substituted
curator schemas, expanded curator worker authority and any changed status
observer method set before the host boundary opens.

## Real-storage drills

Detached exact provider and HMK worktrees ran under temporary roots. The H5
drill verified exact replay, atomic rebuild, SQLite snapshot/restore and peer
independence. The H6 drill verified exact provider plan/replay, fresh effect
reconciliation, two-publisher refusal and preservation of an unrelated target.
All effect roots were temporary and removed by the drills.

The publisher correctly rejected checkouts created with a group-writable umask.
After removing group write from only the temporary checkout roots and audited
files, the exact same commits passed. This was the intended custody gate, not
a source or protocol substitution.

## Remaining gate

Push this integration-only candidate for CI and independent review. Do not
deploy or merge it merely from this receipt. A live DM-034/DM-035 canary still
requires current source intent, production fence, explicit consent and a
separate human review over the exact final bytes; this receipt supplies none of
those authorities.
