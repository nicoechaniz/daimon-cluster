# Reproducible three-repository release-candidate freeze

`tools/build_rc_manifest.py` is the only supported freezer for the integrated
candidate. It reads three clean, non-shallow repositories, verifies Cluster's
exact Matrix Git dependency, proves that every qualified head descends from the
goal's exact commit/tree baseline and emits one canonical, content-addressed
JSON manifest. It does not publish a release, deploy software or contact a
host.

The separate qualification input must be canonical owner-only JSON with schema
`daimon-release-qualification/v1` and exactly these fields:

- `release`: the release-candidate version, for example `0.1.0rc1`;
- `supported_python`: an ordered, non-empty version list for each of
  `daimon-matrix`, `daimon-cluster` and `tribe-bridge`;
- `tests`: named pass/skip counts covering every declared Python version;
- `artifacts`: optional non-source artifacts with a unique relative path, exact
  byte size and SHA-256. The freezer opens and hashes each regular file beneath
  the immutable artifact root and rejects links, replacement or mismatch;
- `evidence`: committed paths and SHA-256 values. The freezer reads those bytes
  from each exact component commit and rejects any mismatch;
- `limitations`: statements that remain true of the candidate; and
- `human_gates`: exactly the closed set for physical hosts/backup target,
  physical GO, live custody, cross-being consent, independent Tribe approval,
  publication/cutover and eventual Tribe retirement.

Source archives are generated directly with `git archive`; their size and
SHA-256 are calculated by the freezer. Initial goal baselines are retained
separately from the qualified component heads.

Freeze only after all three exact candidates are independently reviewed and
their worktrees are clean:

```bash
python tools/build_rc_manifest.py \
  --matrix /path/to/clean/daimon-matrix \
  --cluster /path/to/clean/daimon-cluster \
  --tribe /path/to/clean/tribe-bridge \
  --qualification qualification.json \
  --artifact-root /path/to/owner-controlled/artifacts \
  --output daimon-v0.1.0rc1.json
```

The output path and its parent must already satisfy separate conditions: the
file must not exist, while the parent must exist as an owner-controlled real
directory with no symlink component. The freezer never creates missing parent
directories and never follows a linked parent. The printed SHA-256 addresses
the exact manifest bytes. Repeating the command over the same commits and
qualification input produces identical bytes; a changed repository, evidence
file, test claim, artifact, limitation or gate produces a different result.

The final manifest is a release artifact. Creating it is automated; publishing
or cutting over to it remains a human gate. Until that publication gate is
crossed, repository receipts may describe candidates but must not call
themselves the final integrated manifest.
