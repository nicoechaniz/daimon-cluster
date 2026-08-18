# Reproducible three-repository release-candidate freeze

`tools/build_rc_manifest.py` is the only supported freezer for the integrated
candidate. It reads three clean, non-shallow repositories, verifies Cluster's
exact Matrix Git dependency, proves that every qualified head descends from the
goal's exact commit/tree baseline and emits one canonical, content-addressed
JSON manifest. It does not publish a release, deploy software or contact a
host.

The separate qualification input must be canonical owner-only JSON with schema
`daimon-release-qualification/v2` and exactly these fields:

- `release`: the release-candidate version, for example `0.1.0rc1`;
- `supported_python`: an ordered, non-empty version list for each of
  `daimon-matrix`, `daimon-cluster` and `tribe-bridge`;
- `tests`: named pass/skip counts covering every declared Python version;
- `artifacts`: a non-empty, typed list for every component. Each exact release
  artifact has a unique relative path, byte size and SHA-256. Matrix requires
  one `git-bundle`, one structurally valid `python-wheel` and one structurally
  valid `python-sdist`; `runtime-lock` and `wheelhouse` are optional. Cluster
  and Tribe each require one `git-archive`, with the same two optional kinds.
  A kind may occur at most once per component. The freezer opens and hashes
  each regular file beneath the immutable artifact root and rejects missing
  component artifacts, links, replacement or mismatch;
- `artifact_receipts`: one closed `daimon-artifact-qualification/v1` receipt
  per component. It binds the exact commit/tree, source artifact, complete
  name/SHA-256 inventory and one network-disabled successful clean-install row
  for every supported Python version. Matrix rows use `vcs-direct-url`, while
  Cluster and Tribe rows use `git-archive`. Receipt inventory is sorted by
  artifact name and must equal the artifact list exactly;
- `evidence`: committed paths and SHA-256 values. The freezer reads those bytes
  from each exact component commit and rejects any mismatch;
- `limitations`: statements that remain true of the candidate; and
- `human_gates`: exactly the closed set for physical hosts/backup target,
  physical GO, live custody, cross-being consent, live Tribe participant
  contact, key generation/rotation, directory publication, provisioning and
  service/timer operations, publication/cutover and eventual Tribe retirement.
  The completed independent Tribe software approval is release evidence, not a
  remaining gate.

The source-artifact check is semantic rather than label-based:

- Cluster and Tribe `git-archive` bytes must equal the freezer's own unprefixed
  `git archive --format=tar <exact-commit>` bytes exactly;
- the Matrix `git-bundle` must expose only `<exact-commit> HEAD`, verify in an
  empty repository (therefore have no missing prerequisites), produce the
  exact component tree and pass strict full object-store fsck; and
- wheel/sdist containers are inspected without extraction or execution. They
  must be bounded, link-free package structures for `daimon-matrix`, with
  required package metadata.

Git inspection runs with ambient Git configuration and hooks disabled, and no
artifact content is checked out or executed. Initial goal baselines are
retained separately from the qualified component heads.

A receipt is a deterministic, machine-checked qualification statement: the
freezer proves all of its cross-references and closed values, but does not
re-run the installation while freezing. The test/evidence hashes must point to
the independently produced clean-install evidence. This avoids both executable
input and a self-referential manifest while keeping false artifact substitution
fail-closed.

The relevant shape is:

```json
{
  "artifacts": {
    "daimon-matrix": [
      {
        "bytes": 123,
        "kind": "git-bundle",
        "name": "source-bundle",
        "path": "daimon-matrix.bundle",
        "sha256": "<64 lowercase hex>"
      }
    ]
  },
  "artifact_receipts": {
    "daimon-matrix": {
      "schema": "daimon-artifact-qualification/v1",
      "commit": "<40 lowercase hex>",
      "tree": "<40 lowercase hex>",
      "source_artifact": "source-bundle",
      "artifacts": [
        {"name": "source-bundle", "sha256": "<64 lowercase hex>"}
      ],
      "installations": [
        {
          "python": "3.13",
          "network": "disabled",
          "result": "passed",
          "source": "vcs-direct-url",
          "installed_commit": "<same exact commit>",
          "installed_tree": "<same exact tree>"
        }
      ]
    }
  }
}
```

The abbreviated example omits the other required Matrix artifact rows, the two
other components and the qualification's remaining top-level fields.

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
