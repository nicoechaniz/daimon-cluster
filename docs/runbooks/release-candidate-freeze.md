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
  valid `python-sdist`; every component requires one `install-evidence`.
  `runtime-lock` and `wheelhouse` are optional. Cluster and Tribe each also
  require one `git-archive`. A kind may occur at most once per component. The
  freezer opens and hashes each regular file beneath the immutable artifact
  root and rejects missing component artifacts, links, replacement or
  mismatch;
- `artifact_receipts`: one closed `daimon-artifact-qualification/v1` receipt
  per component. It binds the exact commit/tree, source artifact, complete
  name/SHA-256 inventory and one network-disabled successful clean-install row
  for every supported Python version. Every installation row has an
  `evidence_ref` naming the component's external `install-evidence` artifact
  and exact SHA-256. Matrix rows use `vcs-direct-url`, while Cluster and Tribe
  rows use `git-archive`. Receipt inventory is sorted by artifact name and must
  equal the artifact list exactly;
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
- wheel/sdist containers are inspected without extraction or execution. Their
  complete package payload must equal the `src/daimon_matrix` blobs from the
  exact Matrix commit. Their build-input allowlist, license, project/version,
  console entry points and wheel RECORD must agree with the exact committed
  `pyproject.toml` and source bytes. Empty or metadata-only packages fail;

Git inspection runs with ambient Git configuration and hooks disabled, and no
artifact content is checked out or executed. Initial goal baselines are
retained separately from the qualified component heads.

A receipt is a deterministic, machine-checked qualification statement. Its
external `daimon-offline-install-evidence/v1` artifact binds component,
commit/tree, source artifact/hash, the exact name/hash inventory of every
other installation input, platform and every supported Python. The evidence
also names the exact Cluster commit containing the qualifier contract; the
artifact itself is deliberately excluded from its input list. Each row must
say network disabled and result passed and carry the closed probe set
(`import`, `installed-metadata`, `smoke`, plus Matrix's
`direct-url-commit`), with a SHA-256 of every probe output. The freezer hashes
and parses this canonical JSON, then cross-checks the receipt row byte for byte
against it. The evidence artifact does not name its own hash or the final
manifest, so it can be produced after installation without changing a
repository head or creating a self-reference.

This evidence is immutable and non-trivially structured, but remains an
attestation from `daimon-rc-offline-qualifier/v1`: the freezer does not re-run
the installation. Clean disposable qualification must produce it, and review
must inspect the commands/environment separately. No synthetic receipt proves
a physical install.

The external evidence artifact has this closed form (probe output hashes are
hashes of the qualifier's captured machine output, not free-form notes):

```json
{
  "schema": "daimon-offline-install-evidence/v1",
  "producer": "daimon-rc-offline-qualifier/v1",
  "producer_commit": "<exact Cluster commit>",
  "component": "daimon-matrix",
  "commit": "<exact Matrix commit>",
  "tree": "<exact Matrix tree>",
  "source_artifact": "source-bundle",
  "source_sha256": "<bundle hash>",
  "inputs": [{"name": "source-bundle", "sha256": "<bundle hash>"}],
  "platform": "linux-x86_64-glibc>=2.34",
  "installations": [
    {
      "python": "3.13",
      "network": "disabled",
      "result": "passed",
      "source": "vcs-direct-url",
      "installed_commit": "<exact Matrix commit>",
      "installed_tree": "<exact Matrix tree>",
      "probes": [
        {
          "name": "direct-url-commit",
          "result": "passed",
          "output_sha256": "<64 lowercase hex>"
        }
      ]
    }
  ]
}
```

The example abbreviates the exact input inventory, supported-Python rows and
required probe list; a real artifact omitting them is rejected.

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
          "installed_tree": "<same exact tree>",
          "evidence_ref": {
            "artifact": "install-evidence",
            "sha256": "<hash of external canonical install evidence>"
          }
        }
      ]
    }
  }
}
```

The abbreviated example omits the other required Matrix artifact rows, the two
other components and the qualification's remaining top-level fields.

`tools/build_physical_preflight.py` independently requires this complete v2
qualification shape. It rejects a manifest with artifacts alone, a missing
required source/build/evidence kind, or a receipt whose commit, tree, inventory
or evidence-artifact reference does not match the frozen component rows.

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
