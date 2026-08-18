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
  Every component also requires its complete `wheelhouse`; Matrix may carry a
  `runtime-lock`. Cluster and Tribe each require one `git-archive`, and Cluster
  additionally requires a `matrix-git-bundle` for the exact commit pinned in
  `requirements-weave.txt`. A kind may occur at most once per component. The
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

A receipt is a deterministic, machine-replayed qualification statement. Its
external `daimon-offline-install-evidence/v1` artifact binds component,
commit/tree, source artifact/hash, the exact name/hash inventory of every
other installation input, platform and every supported Python. The evidence
also names and hashes `tools/qualify_offline.py` from the exact Cluster commit;
the
artifact itself is deliberately excluded from its input list. Each row must
say network disabled and result passed and carry the closed probe set
(`import`, `installed-metadata`, `smoke`, `dependency-check`, plus Matrix's
`direct-url-commit`, `wheel-install` and `sdist-install`), with a SHA-256 of
every probe output. The freezer hashes and parses this canonical JSON, rebuilds
the closed execution plan from repository and artifact facts, reruns every
installation in a fresh sandbox, and requires byte-identical canonical
evidence. The evidence artifact does not name its own hash or the final
manifest, so it can be produced after installation without changing a
repository head or creating a self-reference.

`tools/qualify_offline.py` is the only producer. It accepts a closed canonical
`daimon-offline-qualification-plan/v1`, snapshots every verified artifact by
descriptor, and runs with bubblewrap `--unshare-all --clearenv`. The sandbox
mounts only the selected interpreter prefix, system runtime directories, the
public CA bundle, private `/dev` and `/proc`, a tmpfs `/tmp`, and its disposable
work directory. It has no host home or `/run`, and every subprocess has a
bounded timeout. Interpreter paths are trusted operator inputs outside the
qualification JSON. Native interpreter binaries and every prefix parent must be
root/owner-controlled; group-writable paths are accepted only when the group is
provably the owner's single-member primary group. The freezer CLI requires repeatable
`--python COMPONENT:VERSION=/absolute/python` arguments for a multi-version
candidate. Evidence cannot select an executable or command.

The trust boundary is the local Linux kernel, bubblewrap binary, selected
CPython binaries/prefixes, mounted system runtime bytes and CA bundle. Their
relevant paths and hashes are captured in the replay transcript. This is
reproducible local installation evidence, not remote attestation or physical
host evidence. No signing key or unverifiable producer claim substitutes for
replay.

The external evidence artifact has this closed form (probe output hashes are
hashes of the qualifier's captured machine output, not free-form notes):

```json
{
  "schema": "daimon-offline-install-evidence/v1",
  "producer": {
    "name": "daimon-rc-offline-qualifier/v1",
    "commit": "<exact Cluster commit>",
    "path": "tools/qualify_offline.py",
    "sha256": "<committed tool blob hash>"
  },
  "component": "daimon-matrix",
  "commit": "<exact Matrix commit>",
  "tree": "<exact Matrix tree>",
  "source_artifact": "source-bundle",
  "source_sha256": "<bundle hash>",
  "inputs": [{"name": "source-bundle", "sha256": "<bundle hash>"}],
  "platform": {"machine": "x86_64", "system": "Linux"},
  "installations": [
    {
      "python": "3.13",
      "network": "disabled",
      "result": "passed",
      "source": "vcs-direct-url",
      "installed_commit": "<exact Matrix commit>",
      "installed_tree": "<exact Matrix tree>",
      "interpreter": {
        "base_prefix": "/trusted/python/prefix",
        "executable": "/trusted/python/prefix/bin/python3.13",
        "executable_sha256": "<64 lowercase hex>",
        "implementation": "CPython",
        "version": "3.13",
        "version_full": "3.13.x"
      },
      "execution": {
        "sandbox": "bubblewrap-unshare-all",
        "exit_code": 0,
        "contract_sha256": "<64 lowercase hex>",
        "ca_bundle_sha256": "<64 lowercase hex>",
        "sandbox_executable": "/usr/bin/bwrap",
        "sandbox_sha256": "<64 lowercase hex>",
        "stdout_sha256": "<64 lowercase hex>",
        "stderr_sha256": "<64 lowercase hex>"
      },
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

For each component, create an owner-only canonical plan whose
`artifacts` rows name the exact kind, absolute source path and SHA-256; whose
`repository`, commit and tree identify the clean candidate; whose `python`
rows contain the separately selected version/executable pairs; and whose
`cluster_repository`/`producer_commit` identify the commit containing this
tool. Cluster's plan additionally supplies the exact Matrix commit/tree as
`matrix_dependency` and includes its `matrix-git-bundle`. Then produce the
external artifact without overwriting an existing path:

```bash
python tools/qualify_offline.py \
  --plan /owner-only/plans/daimon-matrix.json \
  --output /owner-only/artifacts/daimon-matrix-install-evidence.json
```

Run the same closed command for Cluster and Tribe. Repeating it with identical
inputs must produce identical bytes. The later freezer replay is mandatory;
successful standalone production is not acceptance by itself.

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
  --python daimon-matrix:3.11=/trusted/python/3.11/bin/python3.11 \
  --python daimon-cluster:3.11=/trusted/python/3.11/bin/python3.11 \
  --python tribe-bridge:3.10=/trusted/python/3.10/bin/python3.10 \
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
