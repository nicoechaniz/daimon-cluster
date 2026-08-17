# Daimon V0 release-candidate checkpoint

Last reconciled: 2026-08-16.

This repository is not deployed from the candidate described here. No existing
host, service, access path, real custody or production state is part of the
qualification. All destructive tests use owner-only temporary state or
network-disabled disposable containers.

## Exact baseline and forward boundary

The goal began from these merged V0 baselines:

- Matrix `e855148ffac5b2f4068ba56be6324d7b78fb430f`, tree
  `be24a07fd387c9fe10331b17507904f14f66ea71`;
- Cluster `734fd0037dcf84783ef7991415014af7435a46f2`, tree
  `317d76bada51741dd3fcd40b7edbb3120b3393a6`;
- Tribe Bridge `187c61d881e6de830a029027144193645f2c7f62`, tree
  `84da16611be62581d9a049d9f567652c4cc4e61b`.

The qualified Matrix functional merge is
`09414d6edd9586f539be8272c4979d0b36c86b87`, tree
`d7146e291ae3f8313dc0b3d3c3a0b5e5f94d33ad`. The prepared documentation
successor is `8262e1ee5ab2f0b1a389a911b206cac94b823618`, tree
`8daf4c99192a8f797d60f36f049a832761304082`; Cluster pins that exact full
commit in `requirements-weave.txt`, verifies `direct_url.json` at startup and
has no unpinned runtime fallback. This local pin becomes publishable only after
the Matrix successor reaches its protected default branch unchanged.

The current Cluster functional merge is
`820e3792a227b1848681a3421b113e8822c8d08a`, tree
`4f62eb4f6eff1dfafbd477339a86fa7d5e70a5d8` (PR #93). It contains the
independently reviewed shared admission/fencing, authenticated handoff,
recovery/rebirth, V7 snapshot, preflight and qualification corrections. Later
documentation or exact-pin commits do not change those semantics; the
generated RC manifest records the final repository head and tree.

Tribe Bridge transitional work is qualified on exact PR head
`42d637245864fcd431198a570d19d7a6dd042924`, tree
`5145f6446f3ec3013347509477a262f98825ebfa`; its content-addressed source
boundary is `9c4f14f613657ea1e6e6c1805d4f869ae93d082f`, tree
`38361d248866a84a6e4a45a2d83af56e7c549f66`. The exact head passed
independent adversarial review, 124 tests on Python 3.10–3.13 and protected CI;
PR #65 still requires independent human approval and normal merge. Tribe is
not deployed and is not Matrix intake or semantic-delivery authority.

## What is automated and proven

- Matrix recovery holders keep one key per encrypted store/process; holders
  emit partial artifacts and a keyless aggregator verifies threshold,
  duplicates, expiry and revocation. Centralized ceremonies are explicitly
  synthetic fixtures only.
- Runtime authority is split into ten disjoint operator profiles plus separate
  five-method host status and four-method host curator profiles. All twelve
  rows are covered by the active embodiment's signed runtime binding.
- Cluster admission is shared, signed and CAS-based across state directories.
  It distinguishes being root, `embodiment_id`, incarnation and ephemeral
  session. The same embodiment credential cannot win two concurrent launches;
  distinct root-authorized embodiments of one being remain legitimate.
- Resource-fence mutation uses enrolled holder keys, trusted time, bounded
  TTLs, exact prepared successors, fresh proof of possession and crash-safe
  release recovery. Park/wake/transfer fail before effects when authorization
  is missing or revoked.
- A fresh embodiment receives new root-authorized identity and fresh private
  custody. The distinct recovery-snapshot contract contains only the public
  runtime bundle and canonical ledger; predecessor keys, client capabilities,
  writable databases and journals are not copied, and the generic full restore
  rejects that derivative.
- V7 snapshots require the complete canonical twelve-profile table and exclude
  root, operator and host client material unconditionally. Incomplete,
  duplicated, relabelled or unsafe layouts fail before a destination exists.
- The complete Cluster suite passes with ResourceWarning and unraisable-warning
  failures enabled. The network-disabled recovery/rebirth container journey
  and the independent encrypted backup/export/offline-restore journey pass.

Current qualification evidence lives in
`docs/verification/rc-recovery-rebirth-2026-08-16.md`. Older verification files,
inventory and incident documents are historical evidence; their hosts, hashes
and test counts are not the current RC baseline.

## Remaining automated work

1. Obtain the protected Tribe PR #65 approval and merge.
2. Publish the reviewed Matrix documentation successor, then merge this exact
   Cluster repin/documentation successor through normal review.
3. Repin Tribe metadata once to those final Matrix/Cluster heads.
4. Run clean-install and supported-Python gates from the three exact final
   commits, generate the final content-addressed manifest and keep tracking
   synchronized with its hashes.

## Human and external gates

The following cannot be inferred from local tests or broad authorization:

- independent GitHub approval where branch protection requires it;
- selection of purpose-built non-production hosts and an independent backup
  target, followed by an exact GO for one content-addressed physical preflight;
- assignment of real independent root/recovery holders and live custody;
- consent, independent custody and contact authorization for the other being in
  the cross-being Matrix canary;
- any Tribe key rotation, directory publication, participant provisioning,
  service/timer change or external contact;
- publication, cutover and eventual Tribe retirement/archive decisions.

## Absolute boundaries

- Mona is excluded from resolution, connection, scanning, targeting and new
  evidence.
- Do not modify SSH, `authorized_keys`, administrative accounts, sudoers,
  firewalls, real keys, custody, services or production.
- No physical infrastructure action is authorized without a reviewed
  content-addressed preflight and an exact GO for that same plan.
- Synthetic evidence must never be described as physical singleton or live
  distributed custody evidence.

Resume from the first unfinished automated item above. Read `AGENTS.md` before
any action and preserve every access/production exclusion there.
