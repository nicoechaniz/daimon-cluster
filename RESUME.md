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

The current Matrix dependency is merged on `main` at
`09414d6edd9586f539be8272c4979d0b36c86b87`, tree
`d7146e291ae3f8313dc0b3d3c3a0b5e5f94d33ad`. Cluster pins that exact commit in
`requirements-weave.txt`, verifies `direct_url.json` at startup and has no
unpinned runtime fallback.

The current Cluster candidate functional boundary is
`4949a0c9c45bd4a277e54565ef0bdd7d476393c5`, tree
`a8b09afb70116bc90938e9f055c4623e0ca4cc86`. It contains the reviewed shared
admission/fencing, authenticated handoff and recovery/rebirth components plus
the final V7 snapshot, preflight and qualification corrections. This exact
successor still requires independent review before publication. Later
documentation or exact-pin commits do not change those semantics; the generated
RC manifest records the final repository head and tree.

Tribe Bridge transitional work is qualified on exact PR head
`418900a9d3732689d6a309336c467623637fe8d4`, tree
`d5b50379b1d9abe781ef92d0a50390559eed17c1`; its content-addressed source
boundary is `cd54865733c0b0200924dcd39213b7fcd7eb12ec`, tree
`7052ca5672fb56a14b826382f468fb38e19c50f0`. The exact head passed independent
review and supported-Python qualification, but PR #65 still requires its
independent human approval and normal merge. Tribe is not deployed and is not
Matrix intake or semantic-delivery authority.

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

1. Merge the exact reviewed Cluster successor and obtain clean CI on `main`.
2. Repin Tribe metadata to the final Matrix/Cluster merges, repeat its exact
   review and obtain the independently approved normal PR merge.
3. Run clean-install and supported-Python gates from the three exact final
   commits, then generate the content-addressed manifest and wheelhouses.
4. Keep Project/issues/PR receipts synchronized with the exact final hashes.

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
