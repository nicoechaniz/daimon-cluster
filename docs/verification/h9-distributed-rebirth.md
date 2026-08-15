# H9 distributed fresh-embodiment verification receipt

Date: 2026-08-11. Candidate only; not deployed or independently reviewed.

## Exact boundary

- Cluster H9: `a53517178e9ed19b3392a739a793d1a1e0c39bdf`
  (draft PR #84, stacked on H8 PR #82).
- Matrix rebirth contract:
  `0a5fd3383aeb391488888d397a3d3296a71f98db`
  (draft PR #116).
- Physical hosts: `legion` and `daimonmatrix`, joined by their existing private
  ZeroTier network.
- Cluster issue: #83.

Both hosts checked the exact Cluster head. The fresh remote Python environment
verified the Matrix VCS commit from installed distribution metadata before
import. No production Cluster state, existing Matrix runtime, Incus instance,
installed release tree or live authority was used by the journey.

## Synthetic authority result

The ceremony created a new embodiment of one synthetic root-authorized being;
it did not copy an existing embodiment:

- being: `dm:being:v1:9PvxwDWwR-3Maz3qKFtmQvPWMR4dYbKpEyamAgITh-Q`;
- successor manifest:
  `938adfc2151f402f477bc43d1c6444919337de83b3ac46f767dd8bb50ab06240`;
- rollout:
  `dm:cluster-rebirth-rollout:v1:IFYaUEktqFHpEY9PGxAt7MdqVv2Fce-5p9T7u9ulYps`;
- target admission:
  `dm:cluster-rebirth-admission:v1:OnS4ZBOr0U3VJn_c4HR7cmwhboSmUpJpeo4dUbRnidg`;
- remote target embodiment:
  `embodiment:34e3d9fd-b4b0-4fef-a3dd-58a2213ff6eb`; and
- remote target incarnation:
  `incarnation:374ea896-9c06-403e-92dc-217493c62d8a`.

Bootstrap root custody and the two predecessor runtimes remained on Legion.
Target preparation and target custody occurred only on daimonmatrix. Legion
received the public preparation request and returned only root-signed public
authority. Daimonmatrix returned a closed public rollout; each predecessor
applied it locally, restarted with its unchanged custody and produced one
authenticated acknowledgement.

The target installed stopped. Its audit order was target install, exact
two-acknowledgement admission, then rebirth start. Startup reported
`running-ready`, integrity `ok`, the exact successor manifest and exactly the
target plus both predecessor embodiments as active. A duplicate acknowledgement
produced a byte-identical admission. Reapplying either completed predecessor
rollout returned `already-acknowledged` with the original operation ID.

## Custody and public boundary

Seven target-private files were checked: the password, preparation custody,
preparation transport custody, installed runtime custody, installed transport
custody and both target-local client capabilities. Every file was owner-only
and none of their SHA-256 byte identities occurred anywhere in Legion's
disposable tree. Daimonmatrix contained neither bootstrap root password nor
root custody.

The rollout, both acknowledgements and both admission renderings contained no
password, private, custody, secret, path or payload field. Target and
predecessor password bytes occurred zero times across every live process
`argv` and environment blob inspected. Passwords were delivered only through
inherited descriptors.

## Native convergence

The remote target authored event
`61c70cea-3a80-4c9e-9dd8-3ee9c561ab4e`; a Legion predecessor imported it once
and an exact prepared request replayed byte-identically. The predecessor then
authored event `705a1985-f9f3-4550-a3df-d4143657404a`, which the remote target
imported once. Both imported projections remained `pending`: transport did not
silently make an adoption decision. Subsequent pulls in both directions
reported zero new events.

Both ends finally reported the same being, successor manifest, non-partial
three-embodiment scope and integrity `ok`. The first replayed pull response had
SHA-256
`55659498a8a385e1074e44da76514adf122da4be821e9b7e3a7a94884e44d88d`.

## Gates and cleanup

```text
ruff: clean
mypy: clean
complete Cluster suite: 455 passed, 2 skipped
Cluster CI: Python 3.11, 3.12, 3.13 and 3.14 passed
Matrix package/conformance/Hermes/3.11-3.14 CI: passed
```

The focused suite covers wrong, missing, extra and duplicate acknowledgements,
partial-host recovery and response loss around peer operations. The physical
journey exercised the successful forward path and idempotent terminal replay.

All three disposable processes stopped cleanly and their three test listeners
closed. Only the two exact owner-local temporary roots were removed. The
installed `clusterd` on daimonmatrix remained active; the production fleet and
state were unchanged.

This receipt qualifies a release candidate. It does not authorize a live
being transition. A live rollout still requires the exact DM-078 preflight and
same-plan human GO, independent review of the stacked PRs, real root/recovery
custody policy and a later signed retirement transition for any removal.
