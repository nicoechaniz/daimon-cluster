# Repository operating rules

Read `RESUME.md` before roadmap work. Preserve the exact reviewed RC pins and
the access/production boundaries recorded there. Historical deployed-pair
receipts are evidence only and do not authorize contact with those systems.

## Administrative-access invariant

Autonomous work in this repository must not modify an existing administrative
login path. This includes `root`, `debian`, `nicolas`, their SSH key files,
`sshd` admission, management firewall rules, console credentials and broad
sudo policy. A broad roadmap authorization, fast-forward request or permissive
execution mode is not authorization to cross this boundary.

Services that need SSH use a new, dedicated least-authority identity. Failure
or removal of that identity must leave every pre-existing administrative key
and session byte-for-byte unaffected. Repository executable assets are tested
to reject references to administrative SSH roots or `authorized_keys`.

An exceptional administrative-access change requires all of the following:

1. the user explicitly names the host, file/rule and exact intended mutation;
2. a reviewed, idempotent tool produces a content-addressed preflight and
   candidate; never use an inline redirection or an improvised remote command;
3. an independent recovery path and a timed automatic rollback are already
   proven;
4. an existing recovery session stays open while a second fresh session proves
   the old access still works; and
5. the rollback is cancelled only after owner/mode/hash, old access, new
   least-authority behavior and negative shell/forwarding checks all pass.

If any condition is missing, stop before mutation. See
`docs/incidents/2026-08-11-ssh-authorized-keys-lockout.md` for the incident that
established this invariant.

## Production-host exclusion

`mona` / `mona.altermundi.net` is a production server and is categorically out
of scope for this repository's experiments, rehearsals, backup targets,
restore drills, synthetic journeys, staging, probes and temporary files. Do
not connect to it for discovery or verification. Its presence in the user's
SSH inventory is not authorization. Only an exact future request from the
owner naming Mona and the production action can change this boundary; broad
roadmap or autonomous-work permission cannot.

All pre-production mirror and recovery work must run on local fixtures,
containers or purpose-created disposable hosts. Evidence from the invalid
2026-08-11 Mona rehearsal is incident evidence only and must not satisfy any
acceptance criterion.

## Live authority and review

Do not create Matrix root/embodiment custody, sign governance artifacts,
rotate Tribe keys, contact external participant hosts, merge a change that
requires independent review, or perform a live cutover without its recorded
consent/review and exact same-plan GO. Synthetic and disposable rehearsals may
proceed only when their cleanup and access boundaries are independently
testable.
