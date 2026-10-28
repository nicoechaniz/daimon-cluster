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
rotate Tribe keys, contact external participant hosts, or merge a change that
requires independent review without the applicable recorded authorization.

Nicolas clarified on2026-10-28 that an already-authorized task includes its
routine scoped deployment and repair. Do not demand another same-plan GO when
the existing request already authorizes the intended result. Prepare and verify
the concrete change, choose the appropriate activation time, preserve actual
resource grants, configuration/state, conversations and a practical rollback,
and observe receiving behavior. Ask only for a genuinely new scope, authority
or missing human decision. This clarification does not authorize changes to
custody, credentials, administrative access, production-host exclusions or a
coordinated global Stop; their explicit consent requirements remain in force.
Synthetic/disposable rehearsals must retain testable cleanup/access boundaries.

## Tribe group invariant — human correction, 2026-10-13

A Tribe conversation is one group whose audience is resolved from signed membership
at send time. It is not a complete mesh of bilateral channels or a set of separate
founder/member pairs. Joining the Tribe must enable participation without per-pair
onboarding. Telegram Tribu is the human-visible projection, not proof that a Matrix
group channel is enabled. Source-to-each-member delivery does not prove that all
members can converse as a group. A missing group channel is a deployment gap.

Use the membership-based group for same-Tribe collaboration. Keep bilateral lanes
for deliberately directed conversations and explicitly requested temporary repairs;
never expand a temporary pair repair into the default group architecture. Preserve
existing history, but do not treat old pair-enrollment instructions as the current
onboarding design. The normative source is `specs/tribe-conversation.md`; #151/#198
own the group-channel completion. No alternate transport or autonomous attention is
implied by this rule. A global Stop always requires fresh explicit human consent.
