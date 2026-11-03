# Admitted native surface observation

The foundation's `/here` selects daimons sharing an embodiment surface. Tribe
membership, a signed host label and physical hypervisor colocation do not prove
that relationship. In the native Linux domain, the surface is the current OS
instance. CompAII on ITACA and Oliva in its full KVM therefore have distinct
surfaces even though they use the same physical server.

The existing inherited parent observation socket accepts a `kind: surface`
request alongside the unchanged body request. The exact body, incarnation and
evaluation time are required. Both H8 and relocated native parents reuse the
same current-presence and admission checks. An expired/released lease, foreign
origin or unknown kind cannot yield a surface. No holder custody, network
listener, resource grant, writable fence or model turn is created.

`connected_body_reader` remains the original callable body reader and now exposes
`.surface` with the same four arguments. Both methods serialize through one
lock on the existing bounded socket. The response is
`dm.cluster-surface-snapshot/v1`: exact body/embodiment/incarnation, observation
time, `state`, `domain: native-linux-os` and a `surface_ref`. The reference is a
purpose-separated SHA256 of the local machine and kernel boot identities. Neither
identifier leaves the parent. Including boot identity distinguishes OS instances
cloned from an image with an accidentally identical machine ID. A reboot changes
the reference; callers must obtain fresh observations rather than treating it as
an eternal host identity or an inheritance relation.

This is a Cluster observation primitive, not a completed Matrix scope resolver.
Matrix must validate the response and compare fresh observations in the selected
domain, retaining unavailable/unknown participants explicitly. An operator's
selected cohort is not proof of a complete Cluster or `/everyone` roster.
Geographic `/near`, world-specific surfaces and realm controls require their own
actual domain evidence. No distance, authority or membership is inferred here.
Source availability does not establish receiving deployment or live `/here`
acceptance; those belong in the existing Matrix #437 checkpoint.

## Explicit admitted surface census

The optional `surface-inventory` parent observation reuses that same channel and
actual local OS calculation. The child supplies only its original identity and
evaluation time; it cannot substitute a surface descriptor. The parent reports
its opaque native OS reference through the existing signed admission session.
The canonical authority returns `dm.cluster.admission-surfaces/v1`, with the
ordinary bounded admission inventory and an optional `surface` on each member.

Reports are authenticated launch declarations (`evidence: admitted-launch-report`),
not independent remote physical attestation or permission to control a machine.
The authority joins each report to the exact current lease's launch session in
the same verified inventory snapshot. Release, expiry, replacement or revocation
cannot transfer an old declaration to a new launch. Ordinary renewal preserves
the same OS instance and its report. No session identifier leaves the authority.

Only an explicit census request reports a surface. No heartbeat, timer, message,
peer wakeup, lease mutation or durable metadata store is added. The authority
keeps at most256 volatile reports (one per admission resource), each containing
only the session reference, fixed native domain, opaque SHA256 reference and
report time. Oldest reports are evicted at capacity; process exit drops them all.
A missing declaration remains unknown, including after authority restart. It
must never be interpreted as a different surface or a complete negative match.
Matrix may compare reported surfaces with its actual current own-body surface;
unknown reports or a truncated admission scan require an explicitly partial
`/here` result. Existing `/all` inventory responses remain unchanged.
