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
