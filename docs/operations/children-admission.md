# Children's physical admission

Keep Matrix identity, physical holder enrollment, a running canonical admission,
Tribe membership and human application acceptance separate. A signed public
identity or registrar profile alone proves none of the later stages.

Use the existing `FirstCustody.admission_coordinates`, target
`admission-prepare`, `onboarding_admission.profile` and target
`admission-enroll`/`admission-check` operations. Each receiving holder creates
its own physical key in its own virtual machine. The registrar receives the
public holder/proof and verified native coordinates; its private key stays at
the existing central authority. Preserve each existing Matrix identity and
physical holder key. Never replace an uncertain enrollment with a new identity.

The central profile operator must select code that validates the exact approved
plan, including optional resource limits. Retain its qualified public source
and reuse the existing dependency environment; do not remove fields from the
plan or change the shared running worker just to sign one profile.

Proof-of-possession requests expire after 60 seconds and default registrar
enrollments after five minutes. Prepare, validate, sign, transfer and enroll in
one finite operation once the receiving route is ready. If a known-unattempted
profile expires, obtain a fresh proof from the SAME preserved holder and sign a
fresh profile; retain the prior artifact and its expired/unattempted status.
An uncertain network result instead requires the maintained enrollment check,
not another identity, key or blind request replay.

## Existing authority over the selected network

When the selected central authority is already reachable on the host's private
network, reuse it. The maintained `children-cluster-admission.socket` listens
only on the children's host loopback. The matching standard systemd relay
forwards to the operator-selected existing authority, without creating another
authority, registry, credential store, chat transport or model process.

The private root-owned `admission-proxy.env` supplies exactly the selected
`CLUSTER_ADMISSION_ENDPOINT=ADDRESS:PORT`. A root-owned service drop-in must
allow that exact address with `IPAddressAllow=ADDRESS/PREFIX`; the base unit
denies other network addresses except loopback. Do not place private addresses,
keys or tokens in source. Verify the installed binary's supported flags, unit
syntax, destination restriction and actual signed admission responses on the
receiving host. A listening socket is not end-to-end acceptance.

For each approved local Incus body, reuse the existing `onboarding-admission`
proxy contract: instance-bound guest loopback to host loopback, using the
profile's selected port. Preserve any conflicting device rather than replacing
it. This exposes only that fixed admission service and gives the guest neither
the Incus socket nor host files, administrator credentials or other resources.
The existing signed holder/authority protocol still authorizes each request.

The relay has at most 16 connections, 64 descriptors, 32 MiB memory, 10% CPU and
16 tasks. It exits after five idle minutes; socket activation remains available.
Use the already bounded host journal. Qualification must distinguish idle
standby, running relay, unreachable destination and refused signatures.

Disable future activation by stopping/disabling only this socket. Stop its relay
separately only when intended; dropping a live admission path can stop admitted
bodies through their existing lease supervisor. Do the stop test before live
body work, preserve all receiving state, and never turn it into global Stop.

Retain one current and one previous public request/profile per companion, plus
one bounded receipt (at most 64 KiB); cap this dedicated preparation at 512 KiB
per companion. Keep one checked public operator package within 8 MiB and retire
its byte-verified disposable transfer after consumption. Preserve pending or
uncertain operations rather than deleting them to admit more work.

Enrollment is not `Registry.adopt_running`: that requires actual admitted native
presence with matching body/embodiment/incarnation. Complete the existing
protected cohort and membership route before claiming Tribe delivery. No child
participation, media capture or external workspace/Drive grant follows from
this technical preparation.
