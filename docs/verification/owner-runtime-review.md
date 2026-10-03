# Existing-owner runtime review — issue116

Independent Codex review: **APPROVE** exact implementation
`b097157f73498ebfb20e362221ad716becb7ed70`.

The reviewer independently passed62 runtime/reader/registry/maintenance-boundary
checks with strict resource and unraisable warnings. Additional disposable
probes verified actual zombie refusal, process death immediately after registry
commit with accepted history retained, dead-process exact retry without mutation,
concurrent global-incarnation uniqueness and repeated pidfd descriptor closure.
No blocking finding remained. Existing reader v1 and native Matrix admission
remain distinct; no new IDs, Root authority or custody are manufactured.

The root/service-controlled profile must bind unit MainPID to actual runtime
socket peer PID/UID before approved activation. Author separately verified the
candidate ProcessPresence as actual service UID994 against actual runtime owner
UID1000, using exact public source in removed disposable staging and no daemon
frames/requests, keys, registry or service mutation. That kernel observation does
not prove actual enrollment, reader socket crossing, Matrix current authority
or native harness adoption. Those operational acceptance items remain pending.

Fleet-status correction: independent review **APPROVE** exact
`2a2d9b43b8a5bb26036a2efea8aad2f3a948909f`. Ten focused status/enrollment/boundary
checks and independent external-only, stopped-external, readonly, relabeling and
unknown-marker probes pass. Only explicitly external-owner records bypass the
service-owned Matrix root; managed failures retain503 with content-free errors.
The optional summary claims neither authenticated Matrix metadata nor physical
liveness. Process/socket implementation bytes and their earlier proofs remain
unchanged. Current-head CI and actual adoption are separate outstanding checks.
