# Pinned renderer source for trusted applications

The home gateway can supply its existing isolated model viewer to a trusted
application such as Nexus. This reuses the current visitor, selected resource
policy, immutable publication and cookie-free content lease. It introduces no
application login, model grant, capture, transcription or conversation service.

`GET /access/review-source/RESOURCE/VERSION` requires a 32-character hexadecimal resource and 64-character hexadecimal
immutable publication version; `current`, query overrides and unsupported files
are rejected. The selected artifact must declare an HTML entrypoint plus
review-live.json and gallery.json. The ordinary evaluator checks both its current
and historical audience. Denied or revoked readers receive 404, as with preview.

The no-store JSON descriptor has schema dm.home-review-source/v1, resource,
version, content_origin, frame{src,sandbox}, hydration{manifest,gallery} and
adapter_handshake. The frame source is an ephemeral existing /r/ content lease;
its sandbox is exactly allow-scripts. Hydration names are fixed, and the adapter
handshake is required rather than inferred from declared filenames. No recipient
list, private path, owner credential or title is included. The application's
selected content origin must agree before mounting the frame.

Do not persist, log or share the content URL as a source identity. Persist the
resource, publication/model revision and acknowledged snapshot instead. The
existing content lease lasts at most 15 minutes, bounded by its parent session;
expired leases use the existing next-write cleanup. The client mounts one frame,
does not renew in a timer and releases it on disposal. A later authorized open
obtains another lease without changing the pinned publication. Do not retry an
expired source by following current or substituting the author's identity.

The maintained /work-live-review.js exports
DaimonHomeReview{schema:dm.home-review-parent/v1,mountPinned(frame,descriptor)}.
It reuses the existing checksum-verified fixed-version hydrator, explicitly
disables resource switching/current polling and opts into the renderer state
handshake. One frame can have only one mount; dispose removes its listeners,
aborts owned fetches/timers and releases the frame. Caller mutation cannot change
the pinned descriptor. Legacy work pages retain their existing behavior.

The trusted application handles only messages from that exact opaque child,
validates its declared adapter/version and pinned inventory, and obtains actual
paint acknowledgements before saving a reaction or acquiring a microphone.
An unsupported renderer remains unsupported; a source descriptor is not proof
of 3D capture/restore. The application still owns table authorization, persistence,
original discussion retention and native admission. A table grant never grants
model access. Subsequent model requests and content leases retain current
resource/parent-session revocation checks.

The corresponding application contract is maintained in
[Nexus95](https://github.com/compaii/daimon-nexus/blob/main/docs/collaborative-review-contract.md).
Controlled HTTP and real-renderer browser qualification remain distinct from
receiving deployment and human listening acceptance.

## Current participant permission at application/native handoff

The owner-local check-review-access operation accepts only actor_ref, a 32-character hexadecimal
resource and a 64-character hexadecimal pinned version. It returns dm.review-access/v1 with the same
scope and a strict allowed boolean. The selected home's ordinary current and
historical evaluator decides for that actor. Reader credentials cannot call this
operation, and unknown/disabled actors or unavailable versions are denied.

This is a read-only decision for a trusted application's server-verified actor,
not permission to fetch content as that actor. No reader session or content lease
is minted and no audience changes. Reuse the receiving publisher's maintained
owner_request helper; keep its existing custody local. Another home's resources
require that home's authorized holder/adapter. The application must not accept
actor claims from the browser, cache an allow after revocation or use a model
author's identity when it cannot verify its participant.
