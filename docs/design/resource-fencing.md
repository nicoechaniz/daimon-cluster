# Resource-scoped fencing

Status: normative.

A fence answers “which holder may currently mutate this concrete resource?”
It does not answer “which body may embody this being?”

`resource-fence/v1` contains `resource_ref`, `holder_embodiment_id`, holder
public key/fingerprint, monotonic `epoch`, mutation and acquisition times, TTL,
renewer, and signature. Acquire is CAS. Renew increments the epoch. A durable
per-resource high-water prevents epoch reuse after expiry, release, or
rollback. Expiry allows a new holder. Restore and release require a valid
signature; rollback may restore prior holder bytes, but the next issued epoch
must exceed every epoch ever issued for that resource.

Every effect against a shared volume, database, container mutation lane, or
external resource identifies the appropriate `resource_ref` and current
epoch. Replaying an earlier idempotency result is permitted only when intent,
fence, and observed postcondition all still match.

Two embodiments may simultaneously hold fences for different resources. A
second holder for the same resource is rejected even when both embodiments
belong to one being. This is infrastructure safety, not consciousness or
identity policy.
