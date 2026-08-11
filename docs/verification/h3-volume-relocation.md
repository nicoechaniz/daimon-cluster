# H3 real durable-volume relocation verification

Issue: #66. Candidate branch: `issue-66-real-volume-relocation`.

## Executable acceptance

`tests/test_volume_relocation.py` proves exact volume identity and receipt
binding, source/target locking, immutable outer-journal intent, production
fence epoch/proof advancement, one incarnation under start response loss,
resume after create/detach/attach response loss, and recovery after every
inner transfer step. Wrong or multiple attachments, changed identity,
tampered/stale manifests, a vanished fence and failed source reattachment
fail closed; unprovable rollback remains degraded with the target stopped.

The existing transfer/handoff suites retain state-file hashes, embodiment
preservation, fence order, audit-chain integrity and rollback regressions.

## Real Incus drill

On 2026-08-10 the self-cleaning drill ran on `daimonmatrix` against Incus
6.0.4, image `tribe-base/latest`, profile `tribe-agent` and exact scratch
resources `h3-66a-20260810-{src,dst,home}`. Fourteen process boundaries
covered stopped target creation without home, source attachment/checkpoint,
detach response loss and observation-based retry, attach response loss and
observation-based retry, target start/post-start verification, and rollback
through stopped target, detach, source reattach and byte verification.

The receipt reported:

```json
{
  "schema": "h3-real-volume-drill/v1",
  "result": "ok",
  "one_writable_attachment_at_every_boundary": true,
  "response_loss_resumed": ["detach", "attach"],
  "rollback_restored_source": true,
  "volume_identity": "volume:0ab1d5158d77f949d452802a4d69ada2eedd4bf7e25056f92ffaf390d4e1dfdb",
  "state_sha256": "a2d251560447adc0fb748c10d62a2b13502a5401a70eecb3e454a69a70a46550",
  "public_key_fingerprint": "SHA256:EdvDrZhosWXDyBj/BG50zjFB3/bNXAoVFQcD3AAJSlM"
}
```

The private key was generated and used only inside the attached volume; only
its public fingerprint crossed the adapter boundary. Final read-only checks
proved the scratch containers, volume and temporary code directory absent.
`iso-a`, `iso-b` and `steward` remained running.

## Reproduction

```console
python -W error::ResourceWarning -m pytest -q \
  tests/test_volume_relocation.py tests/test_transfer.py \
  tests/test_handoff_failures.py tests/test_operation_journal.py
python -m ruff check clusterctl/adapters.py clusterctl/locks.py \
  clusterctl/provision.py clusterctl/transfer.py \
  tests/test_volume_relocation.py scripts/h3-volume-drill.py
PYTHONPATH=. python scripts/h3-volume-drill.py --prefix h3-<unique>
# Inspect the plan, then on the authorized Incus host:
PYTHONPATH=. python scripts/h3-volume-drill.py \
  --prefix h3-<unique> --execute
```

## Candidate result

On 2026-08-10 the exact stacked H1/H2/H3 candidate passed 116 focused volume,
transfer, handoff, provision and operation-journal tests and the complete
repository suite: 413 passed with 2 intentional skips under
ResourceWarning-as-error. The 31 H3-specific tests passed five consecutive
repetitions. Focused ruff, mypy over ten boundary modules, compileall,
workflow-YAML parsing, `git diff --check` and a changed-file secret-pattern
scan were clean. The immutable commit and Python 3.11–3.14 CI links are added
to issue #66 after publication; independent review remains required before
merge or deployment.
