# H2 mutation-journal verification

Issue: #65. Candidate branch: `issue-65-mutation-journal`.

## Executable acceptance

`tests/test_operation_journal.py` injects crashes or failures at the durable
boundaries around runtime, registry, spec, idempotency and audit work.

The suite proves:

- start response loss at every stage returns one result and one incarnation;
- create interruption never creates a duplicate and leaves either one exact
  tracked container or a verified compensation;
- provision interruption converges to one container, volume, in-container
  credential and confirmation token;
- start, stop and restart runtime-success/registry-failure resumes the exact
  logical transition, including a restart failure between registry stop and
  start;
- spec, idempotency and audit persistence failures do not cause a second
  runtime effect;
- stable audit event identity survives response loss and stale-lock context;
- the same idempotency identity with different operation bytes conflicts;
- contradictory or unverifiable runtime truth stays degraded, blocks unsafe
  follow-on work and is visible in reconcile and health;
- the repair command is bounded to observable power-state convergence;
- a read-only journal probe does not create a database.

Existing park, wake, transfer and handoff failure suites exercise the inner
workflow journals and rollback policies under the new outer journal. The full
repository suite also retains effect-truth replay, Matrix host, production
fence, clusterd and dashboard coverage.

## Reproduction

```console
python -W error::ResourceWarning -m pytest -q tests/test_operation_journal.py \
  tests/test_lifecycle.py tests/test_provision.py tests/test_park.py \
  tests/test_transfer.py tests/test_handoff_failures.py tests/test_effect_truth.py
python -W error::ResourceWarning -m pytest -q
python -m ruff check clusterctl/audit.py clusterctl/cli.py \
  clusterctl/embodiments.py clusterctl/idempotency.py clusterctl/inventory.py \
  clusterctl/lifecycle.py \
  clusterctl/operation_journal.py clusterctl/park.py clusterctl/provision.py \
  clusterctl/reconcile.py clusterctl/transfer.py clusterd/handlers.py \
  tests/test_operation_journal.py tests/test_park.py tests/test_transfer.py
python -m mypy --follow-imports=skip --ignore-missing-imports \
  --disable-error-code=import-untyped clusterctl/embodiments.py \
  clusterctl/idempotency.py clusterctl/inventory.py \
  clusterctl/operation_journal.py
python -m compileall -q clusterctl clusterd steward_tools tests
```

The exact Matrix dependency must first match `requirements-weave.txt`; its
source commit is independently checked by CI. No live host configuration or
custody material is required by this acceptance suite.

## Candidate result

On 2026-08-10, the exact stacked H1/H2 candidate passed 136 focused lifecycle,
provision, handoff and effect-truth tests and the complete repository suite:
382 passed with 2 intentional skips under ResourceWarning-as-error. The 58
H2-specific core and outer-handoff crash/retry tests passed five consecutive
repetitions. Focused
ruff and mypy, compileall, `git diff --check` and a secret-pattern scan were
clean; the scan's only matches were key-format detection and deliberate
redaction fixtures. The branch remains subject to independent review before
merge or deployment.
