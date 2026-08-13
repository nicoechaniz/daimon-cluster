# DM-031 Cluster host adaptation receipt

Status: executable local acceptance; production effect adapters remain
intentionally unavailable.

Date: 2026-08-10.

## Frozen boundary

- Current integrated Cluster Matrix pin:
  `915c56c8899fd53d683bd7c7c81c3465b600bed9`. The original DM-031 exercise
  used predecessor `f0181f7117859f3f9cc4afc7dfbdaf9b06e74754`; the current
  additive descendant passed the combined integration gate on 2026-08-11.
- Normative DM-031 merge in that additive lineage:
  `1b133976932cbbc0914ba4ecc403020c647f53c1`.
- Matrix owns curator items, local queue generations, claims, results, request
  journals, actor attribution and cached-response truth checks.
- Cluster owns current body/incarnation observations and resource-fence truth.
- Concrete downstream adapters alone own external intent and postcondition
  observations. No such adapter is enabled in production by this change.

## Executed scenarios

`tests/test_matrix_host.py` proves that an exact synthetic route selected by
receipt adapter, `publication` work kind and `volume` resource namespace can
complete one fenced effect. Changing the observed postcondition makes an exact
retry fail with `effect-truth-discrepancy`; the original terminal receipt stays
immutable. Unknown, duplicate, unavailable and throwing observer routes fail
closed without disclosing observer errors.

`tests/test_matrix_host_process.py` starts the installed pinned Matrix daemon
and proves:

1. the clusterd five-method status capability cannot construct a curator
   request;
2. a separate exact four-method worker capability enqueues and claims local
   queue work;
3. the host-injected Cluster verifier admits a current resource-fenced claim;
4. the empty production observer router rejects an unregistered effect as
   `effect_truth_unverifiable`;
5. an exact completed queue request replays byte-identically after daemon
   restart; and
6. the writable ledger retains exactly one terminal result.

`tests/test_matrix_parity.py` rejects a substituted DM-031 schema or expanded
curator method set before readiness. Existing high-water, wrong holder/body,
incarnation, resource, epoch, proof, expiry, future observation, portable
snapshot, relocation and secret-boundary regressions remain in the complete
Cluster suite.

## Rollback

Stop curator admission, quiesce Matrix and roll back the whole pinned
Matrix+Cluster pair while preserving every queue row, generation, result,
request journal, ledger byte and fence high-water. Remove or rotate host-local
worker capabilities separately; never copy them in a portable snapshot. Do
not delete a terminal result, lower a generation or epoch, revive an expired
claim, or reinterpret an old receipt as current effect truth.
