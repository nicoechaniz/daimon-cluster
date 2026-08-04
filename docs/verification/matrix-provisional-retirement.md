# Provisional Weave retirement receipt

Status: executable duplicate retired after frozen-byte parity.

Cluster `54a30fa` still contained its original provisional `weave/` package and
`scripts/weave` entrypoint. That code was a walking skeleton for `dm.we.v1`,
not an independent authority to keep beside the root-authorized Matrix
runtime. The installed `daimon-matrix` merge `73767504b777d0d0c9132a341959f486afce99f1`
is now the only executable Weave implementation hosted by Cluster.

The public fixture under `tests/fixtures/matrix-weave-v1/` is retained as the
migration boundary. `tests/test_matrix_parity.py` proves that the exact
historical manifest and signed event bytes, including their manifest/content
hashes and Ed25519 signature, are accepted by the pinned Matrix provisional
authority. It also proves that a payload mutation fails under Matrix. The
fixture file hashes are frozen in that test, so rewriting the evidence cannot
silently manufacture parity.

The prior Cluster verifier, ledger, projection adapters, fan-out helper and
CLI are recoverable from Git history at `54a30fa`; they are not imported by
clusterd, shipped through an entrypoint, or exercised as a second runtime.
Historical databases are not opened by the new host adapter. Migration to a
root-bound Matrix ledger requires Matrix's explicit history-binding contract;
no implicit schema upgrade or “latest wins” path exists.

Rollback means checking out the prior Git release in an isolated process and
preserving both ledgers unchanged. It never means letting old code open a
Matrix state root or letting Matrix reinterpret an unbound provisional
database.
