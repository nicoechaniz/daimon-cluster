# Recover a hosted Codex provider login

A device login updates persisted credentials. An already-running native daemon
can still hold the old credentials and report `401 token_revoked`; workspace
routing may surface it as JSON-RPC `-32603`. That code alone is not a diagnosis.
Inspect the native error, current credential validity and actual thread history.
Do not create a new conversation or replay an uncertain input to repair login.

The maintained operator is `tools/refresh_hosted_codex_login.py`. Run it through
the existing authorized Incus administrator with an owner-private configuration:

```sh
sudo python3 tools/refresh_hosted_codex_login.py --config /private/receivers.json
```

The config has schema `cluster.hosted-codex-login/v1`, `source_login` (an existing
native Codex auth file), and an explicit `receivers` list. Each receiver declares
`name`, `instance`, `home`, `uid`, `gid`, `account_sha256` (SHA256 of the selected
account ID), `code` (its existing qualified Cluster code), `binary`,
`native_helper` (its maintained Telecodex activity client), and `units` (its
selected native/listener/activity services). Keep this installation data and all
credentials outside Git. An excluded receiver remains unchanged.

The operator checks the selected account before provider access or installation.
A valid receiving login is retained even when its bytes differ from the source.
Only an invalid receiving login can be replaced by a valid same-account source.
Replacement quiesces the selected services, retains the exact private preimage,
checks it again and uses the existing `install_shared_cache` API. Failure before
installation restores that preimage; previously active services are restored.
It never installs one human's account over another's.

The native verification first reads account/rate-limit state without refreshing.
If necessary it uses `account/read` with `refreshToken:true`: the native auth
manager reloads a changed file under its account guard before asking the provider
to refresh tokens. A second account/rate-limit success is the useful proof. No
model turn, bot polling, Matrix attention, global Stop or input replay occurs.
The operator exposes only bounded outcome metadata, not account details or tokens.
If the source also needs device login, report that actual missing human action;
`codex login status` alone does not prove a token is accepted by the provider.

## Slow native startup

The native daemon CLI has its own short readiness deadline. A timed-out `start`
can leave a legitimate child still starting. The hosted supervisor must retain
that process for a bounded 180-second startup window and reuse idempotent native
start, instead of exiting immediately and letting systemd kill the child's
cgroup on every retry. A persistent failure remains visible after that window.
Reuse the shared [native supervisor](../runbooks/native-codex-supervision.md)
from Cluster #288, including its supported content-addressed maintenance drop-in.
This changes supervision, not the daemon version or its stored conversations.

An already-running supervisor adopts the correction at its next maintained
service activation; installing bytes alone does not claim that code is loaded.
Do not restart working paid conversations merely to repeat a startup test.

## Receiving record, 2026-10-21

Oliva's renewed persisted login was already valid while its running process
reported token revocation. A scoped native/listener recovery and retained native
startup restored successful native account and rate-limit requests; Casa's
existing history remained readable. No earlier failed request was replayed.
Human Telegram acceptance remains separate. Eko's separately selected account
is explicitly excluded from this renewal procedure.
