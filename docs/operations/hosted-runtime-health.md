# Automatic hosted native recovery and health enrollment

Each new Telegram-enabled hosted body uses the corrected standalone native
supervisor from the selected immutable Telegram code generation. The code bundle
must include `native_codex_supervisor.py`; launching the frozen base's old launcher
would silently undo the repair. Public-code file modes are explicit even under
operator umask0077. Existing native history, accounts and Matrix SDK selectors are
separate and remain unchanged.

The existing onboarding worker accepts an operator-private
`runtime_health_registry` directory in its fixed host configuration. After the
retained job has completed Telegram, it registers that exact authorized plan's
resource with the host Alerts observer. Completed accepted jobs register through
the same idempotent path without reopening uploads or repeating their stages.
The registry contains only a name, fixed instance/resource IDs and plan digest;
it grants no Matrix authority and contains no guest credential or command.

Install host observation once through `tools.install_host_runtime_health` with
the existing Alerts core config, receiving scope/adapter, verified root-owned
monitor source and private registry. This reuses the host operator's route and
adds only a publish/observe/status actor. Future bodies need no separate core,
bot consumer or copied producer credential for infrastructure observation. Their
own existing local alerts may remain independently active.

A maximum of16 resources is enforced atomically by the writer. Overflow or other
enrollment failure retains a private failure marker and produces an operational
incident; it never removes prior coverage or rewrites a completed onboarding.
After recovery the same registration removes only its own marker. This capacity
limit is explicit, not a claim that sixteen physical workloads always fit.

The observer reads all cgroup PSI/OOM metrics before any guest RPC. At most four
native probes run concurrently; each separately bounds its restart-counter and
version call at15seconds. Completed incidents are published immediately. While
remote probes remain pending, ten-second heartbeats explicitly report unreadable
partial observation, not a healthy completed batch. Up to16 slow bodies can take
roughly120seconds; the owned service has a180second limit and runs again15seconds
after completion. The core freshness window must be at least25seconds. Ordinary
healthy native probes are much faster. No model or automatic conversation is run.

Infrastructure recovery remains with each body's native supervisor: readiness
timeout does not kill work, and idempotent Start recovers a genuinely departed
daemon. Monitoring never repeats a failed human turn or expands memory endlessly.
A running Matrix unit does not prove Matrix delivery. Active host pressure,
provider/account errors and Matrix transport incidents keep their separate owners.

For actual deployment, freeze and verify the Telegram code successor against the
original context, preserve all existing runtime-by-name/SDK and Telegram binary
choices, then select it with the supported scoped onboarding-worker drain/restart.
No Matrix/Telegram/Codex or global Stop is required. Preserve paused goals and
uncertain inputs. Use a new receiving profile with a measured memory budget for
future bodies; do not modify the profile already inherited by working bodies.

Rollback restores the prior worker/config selectors and service preimages without
restoring job, incident or conversation databases. Preserve the newer observer
source/journal to drain pending delivery. Explicitly retire observation through
Alerts only after its selected timer is stopped; old warnings and uncertain
receipts remain history. Removing the host registry selection disables future
enrollment, not already-accepted authority or current body work.
