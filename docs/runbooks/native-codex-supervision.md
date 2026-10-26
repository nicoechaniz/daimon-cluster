# Native Codex startup supervision

The receiving native service owns the shared daemon cgroup. A failed
`codex app-server daemon start` readiness handshake does not establish that its
child exited. Exiting the supervisor at that point terminates the child through
systemd and can create a permanent cold-start loop under load.

`clusterctl.native_codex_supervisor.serve` preserves that starting child and probes
`daemon version` for up to 180 seconds after a failed start. It does not issue Stop
or another start during this grace. A successful probe resumes the existing
singleton supervision. Persistent timeout emits `native_codex_readiness_unconfirmed`
and retains the process: control unresponsiveness is not proof of death. Exiting
the supervisor would run ExecStop and kill uncertain work. Every command/window
remains bounded; the next 30-second supervision cycle uses the native idempotent
start to recover a genuinely departed backend. A start-command timeout is also
retained. Only safe status codes go to the journal, never captured native stderr.
Normal explicit service stop retains the existing native shutdown behavior.

The service supervisor is the sole startup owner. After starting its systemd
unit, wait with bounded `daemon version` observations. Do not issue another
`daemon start` from an SSH shell to make a Type=simple unit ready: that caller
can win the singleton race and leave the real daemon or updater outside the
service cgroup. Verify the actual native PID's cgroup, not only MainPID. The
managed native start also recovers a departed updater; preserve an already
running model daemon when repairing only that helper. See
[native host relocation](native-host-relocation.md) for receiving evidence.

The onboarding service uses this same implementation. For an already deployed
immutable onboarding package, the stdlib-only module also accepts `--home` and
`--codex`. Select its verified content-addressed copy through an existing native
unit's ExecStart drop-in, preserving the service's user, environment, ExecStop and
restart policy. Retain the previous effective unit and exact drop-in for rollback;
do not edit the immutable package, native history, authentication or memory.
Adopt only under the receiving maintenance authorization. A selected service
restart does not authorize global Stop or replay of uncertain human input.

To adopt only a supervisor correction while preserving the current daemon, first
qualify this existing systemd seam on a disposable child process. Install the
content-addressed supervisor and permanent ExecStart override. Temporarily clear
ExecStop and set KillMode=process, Restart=always and RestartMode=direct in a
higher-priority temporary drop-in. After daemon-reload, signal only the supervisor
main process with SIGTERM and let direct-mode systemd supervision replace it.
An ordinary restart can stop listeners declaring Requires on the native unit;
qualify with that real dependency in the disposable fixture too. Verify the
native PID/starttime and dependent listener PID/starttime are
unchanged and its actual version/control RPC succeeds. Remove only that temporary
drop-in and daemon-reload to restore Restart=on-failure, normal restart mode and
explicit Stop semantics. Retain the
previous permanent selection and do not roll native history or credentials back.

The independent Alerts runtime monitor checks native version/control, actual
restart-counter increases, cgroup OOM-kill deltas and sustained memory PSI. It
uses the receiving owner's HOME/CODEX_HOME, scoped incident actor and existing
Telegram/Sessions route. A running unit alone never proves functional readiness;
automatic recovery starts departed infrastructure, never models or failed inputs.

Published source and the active onboarding default are separate. A new package
built from the corrected source imports this supervisor; a host worker selecting
an older immutable generation still provisions the older behavior. Existing-body
drop-in adoption does not update that selector. Track the supported default
advance and receiver-local Alerts enrollment in
[Cluster#241](https://github.com/nicoechaniz/daimon-cluster/issues/241).
Keep its existing jobs, bindings, grants and compatible rollback. Until the actual
worker selection and Alerts provisioning are qualified, report future automatic
coverage as pending. Never infer it from Eko/Oliva deployment or a merged PR.

Verify the native version handshake, the absence of repeated restarts across
multiple former failure windows, and the receiving listener separately. An active
supervisor alone is not readiness. Then apply any pending native configuration
through the normal RPC/trust/reload path. Test hook capture on normal human use;
configuration acceptance or a synthetic turn does not establish that acceptance.

Observed in the receiving Eko repair: the prior supervisor exceeded 500 restarts
and the control socket refused connections. The corrected supervisor recorded
waiting followed by recovered readiness, with the actual managed native version
reported by the control handshake. The receiving private record retains exact
versions, unit selection, timings and rollback. This fixes restart amplification;
it does not claim to remove every underlying source of slow startup.
