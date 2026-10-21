# Native Codex startup supervision

The receiving native service owns the shared daemon cgroup. A failed
`codex app-server daemon start` readiness handshake does not establish that its
child exited. Exiting the supervisor at that point terminates the child through
systemd and can create a permanent cold-start loop under load.

`clusterctl.native_codex_supervisor.serve` preserves that starting child and probes
`daemon version` for up to 180 seconds after a failed start. It does not issue Stop
or another start during this grace. A successful probe resumes the existing
singleton supervision; persistent failure exits visibly. Per-probe timeouts are
bounded. Only safe status codes go to the journal, never captured native stderr.
Normal explicit service stop retains the existing native shutdown behavior.

The onboarding service uses this same implementation. For an already deployed
immutable onboarding package, the stdlib-only module also accepts `--home` and
`--codex`. Select its verified content-addressed copy through an existing native
unit's ExecStart drop-in, preserving the service's user, environment, ExecStop and
restart policy. Retain the previous effective unit and exact drop-in for rollback;
do not edit the immutable package, native history, authentication or memory.
Adopt only under the receiving maintenance authorization. A selected service
restart does not authorize global Stop or replay of uncertain human input.

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
