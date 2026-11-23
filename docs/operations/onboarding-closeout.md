# Close an operationally accepted onboarding

Use `tools/close_completed_onboarding.py` only after explicit human acceptance
of the already-working being. All stages before acceptance must be complete.
Human acceptance is recorded with its source reference and the original job;
it is never relabeled as an automatic test, and old hosted-checks remain intact.

Prepare each private plan with the existing host config, name, human acceptance
reference, and retained original archive on the data filesystem:

```text
python -m tools.close_completed_onboarding --config HOST_CONFIG --name NAME \
  --archive RETAINED_ORIGINAL --human-reference HUMAN_ACCEPTANCE --plan PLAN
```

Preparation verifies the complete original and mounted-view input against the
original manifest and the retained archive hash. The plan binds job semantics,
file metadata/inodes, manifests and exact received payload directories. A later
timestamp from an unchanged failed observation does not invalidate that binding;
changed steps, facts or input refuse it.

Apply only while the fixed onboarding worker is cleanly drained through its
existing `receiving_worker.WorkerPause` preservation control and unit selection
lock. Keep its existing durable pause/restoration journal. This pauses no Matrix
daemon, Telegram process, Codex session or global conversation. Restore the
worker's original state even if acceptance or retirement fails.

```text
python -m tools.close_completed_onboarding --config HOST_CONFIG --plan PLAN \
  --apply --receipt RECEIPT
```

The operator commits ordinary complete job/progress records and retires only
the two duplicate `received` trees. It preserves original archive/intake keys,
manifests, plan, matrix/public account/connection data, runtime generations,
signed authority, home, native history and memory. Read-only input mounts may
remain as small metadata mounts because existing services retain their plan
argument there. Do not remove the whole mount or rewrite service definitions
merely to rename it. Active-file references and nested filesystem crossings
refuse retirement.

The same exact plan/receipt resumes an interrupted acceptance or partial payload
retirement. Retained preimage and explicit human provenance distinguish it from
automated checks. Do not restore the old pending job while its duplicate inputs
are retired: deliberate reinstallation first requires rematerializing the
original immutable input using the preserved export and owning intake route.
Software rollback does not undo human acceptance or restore old job journals.

Current candidate receiving maintenance uses `HostBackend._receiving_base` and
the receiving body's retained plan/genesis; it does not reopen participant
uploads. Keep its owner grants, current admission, qualified code/SDK, original
public mounts and native tooling adoption. Native skill updates remain separate.
Legacy no-candidate onboarding repair may still require the original upload;
use the current supported maintenance route for existing accepted bodies.

Cold KVM public App bundles must include the complete selected Codex package
(layout manifest, entrypoint, code-mode host, resources and path tools). A lone
binary can answer `--version` while native daemon startup fails. The pinned
public bundle is bounded to 768 MiB and 10,000 files; mutable accounts, identity
and memory stay outside it. Qualify daemon readiness, not CLI version alone.

A central companion Home resolves the current `/human` projection through the
configured owner adapter and passes only its bounded nonsecret pairing in the
host-owned bootstrap pipe. Guest-local legacy Homes retain `daimon-home human`.
Final acceptance still performs the real paired login, own Conversation read,
anonymous/admin denial and logout; a supplied display label proves none of them.
The initial bootstrap must act on an absent receiver, not report it already ready.

For KVM admission, explicitly select `vm_relay: "PRIVATE_ADDRESS:PORT"` in the
v2 native-admission profile. Reuse the actual existing authority relay destination;
there is no default network expansion. The maintained writer installs a guest
loopback-only systemd socket/proxyd with an exact destination network fence,
32 MiB memory/64 descriptors/16 tasks and five-minute idle exit. Container profiles
keep their existing Incus instance-bound proxy. A listening relay proves only
transport: signed enrollment, admitted presence and registry adoption must pass.
Stop only this guest socket/service if deliberately retiring its admission path;
never stop another body's authority or reuse a foreign profile.

Refresh explicit public membership observer/maintenance helpers through their
current pinned receiving transport. Preserve completed public/context reads and
native serving selections. The finite maintenance recipe also supplies compatible
context readers before its later writer phase; do not combine a new caller with
older peer/context helpers. Operational web-maintenance transport updates do not
change the immutable Home or route intent; current upstream guards still protect
all affected live calls before any Caddy reload.

Matrix maintenance records a stopped native CLI's failed exit truthfully. The
specific terminal exit(1) outcome may proceed only with the unchanged unit,
no systemd job/PID, and an empty control group. This is quiescence, never healthy
drain or service success; all native writers and ledger validation still precede
any signature. A forced kill, remaining process or changed unit remains a refusal.
Restoration may clear an observed start-limit failure of this exact owned unit;
it changes no service limits and retains the failed attempts in the journal.
Maintenance helpers must select an SDK that understands already accepted standing
permissions. The Source adapter resolves the selected public helper's SDK digest
to its existing private installed sibling; only the dropped owner verifies/imports
those bytes. The serving Source descriptor and SDK stay selected independently.
Always close an already entered `Endpoint.open()` scope through its existing
exit/ExitStack callback; entering it a second time starts a competing guard.

Membership preparation has a bounded 180-second parent invocation, including
authenticated base observations and original-pause recovery. Authenticate every
owner before opening any new pause. The guard revalidates that exact process
against systemd and /proc; a changed process refuses. Only after preparation does
the caller freeze the shared stopped-service/native-effect horizon, still at
most 60 seconds and clipped to the parent deadline. No running guard, invitation
or native writer gains time from another phase or retry.

KVM owner calls rebase the closed monotonic deadline flags in the receiving
kernel, bounded by the original remaining duration and wall expiry. Host and
guest uptime are not interchangeable clocks. This changes neither authorization
lifetime nor a native serving selection; expired or ambiguous flags refuse.
