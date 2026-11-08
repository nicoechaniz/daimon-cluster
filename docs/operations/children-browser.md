# Own companion browser on demand

The existing companion virtual owns its browser, profile, X authority and
WebBridge identity. Install only the qualified public executable and extension;
never copy an adult profile, vendor identity, configuration, account or history.
This route does not require Telegram, Matrix social membership or a model turn.

`tools/children_browser.py` is the agent user's lifecycle command. Select a
root-owned immutable public runtime below `/opt/children-maintenance/browser`,
with the exact bounded `runtime.json` inventory and published artifact provenance
in `support/children-browser/PROVENANCE.json`. Create the own private profile once
with `init --runtime PATH`; a changed runtime requires explicit reconciliation.
Preserve the existing profile, display authority and binding during helper updates.
Archive extraction must use `--no-same-owner`; verify bytes and root custody as
well as traversal/read access before selecting code for the agent consumer.

Install the three `deploy/systemd/user/kimi-webbridge-*.service` units in the
existing agent user's user manager. They are not enabled at boot. Keep the
existing guest's system/native/web services and resource limits unchanged. The
agent's `~/.local/bin/daimon-browser start` starts only its own trio for an actual
requested task. `status` reports intentional standby without waking a browser.
A ready connection report is metadata; qualify actual command behavior separately.
Vendor status versions `2.0.22` and `v2.0.22` refer to the same qualified artifact;
other versions do not silently pass.

The daemon listens only on loopback. Its systemd syscall filter refuses outgoing
`connect` calls: the extension opens the inbound WebSocket, so local commands
remain available while vendor reporting cannot open its outbound connection.
This is process-enforced transport restriction, not a vendor telemetry opt-out.
The actual vendor build enables startup telemetry and ignores HTTP proxy
variables; do not claim those variables disable reporting. Verify the installed
filter, an actual refused outbound connection and a successful extension command.
Chromium keeps its normal sandbox and ordinary network behavior. Do not add
`--no-sandbox`, a new root/sudo grant, firewall change or an alternate auth system.

For functional qualification use only a bounded loopback technical page: navigate,
read accessibility, evaluate, capture a synthetic page, retain another task's tab
when closing the first, and verify own local storage across an explicit stop/start.
Retire that test storage and capture afterward. This proves no family sign-in,
human hearing/device acceptance, child-authored speech or model uptake.

Use the installed common Kimi WebBridge skill for actual operations. Keep one
explicit top-level session per task. Close only disposable owned task sessions
under the existing cleanup authorization; borrowed human tabs and other tasks,
active downloads/media and uncertain work remain. `daimon-browser stop` stops
all three own units and keeps the profile. It is an explicit owner operation,
not a timer or an age-based idle guess. The vendor API has no verified complete
session/download inventory: an empty list for one session does not prove global
idleness. If ownership is unknown, leave the browser running and retain the gap.

Browser memory high/max is 768/1280 MiB, 512 tasks and 200% CPU; display and daemon
are each bounded at 128 MiB/32 tasks/25% CPU. Restart bursts and journal output
are bounded; disk cache is capped at 100 MiB, within the existing 8 GiB own home.
Control state is private and capped at 1 MiB, bindings at 64 KiB, public runtime
at 32 MiB/512 files. Preserve profiles and originals; quota is not authority to
delete them. Never wake a browser solely for a periodic health check. Full daily
browser/availability supervision and trustworthy idle retirement remain separate
work until actual receiving evidence exists.

Rollback selects the previous qualified helper/units only after current task
ownership is settled. Keep retained private state and existing account sessions;
never restore an older profile or rerun enrollment to repair code selection.

## Daily connection and standby observation

The existing daily collector supports an optional `browser_status` selection:

```json
{"browser_status":{"helper":"/opt/children-maintenance/browser-helpers/SELECTED_HASH/children_browser.py","sha256":"EXACT_SELECTED_HELPER_SHA256"}}
```

Set it only after actual own-browser installation. This is one exact public
helper selection for the four existing guests, not a new grant or login. The
root-side read verifies the selected helper's bytes, size, resolved path and
root-owned non-writable ancestry, then runs `status` as the actual agent user.
The guest subprocess is bounded at 20 seconds; the outer finite read at 25 seconds
and 128 KiB combined output. No lifecycle action, tab listing, navigation, model
call or private browser content is requested. Only whitelisted status metadata
enters the daily receipt.

Intentional standby is healthy without starting anything. An active connection
requires the qualified version and actual connected extension; it remains only
connection metadata, not a new functional journey. Missing/unavailable/unknown
status is degraded, while successful package inventory and advisory findings are
retained. The daily service returns nonzero and its existing scheduled-job Alerts
observer reports the failed occurrence. There is no extra timer or observer
credential. This daily check is distinct from independent host/network
availability and complete-idle cleanup, which remain separate work.

To stop this optional read, remove only `browser_status` from the private daily
configuration. Keep the timer, other phases, browser profiles and pending state.
