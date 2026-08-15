# Runbook: clusterd deploy (issue #20 evidence)

How clusterd runs as a hardened host service on daimonmatrix.

## Topology (decided 2026-08-01)

- Code deploy target: `/opt/daimon-cluster/` (rsync from the repo, owned
  root:clusterd, group-readable). The repo stays the workspace; /opt is
  the service boundary — the service account never traverses /home.
- Runtime: `/opt/daimon-cluster/venv` (the exact committed
  `requirements.txt`, including source-pinned `daimon-matrix`) with
  `PYTHONPATH=/opt/daimon-cluster`.
- State: `/var/lib/daimon-cluster/` owned `clusterd:clusterd`.
- Identity: system user `clusterd` (no shell, no home), group
  `incus-admin` — the ADR places container authority in clusterd; the
  group gives it the incus socket directly. No setuid sudo path: the
  adapter tries the socket first and only falls back to sudo for
  interactive operators (`clusterctl/adapters.py:_sudo_runner`). This
  keeps `NoNewPrivileges=true` honest.
- sudoers vestige: /etc/sudoers.d/clusterd scopes NOPASSWD to
  `/usr/bin/incus` only (kept for debugging; the service path does not
  use it).

## Install (from scratch)

    sudo useradd --system --no-create-home --shell /usr/sbin/nologin clusterd
    sudo usermod -aG incus-admin clusterd
    sudo mkdir -p /opt/daimon-cluster
    sudo rsync -a --delete --exclude __pycache__ clusterd clusterctl configs scripts steward_tools constraints.txt requirements.txt requirements-weave.txt /opt/daimon-cluster/
    sudo python3 -m venv /opt/daimon-cluster/venv
    sudo /opt/daimon-cluster/venv/bin/python -m pip install -c /opt/daimon-cluster/constraints.txt -r /opt/daimon-cluster/requirements.txt
    sudo chown -R root:clusterd /opt/daimon-cluster && sudo chmod -R g+rX /opt/daimon-cluster
    sudo chown -R clusterd:clusterd /var/lib/daimon-cluster
    sudo cp configs/clusterd.service /etc/systemd/system/
    sudo systemctl daemon-reload && sudo systemctl enable --now clusterd

The virtualenv must be created only after the code is at its final absolute
pathname. Never copy or rename a prepared virtualenv: generated console scripts
retain absolute shebangs and will keep pointing at the staging directory. Verify
both boundaries before starting the service:

    sudo -u clusterd env PYTHONPATH=/opt/daimon-cluster /opt/daimon-cluster/venv/bin/python -c 'import clusterd, clusterctl, steward_tools'
    test "$(head -n 1 /opt/daimon-cluster/venv/bin/daimon)" = '#!/opt/daimon-cluster/venv/bin/python'
    sudo -u clusterd /opt/daimon-cluster/venv/bin/daimon --help >/dev/null

## Update and rollback

Build a source-only candidate containing the same asset list as the install
command. Stop `daimon-matrix-*.service` before `clusterd`, preserve the current
`/opt/daimon-cluster` under an explicit rollback name, and move the candidate to
the final pathname. Only then create its venv and run the three validations
above. Install units from the deployed `configs/`, reload systemd, start
`clusterd` first and Matrix hosts second, then require both health endpoints.

If dependency installation or any validation fails, keep the failed candidate
for diagnosis, restore the preserved release to `/opt/daimon-cluster`, reload
systemd and restart the previously active services. A pre-deploy verified restic
snapshot must cover the old release and complete state before this sequence.

Provision each running embodiment's owner-only Matrix root and host-local
clusterd capability according to `docs/runbooks/matrix-host.md` before
expecting `/v1/weave/status` to become configured and healthy.

## Verified on deploy day (2026-08-01)

- `systemctl is-active clusterd` → active; unit: NoNewPrivileges,
  ProtectSystem=strict, ReadWritePaths only the state dir, MemoryMax
  256M, TasksMax 64, restart on-failure, After incus+zerotier.
- Health ok end-to-end: clusterctl_reachable true, audit_chain_ok true.
- Listener initially used loopback only. The current steward topology binds
  loopback plus the private Incus bridge — still no public v4/v6 listener.
- Authenticated mutation through the service: token for `nico` (30d)
  created via the CLI, `GET /v1/instances` + restart of iso-b executed
  over HTTP, idempotency intact.
- Distinct dependency health states observed live: wrong-privilege
  window showed `degraded` with clusterctl_reachable:false while
  audit_chain_ok stayed true.
- M1 residue container `smoke-1` found by reconcile and deleted.

## Reboot

The authorized 2026-08-11 drill in `host-restart-drill.md` passed service,
private-only listener, authenticated state, exact Matrix status and durability
checks. The final candidate was Cluster `94d80ba` with Matrix `915c56c`.

The unit waits up to 30 seconds for the private Incus bridge address before
opening either listener. `incus.service` being active is not sufficient: the
bridge may still be materializing during boot. The preflight probes only local
bindability on an ephemeral port, emits no address or socket inventory, and
fails boundedly instead of making clusterd crash once with `EADDRNOTAVAIL`.
On the final cold boot the preflight exited zero after two seconds, clusterd
started exactly once, `NRestarts=0`, and the boot journal contained no bind
failure.
