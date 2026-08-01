# Runbook: clusterd deploy (issue #20 evidence)

How clusterd runs as a hardened host service on daimonmatrix.

## Topology (decided 2026-08-01)

- Code deploy target: `/opt/daimon-cluster/` (rsync from the repo, owned
  root:clusterd, group-readable). The repo stays the workspace; /opt is
  the service boundary — the service account never traverses /home.
- Runtime: `/opt/daimon-cluster/venv` (pyyaml only) with
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
    sudo rsync -a --delete --exclude __pycache__ clusterd clusterctl configs /opt/daimon-cluster/
    sudo uv venv /opt/daimon-cluster/venv && sudo uv pip install --python /opt/daimon-cluster/venv/bin/python pyyaml
    sudo chown -R root:clusterd /opt/daimon-cluster && sudo chmod -R g+rX /opt/daimon-cluster
    sudo chown -R clusterd:clusterd /var/lib/daimon-cluster
    sudo cp configs/clusterd.service /etc/systemd/system/
    sudo systemctl daemon-reload && sudo systemctl enable --now clusterd

## Verified on deploy day (2026-08-01)

- `systemctl is-active clusterd` → active; unit: NoNewPrivileges,
  ProtectSystem=strict, ReadWritePaths only the state dir, MemoryMax
  256M, TasksMax 64, restart on-failure, After incus+zerotier.
- Health ok end-to-end: clusterctl_reachable true, audit_chain_ok true.
- Listener: `ss -tlnp` shows 127.0.0.1:8785 only — no public v4/v6
  listener (acceptance: no public listener reachable). anyVPN bind is a
  steward-milestone decision (M5/M6), not v1.
- Authenticated mutation through the service: token for `nico` (30d)
  created via the CLI, `GET /v1/instances` + restart of iso-b executed
  over HTTP, idempotency intact.
- Distinct dependency health states observed live: wrong-privilege
  window showed `degraded` with clusterctl_reachable:false while
  audit_chain_ok stayed true.
- M1 residue container `smoke-1` found by reconcile and deleted.

## Reboot

Three clusterd rows added to `host-restart-drill.md` §2 (service active,
loopback-only listener, auth + state survival). The drill itself is run
by Nicolás (agent-side hardline block on reboot).
