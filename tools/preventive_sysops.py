#!/usr/bin/env python3
"""Finite preventive fleet pass for the existing heartbeat; no model or scheduler.

Only operator-pinned oneshot units can be started. Incident text is never input.
An uncertain dispatch is observed on later passes, never resubmitted.
"""

import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import signal
import time

try:
    from .children_daily import atomic, command
    from .model_family_upgrades import model_evidence, plan as model_plan
except ImportError:
    from children_daily import atomic, command
    from model_family_upgrades import model_evidence, plan as model_plan

MAX_TARGETS = 16
MAX_JOBS = 64
MAX_STATE = 2 * 1024 * 1024


def local_prefix(argv):
    if not argv:
        return True
    if Path(argv[0]).name == "sudo" and len(argv) > 1 and argv[1] == "-n":
        argv = argv[2:]
    if not argv:
        return True
    return (
        len(argv) == 4
        and Path(argv[0]).name == "incus"
        and argv[1] == "exec"
        and bool(re.fullmatch("dm-[a-z0-9-]{1,48}", argv[2]))
        and argv[3] == "--"
    )


def ssh_parts(argv):
    if not argv or Path(argv[0]).name != "ssh":
        raise ValueError("fixed_ssh_required")
    i = 1
    while i < len(argv):
        a = argv[i]
        if re.fullmatch("[a-z_][a-z0-9_-]*@[a-zA-Z0-9.:-]+", a):
            if not local_prefix(argv[i + 1 :]):
                raise ValueError("fixed_remote_transport_required")
            return argv[: i + 1], argv[i + 1 :]
        if a in [
            "-T",
            "-oBatchMode=yes",
            "-oStrictHostKeyChecking=yes",
            "-oIdentitiesOnly=yes",
        ] or re.fullmatch("-oConnectTimeout=[1-9][0-9]?", a):
            i += 1
            continue
        if a == "-i" and i + 1 < len(argv) and Path(argv[i + 1]).is_absolute():
            i += 2
            continue
        if (
            a.startswith("-oUserKnownHostsFile=")
            and Path(a.split("=", 1)[1]).is_absolute()
        ):
            i += 1
            continue
        raise ValueError("fixed_ssh_option_required")
    raise ValueError("ssh_destination_required")


PROBE = r"""
import datetime,hashlib,json,os,pathlib,platform,subprocess,sys,time
spec=json.loads(sys.argv[1]);out={'schema':'cluster.sysops-observation/v1','os':{},'jobs':[]}
for line in pathlib.Path('/etc/os-release').read_text().splitlines():
 k,_,v=line.partition('=')
 if k in ('ID','VERSION_ID','VERSION_CODENAME'):out['os'][k]=v.strip('"')
out['kernel']=platform.release();out['disks']={}
for name in ['/','/home/agent','/srv']:
 if pathlib.Path(name).is_dir():
  v=os.statvfs(name);out['disks'][name]={'available_bytes':v.f_bavail*v.f_frsize,'quota_aware':False}
p=subprocess.run(['/usr/bin/dpkg','--audit'],capture_output=True,timeout=15)
out['dpkg_audit']={'exit':p.returncode,'requires_recovery':bool(p.stdout.strip()),'output_bytes':len(p.stdout)+len(p.stderr)}
p=subprocess.run(['/usr/bin/dpkg-query','-W','-f=${Package}\t${Version}\n','base-files','openssl','openssh-server','systemd','python3','nodejs','npm','antigravity','incus','docker.io','unattended-upgrades'],capture_output=True,timeout=10)
out['system_packages']=[x.split('\t',1) for x in p.stdout.decode().splitlines()[:32] if '\t' in x]
out['index_age_seconds']=None
stamp=pathlib.Path('/var/lib/apt/periodic/update-stamp')
if stamp.is_file():out['index_age_seconds']=max(0,time.time()-stamp.stat().st_mtime)
out['non_system_tools']={}
for name in ['codex','antigravity','node','npm','pnpm','corepack','uv','pipx','docker','incus']:
 found=[]
 for base in ['/usr/local/bin','/usr/bin','/home/agent/.local/bin']:
  p=pathlib.Path(base)/name
  if p.exists():found.append(str(p))
 out['non_system_tools'][name]={'paths':found,'manual_version_qualification':'owning managed release required' if found else 'not discovered in selected paths'}
for job in spec['jobs']:
 prefix=['systemctl']+(['--user'] if job['scope']=='user' else [])
 fields=['Id','Type','ActiveState','SubState','Result','ExecMainStatus','InvocationID','ExecMainStartTimestampMonotonic','ExecMainExitTimestampMonotonic']
 p=subprocess.run(prefix+['show',job['unit']]+['-p'+x for x in fields],capture_output=True,timeout=8)
 row=dict(line.split('=',1) for line in p.stdout.decode().splitlines() if '=' in line)
 cat=subprocess.run(prefix+['cat',job['unit']],capture_output=True,timeout=8)
 row.update(id=job['id'],read_ok=p.returncode==0 and cat.returncode==0,unit_sha256=hashlib.sha256(cat.stdout).hexdigest())
 row['age_seconds']=None
 start=int(row.get('ExecMainStartTimestampMonotonic','0') or 0)
 if start:row['age_seconds']=max(0,time.clock_gettime(time.CLOCK_BOOTTIME)-start/1000000)
 out['jobs'].append(row)
print(json.dumps(out))
"""


def private(path):
    p = Path(path)
    m = p.lstat()
    if (
        p.is_symlink()
        or not p.is_file()
        or m.st_uid != os.geteuid()
        or m.st_mode & 0o077
    ):
        raise ValueError("private_operator_file_required")
    return p


def validate(value):
    if (
        set(value) - {"model_evidence"} != {"schema", "state", "paused", "targets"}
        or value["schema"] != "cluster.preventive-sysops/v1"
        or type(value["paused"]) is not bool
    ):
        raise ValueError("closed_sysops_configuration_required")
    if (
        not 1 <= len(value["targets"]) <= MAX_TARGETS
        or not Path(value["state"]).is_absolute()
    ):
        raise ValueError("sysops_capacity")
    if "model_evidence" in value and (
        not isinstance(value["model_evidence"], str) or not Path(value["model_evidence"]).is_absolute()
    ):
        raise ValueError("absolute_model_evidence_path_required")
    ids = set()
    count = 0
    for t in value["targets"]:
        if (
            set(t) != {"id", "transport", "jobs"}
            or not re.fullmatch("[a-z0-9-]{1,64}", t["id"])
            or t["id"] in ids
        ):
            raise ValueError("invalid_target")
        ids.add(t["id"])
        transport = t["transport"]
        if (
            set(transport) != {"kind", "prefix"}
            or transport["kind"] not in ["local", "ssh"]
            or not isinstance(transport["prefix"], list)
            or len(transport["prefix"]) > 24
        ):
            raise ValueError("fixed_transport_required")
        if any(
            not isinstance(a, str) or not a or "\n" in a or "\x00" in a
            for a in transport["prefix"]
        ):
            raise ValueError("fixed_transport_required")
        if transport["kind"] == "ssh":
            ssh_parts(transport["prefix"])
        elif not local_prefix(transport["prefix"]):
            raise ValueError("fixed_local_transport_required")
        names = set()
        for j in t["jobs"]:
            if (
                set(j)
                != {"id", "unit", "scope", "interval_seconds", "unit_sha256", "action"}
                or j["id"] in names
            ):
                raise ValueError("invalid_job")
            names.add(j["id"])
            count += 1
            if not re.fullmatch("[a-z0-9-]{1,64}", j["id"]) or not re.fullmatch(
                "[a-zA-Z0-9@_.-]+\\.service", j["unit"]
            ):
                raise ValueError("invalid_job")
            if (
                j["scope"] not in ["system", "user"]
                or j["action"] not in ["observe", "start-if-due"]
                or type(j["interval_seconds"]) is not int
                or not 3600 <= j["interval_seconds"] <= 604800
                or not re.fullmatch("[a-f0-9]{64}", j["unit_sha256"])
            ):
                raise ValueError("invalid_job")
    if count > MAX_JOBS:
        raise ValueError("sysops_capacity")
    return value


def target_command(target, argv):
    t = target["transport"]
    if t["kind"] == "ssh":
        prefix, remote = ssh_parts(t["prefix"])
        return prefix + [shlex.join(remote + argv)]
    return t["prefix"] + argv


def save(path, data):
    raw = json.dumps(data, sort_keys=True).encode()
    if len(raw) > MAX_STATE:
        raise ValueError("sysops_state_capacity")
    atomic(path, raw)
    fd = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def run_pass(config, *, run=command):
    validate(config)
    root = Path(config["state"])
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if (
        root.is_symlink()
        or root.stat().st_uid != os.geteuid()
        or root.stat().st_mode & 0o077
    ):
        raise ValueError("private_state_required")
    lock = os.open(root / "pass.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        receipt = root / "CURRENT.json"
        prior = json.loads(private(receipt).read_text()) if receipt.exists() else {}
        pending = prior.get("pending", {})
        failures = prior.get("failures", {})
        if len(failures) > MAX_JOBS:
            raise ValueError("sysops_state_capacity")
        if len(pending) > MAX_JOBS:
            raise ValueError("sysops_state_capacity")
        result = {
            "schema": "cluster.preventive-sysops-result/v1",
            "at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "paused": config["paused"],
            "targets": [],
            "pending": pending,
            "failures": failures,
            "semantic": {},
            "models_started": 0,
            "scheduler_created": False,
        }
        if config["paused"]:
            save(receipt, result)
            return result
        started = time.monotonic()
        if "model_evidence" in config:
            try:
                result["model_upgrades"] = model_plan(
                    model_evidence(config["model_evidence"]),
                    {target["id"] for target in config["targets"]},
                )
            except (OSError, ValueError, TypeError):
                result["semantic"]["model_upgrades"] = "evidence-unavailable"
            else:
                for key, item in result["model_upgrades"].items():
                    result["semantic"]["model:" + key] = {
                        field: item[field] for field in ("current", "candidate", "state")
                        if field in item
                    }
        dispatches = 0
        for t in config["targets"]:
            if time.monotonic() - started > 210:
                raise TimeoutError("sysops_pass_deadline")
            try:
                observed = json.loads(
                    run(
                        target_command(
                            t,
                            [
                                "/usr/bin/python3",
                                "-I",
                                "-c",
                                PROBE,
                                json.dumps({"jobs": t["jobs"]}),
                            ],
                        ),
                        seconds=30,
                        limit=128 * 1024,
                    )
                )
                if observed.get("schema") != "cluster.sysops-observation/v1":
                    raise ValueError("invalid_observation")
            except Exception as error:
                result["targets"].append(
                    {
                        "id": t["id"],
                        "state": "unavailable",
                        "error": type(error).__name__,
                    }
                )
                result["semantic"][t["id"]] = "unavailable"
                continue
            attention = []
            if (
                observed["dpkg_audit"]["requires_recovery"]
                or observed["dpkg_audit"]["exit"]
            ):
                attention.append("package-database-needs-recovery")
            for j in t["jobs"]:
                row = next(x for x in observed["jobs"] if x["id"] == j["id"])
                key = t["id"] + ":" + j["id"]
                old = pending.get(key)
                qualified = (
                    row["read_ok"]
                    and row.get("Type") == "oneshot"
                    and row["unit_sha256"] == j["unit_sha256"]
                )
                busy = row.get("ActiveState") in [
                    "active",
                    "activating",
                    "deactivating",
                    "reloading",
                ]
                if old:
                    if (
                        old["unit_sha256"] != j["unit_sha256"]
                        or old.get("transport")
                        != hashlib.sha256(
                            json.dumps(t["transport"], sort_keys=True).encode()
                        ).hexdigest()
                    ):
                        attention.append(
                            j["id"] + ":pending-original-binding-preserved"
                        )
                        continue
                    changed = (
                        row.get("InvocationID")
                        and row["InvocationID"] != old["before_invocation"]
                    ) or int(
                        row.get("ExecMainStartTimestampMonotonic", "0") or 0
                    ) > old.get("before_start", 0)
                    if changed:
                        if not busy:
                            del pending[key]
                            if (
                                row.get("Result") != "success"
                                or row.get("ExecMainStatus") != "0"
                            ):
                                attention.append(j["id"] + ":failed")
                                day = (
                                    datetime.datetime.now(datetime.timezone.utc)
                                    .date()
                                    .isoformat()
                                )
                                old_fail = failures.get(key, {})
                                count = (
                                    old_fail.get("count", 0) + 1
                                    if old_fail.get("day") == day
                                    else 1
                                )
                                failures[key] = {
                                    "day": day,
                                    "count": count,
                                    "retry_after": time.time()
                                    + min(21600, 600 * 2 ** min(count, 6)),
                                }
                            else:
                                failures.pop(key, None)
                    else:
                        attention.append(j["id"] + ":dispatch-unconfirmed")
                    continue
                if not qualified:
                    attention.append(j["id"] + ":qualification-required")
                    continue
                due = (
                    row["age_seconds"] is None
                    or row["age_seconds"] >= j["interval_seconds"]
                )
                if not due or busy or j["action"] == "observe":
                    continue
                failure = failures.get(key, {})
                day = datetime.datetime.now(datetime.timezone.utc).date().isoformat()
                if (
                    failure.get("retry_after", 0) > time.time()
                    or failure.get("day") == day
                    and failure.get("count", 0) >= 3
                ):
                    attention.append(j["id"] + ":retry-deferred")
                    continue
                if dispatches >= 2:
                    attention.append(j["id"] + ":pass-capacity")
                    continue
                # Write intent BEFORE external dispatch. An unknown start is never retried.
                pending[key] = {
                    "before_invocation": row.get("InvocationID"),
                    "before_start": int(
                        row.get("ExecMainStartTimestampMonotonic", "0") or 0
                    ),
                    "transport": hashlib.sha256(
                        json.dumps(t["transport"], sort_keys=True).encode()
                    ).hexdigest(),
                    "unit_sha256": j["unit_sha256"],
                    "state": "dispatching",
                }
                save(receipt, result)
                try:
                    argv = (
                        ["systemctl"]
                        + (["--user"] if j["scope"] == "user" else [])
                        + ["start", "--no-block", j["unit"]]
                    )
                    run(target_command(t, argv), seconds=10, limit=8192)
                    pending[key]["state"] = "accepted"
                except Exception:
                    pending[key]["state"] = "uncertain"
                dispatches += 1
            result["targets"].append(
                {
                    "id": t["id"],
                    "state": "observed",
                    "observation": observed,
                    "attention": attention,
                    "coverage": "partial; manual tools, auth, applicability and backup adapters need explicit owning receipts",
                }
            )
            result["semantic"][t["id"]] = (
                "attention" if attention else "observed-partial"
            )
        result["elapsed_seconds"] = round(time.monotonic() - started, 3)
        save(receipt, result)
        return result
    finally:
        os.close(lock)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--config", type=Path, required=True)
    a = p.parse_args()
    os.umask(0o077)

    def expired(*_):
        raise TimeoutError("sysops_pass_deadline")

    signal.signal(signal.SIGALRM, expired)
    signal.alarm(300)
    result = run_pass(json.loads(private(a.config).read_text()))
    print(
        json.dumps(
            {
                "state": "paused" if result["paused"] else "observed",
                "targets": len(result["targets"]),
                "pending": len(result["pending"]),
                "semantic": result["semantic"],
            }
        )
    )


if __name__ == "__main__":
    main()
