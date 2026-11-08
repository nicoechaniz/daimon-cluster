#!/usr/bin/env python3
"""Durable daily coordinator for the reviewed guest browser package family.

Read deadlines never kill a package writer. Its guest service owns that writer;
the fleet observer may stop waiting without stopping or repeating it. Uncertain
commit intent is reconciled from real packages and services, never retried.
"""
import argparse
import datetime
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import sys
import time

if __package__:
    from . import children_package_selection as selection
    from .children_daily import atomic, command, footprint
    from .children_package_guard import Deferred, private_json, manifest_packages, idle_browser_scope, verify_archive
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import children_package_selection as selection
    from children_daily import atomic, command, footprint
    from children_package_guard import Deferred, private_json, manifest_packages, idle_browser_scope, verify_archive

CHILDREN = ('pixin', 'calipso', 'c-137', 'noodles')
SERVICES = ('daimon-onboarding-codex.service', 'children-conversation-native.service',
            'children-conversation-web.service')
TERMINAL = {'up_to_date', 'complete', 'deferred', 'report_only'}
GIB = 1024 ** 3


def save(path, value):
    atomic(path, json.dumps(value, sort_keys=True).encode())
    # Rename alone does not durably commit its directory entry after power loss.
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def versions(run=command):
    raw = run(['dpkg-query', '-W', '-f=${Package}\t${Version}\t${db:Status-Status}\n',
               *sorted(selection.PACKAGES)], seconds=10, limit=4096).decode()
    rows = [line.split('\t') for line in raw.splitlines()]
    if (len(rows) != 2 or any(len(r) != 3 or r[2] != 'installed' for r in rows)
            or {r[0] for r in rows} != selection.PACKAGES):
        raise Deferred('incomplete_installed_browser')
    if run(['dpkg', '--audit'], seconds=20, limit=64 * 1024).strip():
        raise Deferred('package_database_requires_recovery')
    return {r[0]: r[1] for r in rows}


def service_state(run=command):
    result = {}
    for unit in SERVICES:
        text = run(['systemctl', 'show', unit, '-p', 'ActiveState', '-p', 'MainPID',
                    '-p', 'NRestarts', '-p', 'InvocationID'], seconds=10, limit=8192).decode()
        row = dict(line.split('=', 1) for line in text.splitlines())
        if (row.get('ActiveState') != 'active' or not row.get('MainPID', '').isdigit()
                or int(row['MainPID']) <= 0 or not row.get('InvocationID')):
            raise Deferred('own_service_unavailable')
        result[unit] = row
    return result


def expected_config(state):
    guard = Path(__file__).resolve().with_name('children_package_guard.py')
    hook = shlex.join(['/usr/bin/python3', '-B', '-I', str(guard),
                       '--manifest', str(state / 'manifest.json')])
    return ('#clear DPkg::Pre-Install-Pkgs;\nDPkg::Pre-Install-Pkgs { "' + hook +
            '"; };\nDPkg::Tools::Options::/usr/bin/python3::Version "2";\n').encode()


def precommit(policy, state, manifest, run=command):
    packages = manifest_packages(manifest)
    selection.check_config(run(['apt-config', 'dump'], seconds=10, limit=256*1024).decode(), policy)
    target = selection.security_target(run(['apt-get', 'indextargets'], seconds=20, limit=256*1024).decode())
    index = selection.release_fresh(target, time.time())
    current = {n: p['version'] for n, p in packages.items()}
    records = selection.record_selection(run(['/usr/lib/apt/apt-helper', 'cat-file', str(index)],
                                            seconds=30, limit=selection.MAX_INDEX).decode(), current)
    for n, p in packages.items():
        if records[n]['SHA256'] != p['sha256'] or int(records[n]['Size']) != p['bytes']:
            raise Deferred('changed_security_archive')
        verify_archive(p, 0)
    if versions(run) != {n: p['old_version'] for n, p in packages.items()}:
        raise Deferred('changed_installed_plan')
    config = state / 'transaction.apt.conf'
    info = config.lstat()
    if (config.is_symlink() or info.st_uid != os.geteuid() or info.st_mode & 0o077
            or config.read_bytes() != expected_config(state)):
        raise Deferred('changed_transaction_config')
    # Stop the transaction before APT if a held package or an expanded dependency
    # changes the reviewed plan; the guard repeats under APT's real locks.
    held = run(['apt-mark', 'showhold'], seconds=10, limit=64*1024).decode().splitlines()
    if selection.PACKAGES & set(held):
        raise Deferred('held_browser_package')
    argv = ['apt-get', '-s', '--no-download', '--no-remove', '--no-install-recommends',
            'install', '--only-upgrade', *[n+'='+p['version'] for n, p in sorted(packages.items())]]
    selection.plan_exact(run(argv, seconds=30, limit=256*1024).decode(),
                         {n: p['old_version'] for n, p in packages.items()}, current)
    if os.statvfs('/').f_bavail * os.statvfs('/').f_frsize < GIB:
        raise Deferred('insufficient_guest_space')
    idle_browser_scope()
    return service_state(run)


def writer(argv):
    """Wait without a deadline; output goes directly to bounded systemd journal.

    No parent-owned pipe: losing this Python supervisor must not give APT/dpkg
    SIGPIPE or close their logging sink. The guest service preserves child
    processes; recovery subsequently checks actual package-manager locks.
    """
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                               start_new_session=True,
                               env={**os.environ, 'LC_ALL': 'C', 'DEBIAN_FRONTEND': 'noninteractive'})
    # No terminate/kill in an exception handler. A supervisor outage never
    # authorizes killing dpkg; its systemd journal sink outlives this process.
    return {'exit': process.wait(), 'pid': process.pid, 'output': 'guest-unit-journal'}


def finish(state, journal, run=command):
    with package_locks(state):
        return finish_locked(state, journal, run)


@contextlib.contextmanager
def package_locks(state, dpkg_root=Path('/var/lib/dpkg')):
    """Real POSIX locks, never flock or deletion of APT/dpkg lock files."""
    with contextlib.ExitStack() as stack:
        for path in (dpkg_root/'lock-frontend', dpkg_root/'lock', state/'archives'/'lock'):
            # open() creates nothing: missing custody/lock is a failed read.
            fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW)
            stream=stack.enter_context(os.fdopen(fd,'r+b'))
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode & 0o022:
                raise Deferred('package_lock_custody')
            try:
                fcntl.lockf(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Deferred('original_package_writer_still_running') from None
        yield


def finish_locked(state, journal, run=command):
    manifest = private_json(state/'manifest.json', 0)
    if hashlib.sha256((state/'manifest.json').read_bytes()).hexdigest() != journal['manifest_sha256']:
        raise Deferred('changed_pending_manifest')
    packages = manifest_packages(manifest)
    if versions(run) != {n: p['version'] for n, p in packages.items()}:
        raise Deferred('commit_uncertain_requires_operator')
    if service_state(run) != journal['services_before']:
        raise Deferred('own_service_changed_requires_operator')
    # Read actual executable version as well as the installed package database.
    version = run(['/usr/bin/chromium', '--version'], seconds=10, limit=4096).decode().strip()
    expected = packages['chromium']['version'].split(':')[-1].split('-')[0]
    if not version.startswith('Chromium '+expected+' '):
        raise Deferred('executable_version_mismatch')
    journal.update(phase='complete', finished=int(time.time()), executable_version=version,
                   observed_versions={n: p['version'] for n, p in packages.items()})
    journal.pop('reason',None)
    save(state/'transaction.json', journal)
    retire(state, journal)
    return journal


def retire(state, journal):
    """Resumable exact cleanup only after actual installation/health proof."""
    manifest_path = state/'manifest.json'
    if manifest_path.exists():
        if hashlib.sha256(manifest_path.read_bytes()).hexdigest() != journal['manifest_sha256']:
            raise Deferred('changed_completed_manifest')
        packages = manifest_packages(private_json(manifest_path, 0))
        for item in packages.values():
            path = Path(item['archive'])
            if path.parent != state/'archives':
                raise Deferred('unowned_archive_cleanup_refused')
            if path.exists():
                verify_archive(item, 0)
                path.unlink()
        config = state/'transaction.apt.conf'
        if config.exists():
            if config.is_symlink() or config.read_bytes() != expected_config(state):
                raise Deferred('changed_completed_config')
            config.unlink()
        manifest_path.unlink()
    journal['artifacts_retired'] = True
    save(state/'transaction.json', journal)


def maintain(policy, state, *, install=False, occurrence=None, run=command, commit=writer):
    occurrence = occurrence or datetime.datetime.now(datetime.timezone.utc).date().isoformat()
    path = state/'transaction.json'
    old = private_json(path, 0) if path.exists() else None
    prepared = None
    if old:
        if (old.get('schema')!='children-package-maintenance/v1'
                or old.get('phase') not in TERMINAL|{'selecting','prepared','commit_requested'}
                or type(old.get('write_requested')) is not bool
                or not isinstance(old.get('occurrence'),str)):
            raise Deferred('unknown_transaction_preserved')
        if old['phase'] == 'complete' and not old.get('artifacts_retired'):
            with package_locks(state):
                retire(state, old)
        elif old['phase'] not in TERMINAL:
            # Includes crash after durable intent but before launch. Observing old
            # versions is insufficient to prove the writer was never admitted.
            if old.get('write_requested'):
                return finish(state, old, run)
            if (state/'manifest.json').exists():
                if (old['phase'] != 'prepared' or hashlib.sha256((state/'manifest.json').read_bytes()).hexdigest()
                        != old.get('manifest_sha256')):
                    raise Deferred('prepared_selection_requires_reconciliation')
                prepared = old
            else:
                # The durable writer intent was never set. A failed/killed read
                # cannot have admitted a writer through this coordinator.
                old.update(phase='deferred', reason='selection_interrupted_before_commit')
                save(path, old)
        if prepared is None:
            if old['occurrence'] == occurrence:
                return old
            save(state/'previous-transaction.json', old)
    journal = prepared or {'schema': 'children-package-maintenance/v1', 'occurrence': occurrence,
                           'phase': 'selecting', 'started': int(time.time()), 'write_requested': False}
    # An orphan manifest from a previous partial selection must not be replaced.
    if prepared is None and (state/'manifest.json').exists():
        raise Deferred('orphan_manifest_requires_operator')
    save(path, journal)
    try:
        selected = journal['selection'] if prepared is not None else selection.select(policy, state, download=install, run=run)
        save(state/'current.json', selected)
        journal['selection'] = selected
        if selected['decision'] in {'up_to_date', 'review_download_required'}:
            journal.update(phase='up_to_date' if selected['decision']=='up_to_date' else 'report_only',
                           finished=int(time.time()))
            save(path, journal)
            return journal
        if selected['decision'] != 'reviewed_manifest_prepared' or not install:
            raise Deferred('unreviewed_selection')
        journal['manifest_sha256'] = selected['manifest_sha256']
        journal.update(phase='prepared', occurrence=occurrence)
        save(path, journal)
        manifest = private_json(state/'manifest.json', 0)
        journal['services_before'] = precommit(policy, state, manifest, run)
        journal.pop('reason',None)
        # This fsync precedes every writer admission. Exceptions/interruptions
        # after it preserve intent and will only reconcile, never repeat.
        journal.update(phase='commit_requested', write_requested=True)
        save(path, journal)
        packages = manifest_packages(manifest)
        argv = ['apt-get', '-c', str(state/'transaction.apt.conf'), '-o', 'DPkg::Lock::Timeout=0',
                '-o', 'DPkg::Options::=--force-confold', '-o', 'Dir::Cache::archives='+str(state/'archives'),
                '--no-download', '--no-remove', '--no-install-recommends', '-y', 'install', '--only-upgrade',
                *[n+'='+p['version'] for n, p in sorted(packages.items())]]
        output = commit(argv)
        journal['writer'] = output
        save(path, journal)
        return finish(state, journal, run)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        if not journal['write_requested'] and not (state/'manifest.json').exists():
            journal.update(phase='deferred', finished=int(time.time()))
        journal['reason'] = str(error) if isinstance(error, Deferred) else type(error).__name__
        save(path, journal)
        raise


def fleet(state, run=command, wait=time.sleep, now=time.monotonic, duration=600):
    report = {'schema':'children-daily-packages/v1', 'at':int(time.time()), 'targets':{}}
    deadline = now()+duration
    for name in CHILDREN:
        instance = 'dm-'+name
        prefix = ['incus', 'exec', instance, '--']
        try:
            quota = json.loads(run(['incus', 'query', '/1.0/storage-pools/fast/volumes/container/'+instance+'/state'], seconds=10, limit=8192))['usage']
            if (type(quota['total']) is not int or type(quota['used']) is not int
                    or quota['total']-quota['used'] < 2*GIB):
                raise Deferred('insufficient_root_quota_headroom')
            # systemd owns a single unit per guest, outside this observer's
            # cgroup. A running/start-pending unit is observed, never restarted.
            def status():
                text=run([*prefix,'systemctl','show','children-package-maintenance.service',
                          '-p','ActiveState','-p','ExecMainStatus','-p','LoadState'], seconds=10, limit=8192).decode()
                return dict(l.split('=',1) for l in text.splitlines())
            value=status()
            if value['LoadState']!='loaded':
                raise Deferred('guest_package_unit_unavailable')
            if value['ActiveState'] not in {'active','activating','deactivating'}:
                run([*prefix,'systemctl','start','--no-block','children-package-maintenance.service'],seconds=10,limit=8192)
                value=status()
            while value['ActiveState'] in {'active','activating','deactivating'}:
                if now() >= deadline:
                    raise Deferred('guest_writer_still_running_observation_ended')
                wait(3)
                value=status()
            raw = run([*prefix,'cat','/var/lib/children-maintenance/browser-selection/transaction.json'],seconds=10,limit=256*1024)
            result = json.loads(raw)
            if result.get('schema')!='children-package-maintenance/v1':
                raise Deferred('unknown_guest_package_receipt')
            report['targets'][name] = {k:result[k] for k in
                ('occurrence','phase','write_requested','reason','finished') if k in result}
            report['targets'][name]['unit_exit'] = value['ExecMainStatus']
            today=datetime.datetime.now(datetime.timezone.utc).date().isoformat()
            if (value['ExecMainStatus']!='0' or result['phase'] not in {'complete','up_to_date'}
                    or result.get('occurrence')!=today):
                raise Deferred('guest_package_coverage_degraded')
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
            report['targets'].setdefault(name,{})['error']=str(error) if isinstance(error,Deferred) else type(error).__name__
            # Other idle guests may still assess independently; an observation
            # deadline never kills a prior writer or permits another launch.
            if now() >= deadline:
                break
    report['complete'] = len(report['targets'])==4 and all('error' not in v for v in report['targets'].values())
    report['finished']=int(time.time())
    current=state/'current.json'
    if current.exists():
        previous=private_json(current,0)
        if previous.get('complete'):
            save(state/'previous.json',previous)
    save(state/'current.json',report)
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state',type=Path,required=True)
    parser.add_argument('--policy',type=Path)
    parser.add_argument('--install',action='store_true')
    parser.add_argument('--fleet',action='store_true')
    args=parser.parse_args()
    os.umask(0o077)
    if os.geteuid()!=0 or (not args.fleet and args.policy is None) or (args.fleet and (args.install or args.policy)):
        parser.error('selected root guest or fleet configuration required')
    state=args.state.absolute();state.mkdir(parents=True,mode=0o700,exist_ok=True)
    if state.is_symlink() or state.stat().st_uid!=0 or state.stat().st_mode & 0o077:
        raise Deferred('private_operator_state_required')
    # Same state/lock as the standalone selection tool.
    with (state/'lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if footprint(state)>384*1024*1024:
            raise Deferred('package_state_capacity')
        result=fleet(state) if args.fleet else maintain(private_json(args.policy,0),state,install=args.install)
    print(json.dumps(result,sort_keys=True))
    return 0 if result.get('complete') or result.get('phase') in {'up_to_date','complete','report_only'} else 2


if __name__=='__main__':
    raise SystemExit(main())
