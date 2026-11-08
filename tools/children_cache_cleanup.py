#!/usr/bin/env python3
"""Inspect guest activity as root; remove only owned compiler caches as agent.

No sudo grant or permanent privileged helper socket. A finite inherited socket
accepts only a fixed scan request. Root returns busy configured project roots,
never raw process arguments, paths, files or a command execution capability.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import pwd
import socket
import sys
import time

if __package__:
    from . import storage_hygiene as hygiene
    from .children_daily import command, atomic, footprint
    from .children_package_guard import private_json
else:
    sys.path.insert(0,str(Path(__file__).resolve().parent))
    import storage_hygiene as hygiene
    from children_daily import command, atomic, footprint
    from children_package_guard import private_json

MAX_FRAME=16384


def discover(projects):
    """Bounded Cargo discovery in the selected Projects tree, not host crawling."""
    repos=[];roots=[];entries=0
    for repo in projects.iterdir():
        entries+=1
        if entries>64:raise ValueError('project_inventory_limit')
        if repo.is_symlink() or not repo.is_dir() or repo.name.startswith('.'):
            continue
        result=hygiene.git(repo,'rev-parse','--show-toplevel')
        if result.returncode or Path(result.stdout.strip())!=repo:
            continue
        repos.append(repo)
        workspaces=[repo]
        for child in repo.iterdir():
            entries+=1
            if entries>2048:raise ValueError('workspace_inventory_limit')
            if (not child.is_symlink() and child.is_dir() and not child.name.startswith('.')
                    and child.name not in {'target','node_modules','Storage'}):
                workspaces.append(child)
        for workspace in workspaces:
            cargo=workspace/'Cargo.toml'
            if cargo.is_symlink() or not cargo.is_file():continue
            for profile in ['debug','dev-small']:
                root=workspace/'target'/profile/'incremental'
                if root.is_dir() and not root.is_symlink():roots.append(root)
                if len(roots)>64:raise ValueError('cache_root_limit')
    return repos,roots


def frame(connection,value):
    raw=json.dumps(value,sort_keys=True).encode()
    if len(raw)>MAX_FRAME:raise ValueError('cleanup_frame_limit')
    connection.sendall(raw)


def receive(connection):
    raw=connection.recv(MAX_FRAME+1)
    if not raw or len(raw)>MAX_FRAME:raise ValueError('cleanup_frame_limit')
    return json.loads(raw)


def run(config, *, now=None, scanner=None):
    if config.get('schema')!='children-compiler-cleanup/v1' or config.get('user')!='agent':
        raise ValueError('selected_guest_owner_required')
    owner=pwd.getpwnam('agent')
    projects=Path(config['projects_root'])
    allowed=Path(owner.pw_dir)/'Projects'
    if (owner.pw_uid<1000 or not (projects==allowed or projects.is_relative_to(allowed))
            or projects.resolve()!=projects or projects.stat().st_uid!=owner.pw_uid):
        raise ValueError('own_projects_required')
    # The privileged parent selects only owner project roots for its response.
    project_roots=[];entries=0
    for path in projects.iterdir():
        entries+=1
        if entries>64:raise ValueError('project_inventory_limit')
        if path.is_dir() and not path.is_symlink():project_roots.append(path)
    scanner=scanner or (lambda: {Path(p) for p in json.loads(command(
        ['/usr/bin/python3','-B','-I','-c',hygiene.PROCESS_SCAN],seconds=10,limit=8*1024*1024))})
    parent,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    pid=os.fork()
    if pid==0:
        parent.close()
        try:
            os.setgroups([]);os.setgid(owner.pw_gid);os.setuid(owner.pw_uid)
            if os.getresuid()!=(owner.pw_uid,)*3:raise ValueError('unprivileged_owner_required')
            os.chdir('/')
            os.environ.clear();os.environ.update(PATH='/usr/bin:/bin',HOME=owner.pw_dir,
                                                 USER=owner.pw_name,LOGNAME=owner.pw_name,LC_ALL='C')
            repos,roots=discover(projects)
            def activity():
                frame(child,{'request':'scan'})
                reply=receive(child)
                if set(reply)!={'busy_roots'} or not isinstance(reply['busy_roots'],list):
                    raise RuntimeError('complete_process_scan_unavailable')
                values={Path(p) for p in reply['busy_roots']}
                if not values<=set(repos):
                    # Non-Git project roots may legitimately be busy. They are
                    # irrelevant to this closed compiler cache policy.
                    values={p for p in values if p in repos}
                return values
            policy={'projects_root':str(projects),'cache_roots':[str(p) for p in roots],
                    'retired_worktrees':[], 'cache_min_age_days':2,
                    'max_cache_dirs_per_run':32, 'max_bytes_per_run':config.get('max_bytes_per_run',256*1024*1024),
                    'max_entries_per_run':20000,'max_seconds_per_run':40}
            result=hygiene.clean(policy,apply=True,now=now,activity_scan=activity)
            result.update(status='complete' if not result['errors'] and not result['budget_exhausted'] else 'partial',
                          deletion_uid=os.getuid(),cache_roots_observed=len(roots),
                          coverage='cargo-debug-incremental-only',
                          unassessed=['other-cache-classes','browser-session-lifecycle','explicit-worktree-retirement'])
            frame(child,{'result':result})
            child.close();os._exit(0)
        except BaseException as error:
            try:frame(child,{'error':type(error).__name__})
            finally:child.close();os._exit(1)
    child.close();result=None;scans=0;owner_verified=False
    try:
        parent.settimeout(55)
        while True:
            value=receive(parent)
            if value=={'request':'scan'}:
                if scans>=34:raise ValueError('process_scan_budget')
                # Observe actual real/effective/saved/fs uid after privilege drop.
                status=Path('/proc')/str(pid)/'status'
                uid=next(l.split()[1:] for l in status.read_text().splitlines() if l.startswith('Uid:'))
                if uid!=[str(owner.pw_uid)]*4:raise ValueError('child_owner_mismatch')
                owner_verified=True
                try:
                    active=scanner();scans+=1
                    busy=[str(p) for p in project_roots if hygiene.in_use(p,active)]
                    frame(parent,{'busy_roots':busy})
                except (OSError,RuntimeError,ValueError):
                    frame(parent,{'unavailable':True})
            elif set(value)=={'result'} and isinstance(value['result'],dict):
                result=value['result'];break
            elif set(value)=={'error'}:
                result={'status':'unavailable','reason':value['error']};break
            else:raise ValueError('unsupported_cleanup_request')
    finally:
        parent.close()
        _,status=os.waitpid(pid,0)
    if not result or not owner_verified or (status and result.get('status')=='complete'):
        raise ValueError('cleanup_consumer_unavailable')
    return {**result,'privileged_scans':scans,'deletion_owner_verified':owner_verified,'at':int(time.time())}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,required=True)
    parser.add_argument('--state',type=Path,required=True)
    args=parser.parse_args();os.umask(0o077)
    if os.geteuid()!=0:parser.error('own guest operator required')
    state=args.state;state.mkdir(parents=True,exist_ok=True,mode=0o700)
    if state.is_symlink() or state.stat().st_uid!=0 or state.stat().st_mode & 0o077:
        raise ValueError('private_cleanup_state_required')
    with (state/'lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if footprint(state)>1024*1024:raise ValueError('cleanup_state_capacity')
        try:result=run(private_json(args.config,0))
        except (OSError,ValueError,RuntimeError):result={'status':'unavailable','reason':type(sys.exception()).__name__,'at':int(time.time())}
        result['schema']='children-cache-cleanup/v1'
        current=state/'current.json'
        if current.exists() and private_json(current,0).get('status')=='complete':
            atomic(state/'previous.json',current.read_bytes())
        atomic(current,json.dumps(result,sort_keys=True).encode())
    print(json.dumps(result,sort_keys=True));return 0 if result['status']=='complete' else 2


if __name__=='__main__':raise SystemExit(main())
