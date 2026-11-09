#!/usr/bin/env python3
"""Bounded Debian inventory and vendor advisory phase; never installs packages.

Private configuration selects one host and four children. Full maintenance also
needs the owning cleanup, application-advisory and Alerts adapters. Missing
coverage is explicit, never a zero-vulnerability certificate.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import selectors
import subprocess
import time
import urllib.request
import zlib


FEED = 'https://security-tracker.debian.org/tracker/debsecan/release/1/trixie'
MIB = 1024 * 1024
PROBE = r'''
import json,os,platform
from pathlib import Path
p=Path('/var/lib/dpkg/status')
if p.stat().st_size>4*1024*1024:raise ValueError('inventory limit')
release={}
for line in Path('/etc/os-release').read_text().splitlines():
 k,_,v=line.partition('=')
 if k in {'ID','VERSION_ID','VERSION_CODENAME'}:release[k]=v.strip('"')
memory={}
for line in Path('/proc/meminfo').read_text().splitlines():
 k,_,v=line.partition(':')
 if k in {'MemTotal','MemAvailable','SwapTotal','SwapFree'}:memory[k]=int(v.split()[0])*1024
filesystems={}
for name in ('/','/home/agent'):
 if Path(name).is_dir():
  v=os.statvfs(name);filesystems[name]={'available_bytes':v.f_bavail*v.f_frsize,'inodes_available':v.f_favail,'quota_aware':False}
cgroups={}
for name in ('memory.max','pids.max','cpu.max','cpuset.cpus.effective'):
 p=Path('/sys/fs/cgroup')/name
 if p.exists():cgroups[name]=p.read_text().strip()
print(json.dumps({'os':release,'kernel':platform.release(),'memory':memory,'filesystems':filesystems,'cgroups':cgroups,'package_status':Path('/var/lib/dpkg/status').read_text()}))
'''


class LimitError(ValueError):
    pass


def command(argv, *, seconds=20, limit=8 * MIB):
    """Drain both streams with byte/time bounds; do not retain raw stderr."""
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, start_new_session=True)
    reader = selectors.DefaultSelector()
    reader.register(child.stdout, selectors.EVENT_READ, True)
    reader.register(child.stderr, selectors.EVENT_READ, False)
    output, seen, deadline = bytearray(), 0, time.monotonic() + seconds
    try:
        while reader.get_map():
            if time.monotonic() >= deadline:
                raise LimitError('command_timeout')
            for key, _ in reader.select(min(0.2, max(0, deadline-time.monotonic()))):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    reader.unregister(key.fileobj)
                    continue
                seen += len(chunk)
                if seen > limit:
                    raise LimitError('command_output_limit')
                if key.data:
                    output.extend(chunk)
        if child.wait(timeout=max(0.01, deadline-time.monotonic())):
            raise ValueError('command_failed')
        return bytes(output)
    finally:
        reader.close()
        if child.poll() is None:
            # These commands are finite reads/matching only, never dpkg writers.
            import signal
            os.killpg(child.pid, signal.SIGKILL)
        child.wait()
        child.stdout.close()
        child.stderr.close()


def atomic(path, raw):
    temporary = path.with_name(path.name + '.next')
    if temporary.is_symlink() or path.is_symlink():
        raise ValueError('owned_regular_state_required')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def footprint(root):
    total = 0
    for path in root.rglob('*'):
        if path.is_symlink():
            raise ValueError('state_symlink_refused')
        if path.is_file():
            total += path.stat().st_size
    return total


def fetch_feed(opener=None):
    opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(FEED, headers={'User-Agent': 'children-daily/1'})
    with opener.open(request, timeout=20) as response:
        if response.geturl() != FEED:
            raise ValueError('advisory_redirect_refused')
        raw = response.read(16 * MIB + 1)
    if len(raw) > 16 * MIB:
        raise LimitError('advisory_download_limit')
    decoder = zlib.decompressobj()
    plain = decoder.decompress(raw, 64 * MIB + 1)
    if len(plain) > 64 * MIB or not decoder.eof or decoder.unused_data:
        raise LimitError('advisory_expansion_limit')
    if not plain.startswith(b'VERSION 1\n'):
        raise ValueError('unsupported_vendor_feed')
    return raw


def validate(config):
    required={'schema', 'state', 'scanner', 'scanner_sha256', 'targets'}
    if (not required<=set(config) or set(config)-required-{'compiler_cleanup_enabled','browser_status','application_inventory','public_advisories','known_exploitation'}
            or type(config.get('compiler_cleanup_enabled',False)) is not bool):
        raise ValueError('explicit_daily_configuration_required')
    if 'known_exploitation' in config:
        validate_known_selection(config['known_exploitation'])
        if (config['known_exploitation'].get('assess_freetype') and
                not config.get('application_inventory',{}).get('browser_components')):
            raise ValueError('current_browser_components_required_for_freetype')
    if 'public_advisories' in config:
        if 'application_inventory' not in config:raise ValueError('application_inventory_required_for_advisories')
        validate_advisory_selection(config['public_advisories'])
    if 'application_inventory' in config:
        validate_application_selection(config['application_inventory'])
    if 'browser_status' in config:
        validate_browser_selection(config['browser_status'])
    if config['schema'] != 'cluster-children-daily/v1':
        raise ValueError('unsupported_daily_configuration')
    targets = config['targets']
    if len(targets) != 5 or len({t['id'] for t in targets}) != 5:
        raise ValueError('one_host_and_four_children_required')
    if targets[0] != {'id': 'lordoftheflies', 'instance': None}:
        raise ValueError('selected_host_required')
    if targets[1:] != [{'id': n, 'instance': 'dm-' + n}
                       for n in ('pixin', 'calipso', 'c-137', 'noodles')]:
        raise ValueError('selected_children_required')
    scanner = Path(config['scanner'])
    if (not scanner.is_absolute() or scanner.is_symlink() or scanner.stat().st_uid != 0
            or scanner.stat().st_mode & 0o022 or scanner.stat().st_size > MIB
            or hashlib.sha256(scanner.read_bytes()).hexdigest() != config['scanner_sha256']):
        raise ValueError('qualified_vendor_scanner_required')


def validate_browser_selection(value):
    if (not isinstance(value,dict) or set(value)!={'helper','sha256'}
            or not isinstance(value['helper'],str)
            or not Path(value['helper']).is_absolute()
            or not isinstance(value['sha256'],str) or len(value['sha256'])!=64
            or any(c not in '0123456789abcdef' for c in value['sha256'])):
        raise ValueError('qualified_browser_status_selection_required')


def validate_known_selection(value):
    if (not isinstance(value,dict) or not {'helper','sha256'}<=set(value) or set(value)-{'helper','sha256','assess_chromium','assess_freetype'}
            or type(value.get('assess_chromium',False)) is not bool or type(value.get('assess_freetype',False)) is not bool
            or (value.get('assess_freetype') and not value.get('assess_chromium'))):
        raise ValueError('explicit_known_exploitation_selection_required')
    validate_browser_selection({k:value[k] for k in ('helper','sha256')})


def browser_status(instance, selection):
    """Read own-user metadata only; never open tabs, start or stop browser units."""
    validate_browser_selection(selection)
    probe = 'selection='+repr(selection)+'\n'+r'''
import hashlib,json,pathlib,subprocess
p=pathlib.Path(selection['helper'])
if p.resolve()!=p or p.stat().st_size>65536:raise ValueError('browser_helper_path')
for item in [p,*p.parents]:
 info=item.stat()
 if info.st_uid!=0 or info.st_mode & 0o022:raise ValueError('browser_helper_custody')
if hashlib.sha256(p.read_bytes()).hexdigest()!=selection['sha256']:raise ValueError('browser_helper_bytes')
r=subprocess.run(['runuser','-u','agent','--','env','HOME=/home/agent',
 'XDG_RUNTIME_DIR=/run/user/1000','DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus',
 '/usr/bin/python3','-B','-I',str(p),'status'],capture_output=True,timeout=20)
if r.returncode not in (0,2) or len(r.stdout)>65536:raise ValueError('browser_status_read')
value=json.loads(r.stdout)
if value.get('schema')!='children-browser-status/v1':raise ValueError('browser_status_schema')
print(json.dumps(value))
'''
    value=json.loads(command(['incus','exec',instance,'--','/usr/bin/python3',
                              '-B','-I','-c',probe],seconds=25,limit=128*1024))
    if not isinstance(value,dict) or value.get('schema')!='children-browser-status/v1':
        raise ValueError('browser_status_schema')
    if value.get('state')=='standby':
        if value.get('intentional') is not True:raise ValueError('browser_standby_not_observed')
        result={'state':'standby','intentional':True}
    elif value.get('state')=='ready':
        bridge=value.get('bridge',{})
        if (not isinstance(bridge,dict) or bridge.get('running') is not True
                or bridge.get('extension_connected') is not True
                or bridge.get('version') not in ('2.0.22','v2.0.22')):
            raise ValueError('browser_connection_not_observed')
        result={'state':'ready','version':bridge['version'],'observation':'connection-metadata-only'}
    elif value.get('state')=='unavailable':
        result={'state':'unavailable','reason':'own_browser_status_unavailable'}
    else:raise ValueError('browser_status_unknown')
    return {**result,'checked':int(time.time()),'helper_sha256':selection['sha256']}


def validate_application_selection(selection):
    if (not isinstance(selection,dict) or not {'helper','sha256','units'}<=set(selection)
            or set(selection)-{'helper','sha256','units','browser_components'}
            or type(selection.get('browser_components',False)) is not bool):
        raise ValueError('explicit_application_selection_required')
    validate_browser_selection({k:selection[k] for k in ('helper','sha256')})
    units=selection['units']
    if not isinstance(units,dict) or set(units)!={'lordoftheflies','pixin','calipso','c-137','noodles'}:
        raise ValueError('five_application_targets_required')
    import re
    for names in units.values():
        if (not isinstance(names,list) or not 1<=len(names)<=8
                or any(not isinstance(n,str) or not re.fullmatch(r'[A-Za-z0-9_.@:-]{1,120}\.service',n) for n in names)
                or len(set(names))!=len(names)):
            raise ValueError('bounded_application_units_required')


def application_inventory(name, instance, selection):
    validate_application_selection(selection)
    code='selection='+repr(selection)+'\nname='+repr(name)+'\n'+r'''
import pathlib,hashlib,importlib.util,json
p=pathlib.Path(selection['helper'])
if p.resolve()!=p or not p.is_file() or p.stat().st_size>65536:raise ValueError('application_helper_path')
for item in [p,*p.parents]:
 info=item.stat()
 if info.st_uid!=0 or info.st_mode & 0o022:raise ValueError('application_helper_custody')
if hashlib.sha256(p.read_bytes()).hexdigest()!=selection['sha256']:raise ValueError('application_helper_bytes')
spec=importlib.util.spec_from_file_location('selected_application_reader',p)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
options={'include_browser_components':True} if selection.get('browser_components') and name!='lordoftheflies' else {}
print(json.dumps(m.collect(selection['units'][name],**options),sort_keys=True))
'''
    argv=['systemd-run','--unit=children-application-inventory-daily','--collect','--pipe','--wait',
          '-p','RuntimeMaxSec=40','-p','MemoryMax=128M','-p','CPUQuota=25%','-p','TasksMax=32',
          '/usr/bin/python3','-B','-I','-S','-c',code]
    if instance:argv=['incus','exec',instance,'--',*argv]
    value=json.loads(command(argv,seconds=55,limit=384*1024))
    if (not isinstance(value,dict) or value.get('schema')!='children-application-inventory/v1'
            or not isinstance(value.get('units'),dict)
            or set(value['units'])!=set(selection['units'][name])
            or any(not isinstance(v,dict) for v in value['units'].values())):
        raise ValueError('application_inventory_schema')
    complete=all(v.get('state')=='observed' for v in value['units'].values())
    if selection.get('browser_components') and instance:
        complete=complete and value.get('browser_components',{}).get('state')=='observed'
    return {**value,'state':'observed' if complete else 'unavailable',
            'helper_sha256':selection['sha256']}


def cleanup_receipt(instance):
    # Reconcile only the completed receipt; never restart a cleanup on read failure.
    code=r'''
import pathlib,json
p=pathlib.Path('/var/lib/children-maintenance/cache-cleanup/current.json')
with p.open('rb') as stream:raw=stream.read(65537)
if len(raw)>65536:raise ValueError('cleanup_receipt_capacity')
print(json.dumps(json.loads(raw)))
'''
    failure=None
    for attempt in range(2):
        raw=command(['incus','exec',instance,'--','/usr/bin/python3','-B','-I','-S','-c',code],
                    seconds=10,limit=64*1024)
        try:value=json.loads(raw)
        except ValueError as error:
            failure={'reason':type(error).__name__,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
            if attempt:raise
            continue
        if failure is not None:value={**value,'receipt_read_recovery':failure}
        return value


def validate_advisory_selection(selection):
    if not isinstance(selection,dict) or set(selection)!={'helper','sha256','public_names'}:
        raise ValueError('explicit_public_advisory_selection_required')
    validate_browser_selection({k:selection[k] for k in ('helper','sha256')})
    import re
    names=selection['public_names']
    if (not isinstance(names,list) or not 1<=len(names)<=64
            or any(not isinstance(n,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}',n) for n in names)
            or len({re.sub(r'[-_.]+','-',n).lower() for n in names})!=len(names)):
        raise ValueError('bounded_explicit_public_names_required')


def load_public_matcher(selection):
    import importlib.util
    helper=Path(selection['helper'])
    if helper.resolve()!=helper or not helper.is_file() or helper.stat().st_size>65536:
        raise ValueError('advisory_helper_path')
    for item in [helper,*helper.parents]:
        info=item.stat()
        if info.st_uid!=0 or info.st_mode & 0o022:raise ValueError('advisory_helper_custody')
    if hashlib.sha256(helper.read_bytes()).hexdigest()!=selection['sha256']:
        raise ValueError('advisory_helper_bytes')
    spec=importlib.util.spec_from_file_location('selected_public_advisories',helper)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def public_advisories(selection, inventories, root):
    validate_advisory_selection(selection)
    cache=root/'public-advisories';cache.mkdir(mode=0o700,exist_ok=True)
    if cache.is_symlink() or cache.stat().st_uid!=os.geteuid() or cache.stat().st_mode & 0o077:
        raise ValueError('private_advisory_state_required')
    current=cache/'current.json'
    def previous():
        if not current.exists():return None
        if current.is_symlink() or current.stat().st_size>128*1024:raise ValueError('advisory_state_capacity')
        value=json.loads(current.read_bytes())
        if value.get('schema')!='children-public-advisories/v1' or value.get('state')!='matched':
            raise ValueError('retained_advisory_schema')
        return value
    prior=previous()
    try:
        module=load_public_matcher(selection)
        result=module.match(inventories,selection['public_names'])
        if (result.get('schema')!='children-public-advisories/v1' or result.get('state')!='matched'
                or type(result.get('needs_triage')) is not bool):
            raise ValueError('public_advisory_result_schema')
        raw=json.dumps(result,sort_keys=True).encode()
        if len(raw)>128*1024:raise ValueError('public_advisory_receipt_capacity')
        if prior is not None:atomic(cache/'previous.json',current.read_bytes())
        atomic(current,raw)
    except (OSError,ValueError,KeyError,TypeError) as error:
        result={'schema':'children-public-advisories/v1','state':'unavailable','checked':int(time.time()),
                'reason':type(error).__name__,'last_success_checked':prior.get('checked') if prior else None,
                'last_success_query_sha256':prior.get('query_sha256') if prior else None,
                'coverage':'partial'}
    status={k:result[k] for k in ('schema','state','checked','reason','needs_triage','last_success_checked','last_success_query_sha256') if k in result}
    atomic(cache/'status.json',json.dumps(status,sort_keys=True).encode())
    return result


def known_exploitation(selection, candidates, report, root):
    """Preserve the last accepted intersection on source/input failure."""
    validate_known_selection(selection)
    cache=root/'known-exploitation';cache.mkdir(mode=0o700,exist_ok=True)
    if cache.is_symlink() or cache.stat().st_uid!=os.geteuid() or cache.stat().st_mode & 0o077:
        raise ValueError('private_kev_state_required')
    current=cache/'current.json';prior=None
    if current.exists():
        if current.is_symlink() or current.stat().st_size>128*1024:raise ValueError('kev_state_capacity')
        prior=json.loads(current.read_bytes())
        if prior.get('schema')!='children-known-exploitation/v1' or prior.get('state')!='matched':
            raise ValueError('retained_kev_schema')
    try:
        if (not report['targets'] or set(candidates)!=set(report['targets'])
                or any(v.get('debian_advisories')!='matched' for v in report['targets'].values())):
            raise ValueError('current_debian_matches_required')
        import re
        values={k:sorted(set(v)) for k,v in candidates.items()}
        public=report.get('public_advisories')
        if public is not None:
            if public.get('state')!='matched':raise ValueError('current_public_matches_required')
            values['public-python']=sorted({identifier for r in public['records'] if r['withdrawn'] is None
                for identifier in [r['id'],*r['aliases']] if re.fullmatch(r'CVE-[0-9]{4}-[0-9]{4,19}',identifier)})
        module=load_public_matcher(selection)
        result=module.match(values)
        if selection.get('assess_chromium'):
            contexts={name:module.chromium_context((root/name/'packages.status').read_text(),
                (root/name/'debian-findings.txt').read_text()) for name in ('pixin','calipso','c-137','noodles')}
            options={}
            if selection.get('assess_freetype'):
                options['freetype_components']={name:report['targets'][name]['applications'].get('browser_components',{})
                    for name in ('pixin','calipso','c-137','noodles')}
            result=module.assess_chromium(result,contexts,**options)
        if (result.get('schema')!='children-known-exploitation/v1' or result.get('state')!='matched'
                or type(result.get('needs_triage')) is not bool):raise ValueError('kev_result_schema')
        raw=json.dumps(result,sort_keys=True).encode()
        if len(raw)>128*1024:raise ValueError('kev_receipt_capacity')
        if prior is not None:atomic(cache/'previous.json',current.read_bytes())
        atomic(current,raw)
    except (OSError,ValueError,KeyError,TypeError) as error:
        result={'schema':'children-known-exploitation/v1','state':'unavailable','checked':int(time.time()),
                'reason':type(error).__name__,'coverage':'partial',
                'last_success_checked':prior.get('checked') if prior else None,
                'last_success_source_sha256':prior.get('source_sha256') if prior else None}
    status={k:result[k] for k in ('schema','state','checked','reason','needs_triage',
        'last_success_checked','last_success_source_sha256') if k in result}
    atomic(cache/'status.json',json.dumps(status,sort_keys=True).encode())
    return result


def phase_observations(config, report):
    """Describe this occurrence, never infer another producer's acceptance.

    Selected cleanup/browser/application phases can succeed while advisory
    applicability remains pending. A historical broad label must not erase that
    evidence, and a missing target must not become a vacuously successful phase.
    """
    targets = {row['id'] for row in config['targets']}
    guests = {row['id'] for row in config['targets'] if row['instance']}
    def phase(selected, expected, key, field, accepted):
        if not selected:
            return {'state': 'not-selected'}
        observed = sorted(name for name in expected
            if report['targets'].get(name, {}).get(key, {}).get(field) in accepted)
        missing = sorted(expected - set(observed))
        return {'state': 'observed' if expected and not missing else 'incomplete',
                'observed_targets': observed, 'unavailable_targets': missing}
    debian = sorted(name for name in targets
        if report['targets'].get(name, {}).get('debian_advisories') == 'matched')
    phases = {
        'debian_advisories': {'state': 'observed' if targets and set(debian) == targets else 'incomplete',
                             'observed_targets': debian,
                             'unavailable_targets': sorted(targets - set(debian))},
        'application_inventory': phase(bool(config.get('application_inventory')), targets,
            'applications', 'state', {'observed'}),
        'compiler_cleanup': phase(bool(config.get('compiler_cleanup_enabled')), guests,
            'compiler_cleanup', 'status', {'complete'}),
        'browser_metadata': phase(bool(config.get('browser_status')), guests,
            'browser', 'state', {'standby', 'ready'}),
        # These independent writers have their own native invocation and effect
        # receipts. Running this reader cannot establish their delivery/health.
        'package_transactions': {'state': 'external-producer'},
        'incident_delivery_and_missed_runs': {'state': 'external-observer'},
    }
    for key in ('public_advisories', 'known_exploitation'):
        if not config.get(key):
            phases[key] = {'state': 'not-selected'}
        else:
            value = report.get(key, {})
            phases[key] = {'state': 'observed' if value.get('state') == 'matched' else 'incomplete',
                           'applicability': 'pending' if value.get('needs_triage') is True
                               else 'no-selected-triage' if value.get('needs_triage') is False
                               and value.get('state') == 'matched' else 'unavailable'}
    return phases


def collect(config):
    validate(config)
    root = Path(config['state'])
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if root.is_symlink() or root.stat().st_uid != os.geteuid() or root.stat().st_mode & 0o077:
        raise ValueError('private_daily_state_required')
    with (root/'lock').open('a+b') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # No eviction of findings or pending incidents to admit another run.
        if footprint(root) > 384 * MIB:
            raise LimitError('daily_state_capacity')
        feed = root/'feed'
        feed.mkdir(mode=0o700, exist_ok=True)
        # Vendor whitelist grammar requires its version header even when empty.
        # Never inherit a host/user suppression list into these observations.
        whitelist = root/'no-suppressions'
        atomic(whitelist, b'VERSION 0\n')
        report = {'schema': 'cluster-children-daily-result/v1', 'started': int(time.time()),
                  'coverage': 'partial', 'targets': {}, 'source': {},
                  'unassessed': ['malicious-release-advisories',
                                 'full-application-provenance-loaded-state-and-exposure']}
        try:
            raw = fetch_feed()
            atomic(feed/'trixie', raw)
            report['source'] = {'state': 'fresh', 'sha256': hashlib.sha256(raw).hexdigest(),
                                'bytes': len(raw), 'checked': int(time.time())}
        except (OSError, ValueError, zlib.error) as error:
            report['source'] = {'state': 'unavailable', 'reason': type(error).__name__}
        kev_candidates={}
        for target in config['targets']:
            name = target['id']
            directory = root/name
            directory.mkdir(mode=0o700, exist_ok=True)
            value = None
            cleanup = None
            browser = None
            applications = None
            if config.get('application_inventory'):
                try:
                    applications=application_inventory(name,target['instance'],config['application_inventory'])
                except (OSError,ValueError,KeyError,subprocess.SubprocessError) as error:
                    applications={'state':'unavailable','reason':type(error).__name__,'checked':int(time.time())}
            if config.get('browser_status') and target['instance']:
                try:
                    browser=browser_status(target['instance'],config['browser_status'])
                except (OSError,ValueError,KeyError,subprocess.SubprocessError) as error:
                    browser={'state':'unavailable','reason':type(error).__name__,
                             'checked':int(time.time())}
            if config.get('compiler_cleanup_enabled') and target['instance']:
                try:
                    command(['incus','exec',target['instance'],'--','systemctl','start',
                             'children-cache-cleanup.service'],seconds=100,limit=64*1024)
                    cleanup=cleanup_receipt(target['instance'])
                    if cleanup.get('schema')!='children-cache-cleanup/v1' or cleanup.get('status')!='complete':
                        raise ValueError('compiler_cleanup_incomplete')
                except (OSError,ValueError,KeyError,subprocess.SubprocessError) as error:
                    cleanup={**(cleanup or {}),'status':'unavailable','reason':type(error).__name__}
            try:
                argv = ['/usr/bin/python3', '-B', '-I', '-c', PROBE]
                if target['instance']:
                    argv = ['incus', 'exec', target['instance'], '--', *argv]
                value = json.loads(command(argv))
                if value['os'] != {'ID': 'debian', 'VERSION_ID': '13', 'VERSION_CODENAME': 'trixie'}:
                    raise ValueError('unsupported_distribution')
                status = value.pop('package_status').encode()
                if len(status) > 4*MIB:
                    raise LimitError('package_inventory_limit')
                atomic(directory/'packages.status', status)
                value.update(inventory='observed', inventory_sha256=hashlib.sha256(status).hexdigest(),
                             debian_advisories='unassessed')
                if cleanup is not None:value['compiler_cleanup']=cleanup
                if browser is not None:value['browser']=browser
                if applications is not None:value['applications']=applications
                if report['source']['state'] == 'fresh':
                    found = command(['/usr/bin/python3', config['scanner'], '--suite', 'trixie',
                        '--source', feed.as_uri(), '--status', str(directory/'packages.status'),
                        '--format', 'simple', '--config', '/dev/null', '--whitelist', str(whitelist)],
                        seconds=40, limit=4*MIB)
                    # Preserve exact current findings, including unfixed vulnerabilities.
                    atomic(directory/'debian-findings.txt', found)
                    if config.get('known_exploitation'):
                        import re
                        kev_candidates[name]=sorted({word for word in found.decode().split()
                            if re.fullmatch(r'CVE-[0-9]{4}-[0-9]{4,19}',word)})
                    value.update(debian_advisories='matched',
                                 vulnerability_pairs=len(set(found.decode().splitlines())))
                raw = json.dumps(value, sort_keys=True).encode()
                if len(raw) > 256*1024:
                    raise LimitError('resource_receipt_limit')
                current = directory/'current.json'
                if current.exists() and json.loads(current.read_bytes()).get('debian_advisories') == 'matched':
                    atomic(directory/'previous.json', current.read_bytes())
                atomic(current, raw)
                report['targets'][name] = value
            except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
                observed = value if value is not None and value.get('inventory') == 'observed' else {}
                report['targets'][name] = {**observed,
                    **({'compiler_cleanup':cleanup} if cleanup is not None else {}),
                    **({'browser':browser} if browser is not None else {}),
                    **({'applications':applications} if applications is not None else {}),
                    'inventory': 'observed' if observed else 'unavailable',
                    'debian_advisories': 'unassessed', 'reason': type(error).__name__}
        if config.get('public_advisories'):
            report['public_advisories']=public_advisories(config['public_advisories'],
                [v.get('applications',{}) for v in report['targets'].values()],root)
        if config.get('known_exploitation'):
            report['known_exploitation']=known_exploitation(config['known_exploitation'],kev_candidates,report,root)
        report['phases'] = phase_observations(config, report)
        report['finished'] = int(time.time())
        raw = json.dumps(report, sort_keys=True).encode()
        if len(raw) > 256*1024 or footprint(root) > 512*MIB:
            raise LimitError('daily_state_capacity')
        atomic(root/'current.json', raw)
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    result = collect(json.loads(args.config.read_text()))
    print(json.dumps({'coverage': result['coverage'], 'source': result['source']['state'],
                      'targets': {k: v.get('debian_advisories') for k, v in result['targets'].items()}}))
    return 0 if result['source']['state'] == 'fresh' and all(
        value.get('debian_advisories') == 'matched'
        and value.get('compiler_cleanup',{}).get('status','complete')=='complete'
        and value.get('browser',{}).get('state','standby') in ('standby','ready')
        and value.get('applications',{}).get('state','observed')=='observed'
        for value in result['targets'].values()) and (
        result.get('public_advisories',{}).get('state','matched')=='matched'
        and result.get('public_advisories',{}).get('needs_triage',False) is False
        and result.get('known_exploitation',{}).get('state','matched')=='matched'
        and result.get('known_exploitation',{}).get('needs_triage',False) is False) else 2


if __name__ == '__main__':
    raise SystemExit(main())
