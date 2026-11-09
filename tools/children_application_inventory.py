#!/usr/bin/env python3
"""Read selected live executables and Python metadata without loading packages."""
import argparse
import email.parser
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import stat
import ipaddress
import sys

MAX_FILE=128*1024*1024
MAX_METADATA=65536
MAX_OUTPUT=256*1024


def image_identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def process_start(process):
    # comm may contain spaces and parentheses; only its final delimiter ends it.
    with (process/'stat').open('rb') as stream:
        raw = stream.read(4097)
    fields = raw.rpartition(b') ')[2].split()
    if len(raw)>4096 or len(fields)<20 or not fields[19].isdigit() or int(fields[19])<=0:
        raise ValueError('process_identity_unavailable')
    return int(fields[19])


def process_listeners(process, check=lambda: None):
    """Read this main process's sockets; never connect or inspect remote peers."""
    def sockets():
        result = set()
        with os.scandir(process/'fd') as entries:
            for count, entry in enumerate(entries, 1):
                check()
                if count > 1024:
                    raise ValueError('network_descriptor_capacity')
                target = os.readlink(entry.path)
                match = re.fullmatch(r'socket:\[(\d+)\]', target)
                if match:
                    result.add(int(match[1]))
        return result
    owned = sockets()
    listeners, matched = [], set()
    for table, protocol, family in (('tcp', 'tcp', 4), ('tcp6', 'tcp', 6),
                                    ('udp', 'udp', 4), ('udp6', 'udp', 6)):
        check()
        with (process/'net'/table).open('rb') as stream:
            raw = stream.read(128*1024+1)
        if len(raw) > 128*1024:
            raise ValueError('network_table_capacity')
        lines = raw.decode('ascii').splitlines()
        if not lines or 'local_address' not in lines[0] or len(lines) > 2049:
            raise ValueError('network_table_shape')
        for line in lines[1:]:
            check()
            fields = line.split()
            if len(fields) < 10 or not fields[9].isdigit():
                raise ValueError('network_table_shape')
            inode = int(fields[9])
            if inode not in owned:
                continue
            matched.add(inode)
            if protocol == 'tcp' and fields[3] != '0A':
                continue
            address, port = fields[1].split(':')
            if (re.fullmatch('[0-9A-Fa-f]{8}' if family == 4 else '[0-9A-Fa-f]{32}', address) is None
                    or re.fullmatch('[0-9A-Fa-f]{4}', port) is None):
                raise ValueError('network_local_address_shape')
            packed = bytes.fromhex(address)
            if sys.byteorder == 'little':
                packed = b''.join(packed[i:i+4][::-1] for i in range(0, len(packed), 4))
            ip = ipaddress.ip_address(packed)
            scope = ('wildcard' if ip.is_unspecified else 'loopback' if ip.is_loopback
                     else 'link-local' if ip.is_link_local else 'private' if ip.is_private
                     else 'global' if ip.is_global else 'other')
            if int(port, 16):
                listeners.append(dict(protocol=protocol, family=family, port=int(port, 16), bind_scope=scope))
            if len(listeners) > 128:
                raise ValueError('network_listener_capacity')
    if sockets() != owned:
        raise ValueError('network_descriptors_changed_during_observation')
    return dict(state='observed', scope='selected-main-process-owned-TCP-listeners-and-bound-UDP',
        listeners=sorted(listeners, key=lambda v: (v['protocol'], v['family'], v['port'], v['bind_scope'])),
        unmatched_socket_count=len(owned-matched),
        unassessed=['worker-descendants', 'non-TCP-UDP-sockets', 'firewall-NAT-and-peer-reachability'])


def browser_components(check=lambda:None, root=Path('/'), owner_uid=0, run=subprocess.run, budget=4*1024*1024):
    """Inspect dynamic metadata and a standard library file, never run Chromium/ldd."""
    binary=root/'usr/lib/chromium/chromium';before=binary.stat()
    def identity(info):return (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
    if (binary.is_symlink() or not stat.S_ISREG(before.st_mode) or before.st_uid!=owner_uid
            or before.st_mode & 0o022 or not 0<before.st_size<=512*1024*1024):
        raise ValueError('browser_component_binary_custody')
    check()
    reply=run(['/usr/bin/readelf','-dW',str(binary)],capture_output=True,timeout=5,
              env={**os.environ,'LC_ALL':'C'})
    check()
    if reply.returncode or len(reply.stdout)+len(reply.stderr)>65536:
        raise ValueError('bounded_dynamic_metadata_required')
    if identity(binary.stat())!=identity(before):raise ValueError('browser_changed_during_metadata_read')
    text=reply.stdout.decode();needed=re.findall(r'\(NEEDED\).*?\[([^]]+)\]',text)
    if (not needed or len(needed)>256 or len(set(needed))!=len(needed)
            or any(not re.fullmatch(r'[A-Za-z0-9_.+\-]{1,128}',v) for v in needed)):
        raise ValueError('browser_dynamic_dependencies_shape')
    standard=root/'usr/lib/x86_64-linux-gnu';alias=standard/'libfreetype.so.6';library=alias.resolve(strict=True)
    if standard.resolve()!=standard or not library.is_relative_to(standard):raise ValueError('nonstandard_freetype_target')
    for p in [alias,*alias.parents,library]:
        if not p.is_relative_to(root):continue
        info=p.lstat()
        if info.st_uid!=owner_uid or (not p.is_symlink() and info.st_mode & 0o022):
            raise ValueError('freetype_component_custody')
    with library.open('rb') as stream:
        first=os.fstat(stream.fileno())
        if not stat.S_ISREG(first.st_mode) or not 0<first.st_size<=min(4*1024*1024,budget):
            raise ValueError('freetype_component_capacity')
        raw=stream.read(min(4*1024*1024,budget)+1);check();last=os.fstat(stream.fileno())
    if (len(raw)!=first.st_size or identity(first)!=identity(last) or identity(library.stat())!=identity(first)
            or alias.resolve(strict=True)!=library):
        raise ValueError('freetype_changed_during_read')
    return {'state':'observed','scope':'static-package-dependency-only','direct_freetype_needed':'libfreetype.so.6' in needed,
            'custom_search_path':bool(re.search(r'\((?:RPATH|RUNPATH)\)',text)),
            'chromium_bytes':before.st_size,'dynamic_metadata_sha256':hashlib.sha256(reply.stdout).hexdigest(),
            'freetype_standard_path':True,'freetype_file_bytes':len(raw),'freetype_file_sha256':hashlib.sha256(raw).hexdigest(),
            'unassessed':['upstream-artifact-authenticity','actual-runtime-loader-environment','loaded-module-and-exposure']}


def properties(unit):
    if not isinstance(unit,str) or not re.fullmatch(r'[A-Za-z0-9_.@:-]{1,120}\.service',unit):
        raise ValueError('explicit_service_required')
    p=subprocess.run(['/usr/bin/systemctl','show',unit,'-p','LoadState','-p','ActiveState',
                      '-p','MainPID','-p','WorkingDirectory'],capture_output=True,timeout=3)
    if p.returncode or len(p.stdout)>8192:raise ValueError('bounded_service_read_required')
    return dict(line.split('=',1) for line in p.stdout.decode().splitlines() if '=' in line)


def metadata(site, check):
    """Parse METADATA as data. Never import packages, execute .pth or read direct URLs."""
    result=[];count=0
    with os.scandir(site) as entries:
        for item in entries:
            check();count+=1
            if count>1024:raise ValueError('environment_entry_capacity')
            if not item.name.endswith('.dist-info'):continue
            if len(result)>=256:raise ValueError('distribution_capacity')
            directory=Path(item.path);p=directory/'METADATA'
            if directory.is_symlink() or p.is_symlink() or not p.is_file():
                raise ValueError('regular_distribution_metadata_required')
            size=p.stat().st_size
            with p.open('rb') as stream:raw=stream.read(MAX_METADATA+1)
            # Long package descriptions are not needed for version identity.
            ends=[pos+len(delimiter) for delimiter in (b'\n\n',b'\r\n\r\n')
                  if (pos:=raw.find(delimiter))>=0]
            headers=raw[:min(ends)] if ends else raw
            if len(headers)>MAX_METADATA:raise ValueError('metadata_header_capacity')
            value=email.parser.BytesParser().parsebytes(headers,headersonly=True)
            name=value.get('Name','');version=value.get('Version','')
            if (not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}',name)
                    or not re.fullmatch(r'[A-Za-z0-9.!+_-]{1,128}',version)):
                raise ValueError('bounded_distribution_identity_required')
            result.append({'name':name,'version':version,'metadata_header_sha256':hashlib.sha256(headers).hexdigest(),'metadata_file_bytes':size,
                'direct_url_present':(directory/'direct_url.json').exists()})
    return sorted(result,key=lambda v:(v['name'].lower(),v['version']))


def declared_python_paths(process):
    # Select only this path key in memory; never retain the complete environment.
    with (process/'environ').open('rb') as stream:raw=stream.read(65537)
    if len(raw)>65536:raise ValueError('process_path_metadata_capacity')
    result=[]
    for item in raw.split(b'\0'):
        key,_,value=item.partition(b'=')
        if key!=b'PYTHONPATH':continue
        for name in os.fsdecode(value).split(os.pathsep):
            if not name:continue
            if len(result)>=8 or len(name)>4096 or not Path(name).is_absolute():
                raise ValueError('explicit_bounded_Python_paths_required')
            result.append(Path(name))
    return result


PUBLIC_ROOTS = (Path('/opt/daimon-app'), Path('/usr/libexec/incus'),
                Path('/opt/daimon-onboarding-runtime'))
TRUSTED_UID = 0


def validate_deployments(value, units):
    if (not isinstance(value, dict) or set(value) != {'schema', 'units'}
            or value['schema'] != 'children-selected-deployments/v1'
            or not isinstance(value['units'], dict) or not 1 <= len(value['units']) <= 8
            or not set(value['units']) <= set(units)):
        raise ValueError('selected_deployment_manifest_shape')
    total = 0
    for row in value['units'].values():
        if (not isinstance(row, dict) or set(row) != {'root', 'bind', 'source_ref', 'files'}
                or row['bind'] not in {'cwd', 'executable', 'python-script'}
                or not isinstance(row['source_ref'], str)
                or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9:/#._-]{0,255}', row['source_ref']) is None
                or not isinstance(row['root'], str) or not Path(row['root']).is_absolute()
                or '..' in Path(row['root']).parts
                or not any(Path(row['root']).is_relative_to(p) for p in PUBLIC_ROOTS)
                or not isinstance(row['files'], dict) or not row['files']):
            raise ValueError('selected_deployment_manifest_shape')
        for name, pin in row['files'].items():
            if (not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_./-]{1,240}', name)
                    or name.startswith('/') or any(p in {'', '.', '..', '__pycache__'} for p in name.split('/'))
                    or name.endswith('.pyc') or not isinstance(pin, str)
                    or re.fullmatch('[a-f0-9]{64}', pin) is None):
                raise ValueError('selected_deployment_file_shape')
            total += 1
            if total > 1024:
                raise ValueError('selected_deployment_file_capacity')
    return value


def load_deployments(path, expected, units):
    path = Path(path)
    if not isinstance(expected, str) or re.fullmatch('[a-f0-9]{64}', expected) is None:
        raise ValueError('selected_deployment_manifest_pin')
    for item in (path, *path.parents):
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != TRUSTED_UID or info.st_mode & 0o022:
            raise ValueError('selected_deployment_manifest_custody')
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != TRUSTED_UID
                or info.st_mode & 0o022 or info.st_size > 256*1024):
            raise ValueError('selected_deployment_manifest_capacity')
        raw = stream.read(256*1024+1)
    if len(raw) > 256*1024 or hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('selected_deployment_manifest_pin')
    return validate_deployments(json.loads(raw), units)


def deployment_files(root, check):
    stack, files, nodes = [root], set(), 0
    while stack:
        directory = stack.pop()
        check()
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != TRUSTED_UID or info.st_mode & 0o022):
            raise ValueError('selected_deployment_directory_custody')
        with os.scandir(directory) as entries:
            for entry in entries:
                check()
                nodes += 1
                if nodes > 1024:
                    raise ValueError('selected_deployment_file_capacity')
                if entry.is_symlink():
                    raise ValueError('selected_deployment_symlink')
                if entry.name == '__pycache__' or entry.name.endswith('.pyc'):
                    continue
                if entry.is_dir(follow_symlinks=False):
                    stack.append(Path(entry.path))
                elif entry.is_file(follow_symlinks=False):
                    files.add(str(Path(entry.path).relative_to(root)))
                else:
                    raise ValueError('selected_deployment_regular_file_required')
    return files


def python_script_entrypoint(process, image, root, files):
    """Observe the actual interpreter's script argument, never execute source.

    The remaining arguments may contain private configuration; retain none.
    Python -c/-m and option-based script substitution are not script bindings.
    """
    if re.fullmatch(r'python3(?:\.\d+)?', image.name) is None:
        raise ValueError('selected_deployment_python_interpreter_required')
    with (process/'cmdline').open('rb') as stream:
        raw = stream.read(4097)
    if len(raw) > 4096:
        raise ValueError('command_metadata_capacity')
    argv = raw.split(b'\0')
    index = 1
    while index < len(argv) and argv[index] in {b'-B', b'-I', b'-S', b'-u', b'-E', b'-s'}:
        index += 1
    if index < len(argv) and argv[index] == b'--':
        index += 1
    if index >= len(argv):
        raise ValueError('selected_deployment_python_script_changed')
    script = Path(os.fsdecode(argv[index]))
    if (not script.is_absolute() or '..' in script.parts or not script.is_relative_to(root)
            or str(script.relative_to(root)) not in files):
        raise ValueError('selected_deployment_python_script_changed')
    return str(script.relative_to(root))


def verify_deployment(row, process, image, hashed, check):
    root = Path(row['root'])
    if root.resolve() != root:
        raise ValueError('selected_deployment_symlink')
    for parent in (root, *root.parents):
        info = parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != TRUSTED_UID or info.st_mode & 0o022):
            raise ValueError('selected_deployment_directory_custody')
        if parent in PUBLIC_ROOTS:
            break
    entrypoint = None
    if row['bind'] == 'python-script':
        entrypoint = python_script_entrypoint(process, image, root, row['files'])
    elif row['bind'] == 'cwd':
        if (process/'cwd').resolve() != root:
            raise ValueError('selected_deployment_cwd_changed')
    elif not image.is_relative_to(root) or str(image.relative_to(root)) not in row['files']:
        raise ValueError('selected_deployment_executable_changed')
    if deployment_files(root, check) != set(row['files']):
        raise ValueError('selected_deployment_file_set_changed')
    identities = {}
    for name, pin in sorted(row['files'].items()):
        check()
        path = root/name
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != TRUSTED_UID
                    or before.st_mode & 0o022):
                raise ValueError('selected_deployment_file_custody')
            identity, observed = hashed(stream)
        if observed != pin:
            raise ValueError('selected_deployment_file_changed')
        identities[name] = identity
    if deployment_files(root, check) != set(row['files']):
        raise ValueError('selected_deployment_file_set_changed')
    for name, identity in identities.items():
        check()
        if image_identity((root/name).stat()) != identity:
            raise ValueError('selected_deployment_file_changed')
    if row['bind'] == 'cwd' and (process/'cwd').resolve() != root:
        raise ValueError('selected_deployment_cwd_changed')
    if row['bind'] == 'python-script' and python_script_entrypoint(process, image, root, row['files']) != entrypoint:
        raise ValueError('selected_deployment_python_script_changed')
    return {'state': 'verified', 'source_ref': row['source_ref'], 'bind': row['bind'],
            'files': len(row['files']), 'loaded_main_executable': row['bind'] == 'executable',
            **({'python_entrypoint': entrypoint} if entrypoint is not None else {}),
            'meaning': 'Selected files and process association; Python imported modules, dependency authenticity and exposure remain unassessed'}


def collect(units, proc=Path('/proc'), seconds=25, include_browser_components=False, deployments=None,
            include_network_listeners=False):
    if not 1<=len(units)<=8 or len(set(units))!=len(units):
        raise ValueError('bounded_unique_service_selection_required')
    if deployments is not None:
        validate_deployments(deployments, units)
    deadline=time.monotonic()+seconds;remaining=MAX_FILE;images={}
    def check():
        if time.monotonic()>deadline:raise ValueError('application_inventory_deadline')
    def hashed(stream):
        nonlocal remaining
        before = os.fstat(stream.fileno())
        identity = image_identity(before)
        if identity in images:
            hex_digest = images[identity]
        else:
            if before.st_size > remaining:
                raise ValueError('executable_hash_capacity')
            digest = hashlib.sha256()
            while True:
                check()
                chunk = stream.read(1024*1024)
                if not chunk:
                    break
                remaining -= len(chunk)
                if remaining < 0:
                    raise ValueError('executable_hash_capacity')
                digest.update(chunk)
            hex_digest = digest.hexdigest()
            images[identity] = hex_digest
        if identity != image_identity(os.fstat(stream.fileno())):
            raise ValueError('executable_changed_during_read')
        return identity, hex_digest
    report={'schema':'children-application-inventory/v1','checked':int(time.time()),
            'coverage':'partial','process_scope':'selected-systemd-main-processes-only','units':{},'environments':{},
            'unassessed':['upstream-advisory-applicability','malicious-artifacts',
                          'non-Python-dependencies','artifact-upstream-authenticity']}
    for unit in units:
        value={};report['units'][unit]=value
        try:
            check();props=properties(unit);pid=int(props.get('MainPID','0'))
            if props.get('ActiveState')!='active' or pid<=0:raise ValueError('selected_service_not_running')
            process=proc/str(pid);started=process_start(process)
            image=process/'exe';target=str(image.readlink())
            value.update(pid=pid,process_start_ticks=started,executable=target)
            with image.open('rb') as stream:
                before=os.fstat(stream.fileno())
                identity,hex_digest=hashed(stream)
            value.update(executable_sha256=hex_digest,executable_bytes=before.st_size)
            with (proc/str(pid)/'cmdline').open('rb') as stream:command=stream.read(4097)
            if len(command)>4096:raise ValueError('command_metadata_capacity')
            # Only the executable path is retained; no arguments/environment/secrets.
            entry=Path(os.fsdecode(command.split(b'\0',1)[0]));value['command_executable']=str(entry)
            sites=declared_python_paths(proc/str(pid))
            value['declared_PYTHONPATH']=[str(p) for p in sites]
            if entry.is_absolute():
                environment=entry.parent.parent
                if (environment/'pyvenv.cfg').is_file():
                    with os.scandir(environment/'lib') as versions:
                        count=0
                        for version in versions:
                            check();count+=1
                            if count>16:raise ValueError('Python_environment_capacity')
                            if re.fullmatch(r'python3\.\d{1,2}',version.name):
                                site=Path(version.path)/'site-packages'
                                if site.is_dir():sites.append(site)
                    value['Python_environment']=str(environment)
            for site in sites:
                check();key=str(site)
                if key not in report['environments']:
                    if len(report['environments'])>=8:raise ValueError('Python_path_capacity')
                    report['environments'][key]={'ecosystem':'unqualified-Python-metadata',
                        'packages':metadata(site,check),'source':'installed-metadata-only; not package-code execution'}
            if deployments is not None and unit in deployments['units']:
                value['deployment'] = verify_deployment(deployments['units'][unit], process,
                    Path(target), hashed, check)
            if include_network_listeners:
                value['network_listeners'] = process_listeners(process, check)
            latest=properties(unit)
            if latest.get('MainPID')!=str(pid) or latest.get('ActiveState')!='active':
                raise ValueError('service_changed_during_observation')
            if process_start(process)!=started:
                raise ValueError('process_changed_during_observation')
            if image_identity(image.stat())!=identity or str(image.readlink())!=target:
                raise ValueError('executable_changed_during_observation')
            if (deployments is not None and unit in deployments['units']
                    and deployments['units'][unit]['bind'] == 'cwd'
                    and (process/'cwd').resolve() != Path(deployments['units'][unit]['root'])):
                raise ValueError('selected_deployment_cwd_changed')
            if (deployments is not None and unit in deployments['units']
                    and deployments['units'][unit]['bind'] == 'python-script'
                    and python_script_entrypoint(process, Path(target),
                        Path(deployments['units'][unit]['root']), deployments['units'][unit]['files'])
                        != value['deployment']['python_entrypoint']):
                raise ValueError('selected_deployment_python_script_changed')
            value['state']='observed'
        except (OSError,ValueError,KeyError,subprocess.SubprocessError) as error:
            value.update(state='unavailable',reason=str(error) if type(error) is ValueError else type(error).__name__)
    if include_browser_components:
        try:report['browser_components']=browser_components(check,budget=remaining)
        except (OSError,ValueError,subprocess.SubprocessError) as error:
            report['browser_components']={'state':'unavailable','reason':str(error) if type(error) is ValueError else type(error).__name__}
    if len(json.dumps(report).encode())>MAX_OUTPUT:raise ValueError('application_receipt_capacity')
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--units',nargs='+',required=True)
    p.add_argument('--browser-components',action='store_true')
    p.add_argument('--network-listeners',action='store_true')
    p.add_argument('--deployment-manifest',type=Path)
    p.add_argument('--deployment-manifest-sha256')
    args=p.parse_args()
    try:
        if (args.deployment_manifest is None) != (args.deployment_manifest_sha256 is None):
            raise ValueError('selected_deployment_manifest_pin')
        deployments = (load_deployments(args.deployment_manifest,args.deployment_manifest_sha256,args.units)
            if args.deployment_manifest is not None else None)
        report=collect(args.units,include_browser_components=args.browser_components,deployments=deployments,
                       include_network_listeners=args.network_listeners)
        print(json.dumps(report,sort_keys=True))
        return 0 if all(v.get('state')=='observed' for v in report['units'].values()) and report.get('browser_components',{}).get('state','observed')=='observed' else 2
    except (OSError,ValueError,subprocess.SubprocessError) as error:
        print(json.dumps({'schema':'children-application-inventory/v1','state':'unavailable',
                          'reason':type(error).__name__}));return 2


if __name__=='__main__':raise SystemExit(main())
