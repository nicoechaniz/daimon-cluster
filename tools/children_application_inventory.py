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

MAX_FILE=128*1024*1024
MAX_METADATA=65536
MAX_OUTPUT=256*1024


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


def collect(units, proc=Path('/proc'), seconds=25):
    if not 1<=len(units)<=8 or len(set(units))!=len(units):
        raise ValueError('bounded_unique_service_selection_required')
    deadline=time.monotonic()+seconds;remaining=MAX_FILE;images={}
    def check():
        if time.monotonic()>deadline:raise ValueError('application_inventory_deadline')
    report={'schema':'children-application-inventory/v1','checked':int(time.time()),
            'coverage':'partial','process_scope':'selected-systemd-main-processes-only','units':{},'environments':{},
            'unassessed':['upstream-advisory-applicability','malicious-artifacts',
                          'non-Python-dependencies','artifact-upstream-authenticity']}
    for unit in units:
        value={};report['units'][unit]=value
        try:
            check();props=properties(unit);pid=int(props.get('MainPID','0'))
            if props.get('ActiveState')!='active' or pid<=0:raise ValueError('selected_service_not_running')
            image=proc/str(pid)/'exe';target=str(image.readlink());value.update(pid=pid,executable=target)
            with image.open('rb') as stream:
                before=os.fstat(stream.fileno())
                identity=(before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)
                if identity in images:hex_digest=images[identity]
                else:
                    if before.st_size>remaining:raise ValueError('executable_hash_capacity')
                    digest=hashlib.sha256()
                    while True:
                        check();chunk=stream.read(1024*1024)
                        if not chunk:break
                        remaining-=len(chunk)
                        if remaining<0:raise ValueError('executable_hash_capacity')
                        digest.update(chunk)
                    hex_digest=digest.hexdigest();images[identity]=hex_digest
                after=os.fstat(stream.fileno())
                if (before.st_dev,before.st_ino,before.st_size)!=(after.st_dev,after.st_ino,after.st_size):
                    raise ValueError('executable_changed_during_read')
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
            latest=properties(unit)
            if latest.get('MainPID')!=str(pid) or latest.get('ActiveState')!='active':
                raise ValueError('service_changed_during_observation')
            value['state']='observed'
        except (OSError,ValueError,KeyError,subprocess.SubprocessError) as error:
            value.update(state='unavailable',reason=str(error) if type(error) is ValueError else type(error).__name__)
    if len(json.dumps(report).encode())>MAX_OUTPUT:raise ValueError('application_receipt_capacity')
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--units',nargs='+',required=True)
    args=p.parse_args()
    try:
        report=collect(args.units);print(json.dumps(report,sort_keys=True))
        return 0 if all(v.get('state')=='observed' for v in report['units'].values()) else 2
    except (OSError,ValueError,subprocess.SubprocessError) as error:
        print(json.dumps({'schema':'children-application-inventory/v1','state':'unavailable',
                          'reason':type(error).__name__}));return 2


if __name__=='__main__':raise SystemExit(main())
