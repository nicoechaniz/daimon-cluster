#!/usr/bin/env python3
"""Qualify the read-only package guard using real APT and inert local fixtures.

The source/maintainer fields in fixture manifests imitate a qualified selection
solely to test the wire seam. No signed selection or production grant is created.
Requires APT3.0.3; Debug::pkgDPkgPM prevents package writes. No model or timer.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('guard', type=Path)
    parser.add_argument('--state', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('requires the selected guest operator')
    os.umask(0o077)
    root = args.state.absolute()
    if root.exists():
        parser.error('inspect existing qualification before choosing a continuation')
    root.mkdir(parents=True, mode=0o700)
    guard=Path(args.guard);source_sha=hashlib.sha256(guard.read_bytes()).hexdigest()
    assert guard.is_file() and guard.stat().st_uid==0
    v=subprocess.run(['apt-get','--version'],capture_output=True,text=True,check=True).stdout.splitlines()[0];assert v=='apt 3.0.3 (amd64)',v
    status=Path('/var/lib/dpkg/status');before=hashlib.sha256(status.read_bytes()).hexdigest()
    f=root/'fixture';f.mkdir(mode=0o700,exist_ok=True)
    for n in ['archives','state','lists','log','empty']: (f/n).mkdir(mode=0o700,exist_ok=True)
    (f/'sources.list').write_text('')
    manifest={'schema':'children-reviewed-apt-transaction/v1','source':'verified-local-debian-security','maintainer_reviewed':True,'packages':{}}
    # The manifest/source fields below are synthetic protocol fixtures, not a signed
    # package selection or an authorization for any production package transaction.
    archives={}
    for name in ['chromium','chromium-common','systemd']:
     p=f/('build-'+name);(p/'DEBIAN').mkdir(parents=True,mode=0o755,exist_ok=True);(p/'DEBIAN').chmod(0o755)
     (p/'DEBIAN/control').write_text('Package: '+name+'\nVersion: 2\nArchitecture: amd64\nMaintainer: Operator fixture <fixture@invalid>\nDescription: Synthetic protocol qualification; never installed\n')
     (p/'DEBIAN/control').chmod(0o644)
     (p/'usr/share/children-apt-fixture').mkdir(parents=True,exist_ok=True)
     (p/'usr/share/children-apt-fixture'/name).write_text('synthetic; no child content\n')
     archive=f/'archives'/(name+'_2_amd64.deb')
     build=subprocess.run(['dpkg-deb','--build','--root-owner-group',str(p),str(archive)],capture_output=True,text=True,timeout=10)
     if build.returncode:(root/('build-'+name+'.stderr')).write_text(build.stderr);raise RuntimeError('Inspect retained synthetic package build output')
     archives[name]=archive
     if name!='systemd':manifest['packages'][name]={'old_version':'1','version':'2','archive':str(archive),'sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'bytes':archive.stat().st_size}
    (f/'state/status').write_text('\n\n'.join('Package: '+n+'\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1\nDescription: Synthetic fixture\n' for n in archives)+'\n')
    fake_before=hashlib.sha256((f/'state/status').read_bytes()).hexdigest()
    m=f/'manifest.json';m.write_text(json.dumps(manifest));m.chmod(0o600)
    hook=shlex.join(['/usr/bin/python3','-B','-I',str(guard),'--manifest',str(m)])
    config=f/'apt.conf';config.write_text('Dir::Etc::Parts "'+str(f/'empty')+'";\nDir::Etc::Main "/dev/null";\n')
    base=['apt-get','-y','--no-download','--no-remove','-o','Debug::pkgDPkgPM=true','-o','Dir::State='+str(f/'state'),'-o','Dir::State::status='+str(f/'state/status'),'-o','Dir::State::lists='+str(f/'lists'),'-o','Dir::Cache='+str(f/'cache'),'-o','Dir::Cache::archives='+str(f/'archives'),'-o','Dir::Log='+str(f/'log'),'-o','Dir::Etc::sourcelist='+str(f/'sources.list'),'-o','Dir::Etc::sourceparts='+str(f/'empty'),'-o','APT::Sandbox::User=root','-o','DPkg::Pre-Install-Pkgs::='+hook,'-o','DPkg::Tools::Options::/usr/bin/python3::Version=2','install']
    env={**os.environ,'APT_CONFIG':str(config),'DEBIAN_FRONTEND':'noninteractive'}
    results={}
    def run(label,packages,decision,reason=None):
     p=subprocess.run([*base,*[str(archives[n]) for n in packages]],capture_output=True,text=True,env=env,timeout=30)
     text=p.stdout+p.stderr;assert len(text.encode())<128*1024
     (root/(label+'.log')).write_text(text)
     rows=[]
     for line in text.splitlines():
      try:r=json.loads(line)
      except ValueError:continue
      if isinstance(r,dict) and r.get('schema')=='children-apt-guard-result/v1':rows.append(r)
     assert len(rows)==1,(label,p.returncode,text[-4000:]);r=rows[0]
     assert r['decision']==decision and r['package_write_performed'] is False,(label,r)
     assert (p.returncode==0)==(decision=='admitted'),(label,p.returncode)
     if reason:assert r['reason']==reason,(label,r)
     assert hashlib.sha256(status.read_bytes()).hexdigest()==before
     assert hashlib.sha256((f/'state/status').read_bytes()).hexdigest()==fake_before
     results[label]={'apt_exit':p.returncode,'guard':r,'global_dpkg_unchanged':True,'fixture_status_unchanged':True,'log_sha256':hashlib.sha256(text.encode()).hexdigest()}
    run('reviewed-fixture',['chromium','chromium-common'],'admitted')
    run('important-service-fixture',['chromium','chromium-common','systemd'],'deferred','unreviewed_packages')
    child=subprocess.Popen(['/usr/bin/python3','-I','-c',"import ctypes,time;ctypes.CDLL(None).prctl(15,b'chromium',0,0,0);time.sleep(30)"])
    try:
     deadline=time.monotonic()+5
     while Path('/proc',str(child.pid),'comm').read_text().strip()!='chromium':
      assert time.monotonic()<deadline;time.sleep(.02)
     run('active-browser-fixture',['chromium','chromium-common'],'deferred','browser_active')
    finally:child.terminate();child.wait(timeout=5)
    manifest['packages']['chromium']['sha256']='0'*64;m.write_text(json.dumps(manifest));m.chmod(0o600)
    run('changed-archive-fixture',['chromium','chromium-common'],'deferred','archive_changed')
    shutil.rmtree(f);assert not f.exists()
    value={'schema':'children-apt-guard-qualification/v1','at':time.time(),'source_sha256':source_sha,'apt':v,'synthetic_protocol_only':True,'production_manifest_created':False,'production_package_install':False,'global_hook_installed':False,'results':results,'fixture_retired':True,'global_dpkg_sha256':before}
    (root/'current.json').write_text(json.dumps(value,indent=2));print(json.dumps(value),flush=True)


if __name__ == '__main__':
    main()
