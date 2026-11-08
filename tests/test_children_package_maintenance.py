"""Commit intent, independent writer lifetime, recovery and scoped cleanup."""
import contextlib
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from unittest.mock import patch

import pytest
from tools import children_package_maintenance as m
from tools.children_package_guard import Deferred


@pytest.fixture
def transaction(tmp_path):
    state = tmp_path/'state';state.mkdir(mode=0o700)
    archives=state/'archives';archives.mkdir()
    installed={n:'1' for n in m.selection.PACKAGES}
    services={n:{'ActiveState':'active','MainPID':str(200+i),'NRestarts':'0','InvocationID':'original'+n}
              for i,n in enumerate(m.SERVICES)}
    calls=[]
    def select(policy,state,**kwargs):
        packages={}
        for n in installed:
            p=archives/(n+'.deb');p.write_bytes(b'inert test archive');p.chmod(0o600)
            packages[n]={'old_version':'1','version':'2','archive':str(p),
                         'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'bytes':p.stat().st_size}
        manifest={'schema':'children-reviewed-apt-transaction/v1',
                  'source':'verified-local-debian-security','maintainer_reviewed':True,'packages':packages}
        m.save(state/'manifest.json',manifest)
        (archives/'lock').touch()
        (state/'transaction.apt.conf').write_bytes(m.expected_config(state))
        (state/'transaction.apt.conf').chmod(0o600)
        return {'decision':'reviewed_manifest_prepared',
                'manifest_sha256':hashlib.sha256((state/'manifest.json').read_bytes()).hexdigest()}
    def run(argv,**kwargs):
        if argv[0]=='dpkg-query':
            return ''.join(n+'\t'+v+'\tinstalled\n' for n,v in sorted(installed.items())).encode()
        if argv==['dpkg','--audit']:return b''
        if argv[0]=='systemctl':
            return ''.join(k+'='+v+'\n' for k,v in services[argv[2]].items()).encode()
        if argv==['/usr/bin/chromium','--version']:return b'Chromium 2 built on Debian GNU/Linux 13 (trixie)'
        raise AssertionError(argv)
    def commit(argv):
        intent=json.loads((state/'transaction.json').read_text())
        assert intent['phase']=='commit_requested' and intent['write_requested']
        assert '--no-download' in argv and '--no-remove' in argv
        assert '-c' in argv and '--only-upgrade' in argv
        calls.append(argv)
        installed.update({n:'2' for n in installed})
        return {'exit':0,'pid':1234,'output':'guest-unit-journal'}
    original=m.private_json
    with patch.object(m,'private_json',side_effect=lambda p,uid:original(p,os.getuid())),\
         patch.object(m,'verify_archive'),patch.object(m,'package_locks',side_effect=lambda *a:contextlib.nullcontext()),\
         patch.object(m.selection,'select',side_effect=select),\
         patch.object(m,'precommit',side_effect=lambda *args:dict((n,dict(v)) for n,v in services.items())):
        yield state,installed,services,calls,run,commit


def test_commit_durable_intent_then_health_and_exact_cleanup(transaction):
    state,installed,services,calls,run,commit=transaction
    unrelated=state/'preserved-profile';unrelated.write_bytes(b'private')
    row=m.maintain({},state,install=True,occurrence='2026-11-08',run=run,commit=commit)
    assert row['phase']=='complete' and row['artifacts_retired']
    assert len(calls)==1 and not (state/'manifest.json').exists()
    assert not list((state/'archives').glob('*.deb')) and unrelated.read_bytes()==b'private'
    # A duplicate occurrence neither reselects nor repeats installation.
    with patch.object(m.selection,'select',side_effect=AssertionError('replayed selection')):
        again=m.maintain({},state,install=True,occurrence='2026-11-08',run=run,commit=commit)
    assert again==row and len(calls)==1


def test_lost_writer_ack_old_versions_never_replay_and_new_versions_reconcile(transaction):
    state,installed,services,calls,run,commit=transaction
    def lost(argv):
        calls.append(argv)
        raise KeyboardInterrupt('simulated lost supervisor')
    with pytest.raises(KeyboardInterrupt):
        m.maintain({},state,install=True,run=run,commit=lost)
    assert json.loads((state/'transaction.json').read_text())['phase']=='commit_requested'
    with pytest.raises(Deferred,match='commit_uncertain'):
        m.maintain({},state,install=True,run=run,commit=commit)
    assert len(calls)==1
    installed.update({n:'2' for n in installed})
    row=m.maintain({},state,install=True,run=run,commit=commit)
    assert row['phase']=='complete' and len(calls)==1


def test_service_change_retains_pending_work_and_never_repeats(transaction):
    state,installed,services,calls,run,commit=transaction
    def changed(argv):
        result=commit(argv);services[m.SERVICES[0]]['MainPID']='9999';return result
    with pytest.raises(Deferred,match='own_service_changed'):
        m.maintain({},state,install=True,run=run,commit=changed)
    assert (state/'manifest.json').exists()
    with pytest.raises(Deferred,match='own_service_changed'):
        m.maintain({},state,install=True,run=run,commit=commit)
    assert len(calls)==1


def test_browser_deferral_resumes_same_reviewed_manifest_without_reselection(transaction):
    state,installed,services,calls,run,commit=transaction
    with patch.object(m,'precommit',side_effect=Deferred('browser_active')):
        with pytest.raises(Deferred,match='browser_active'):
            m.maintain({},state,install=True,run=run,commit=commit)
    assert json.loads((state/'transaction.json').read_text())['phase']=='prepared'
    assert not calls
    with patch.object(m.selection,'select',side_effect=AssertionError('duplicate download')):
        result=m.maintain({},state,install=True,run=run,commit=commit)
    assert result['phase']=='complete' and len(calls)==1


def test_read_only_assessment_never_calls_writer(transaction):
    state,installed,services,calls,run,commit=transaction
    with patch.object(m.selection,'select',return_value={'decision':'up_to_date'}):
        row=m.maintain({},state,install=True,run=run,commit=commit)
    assert row['phase']=='up_to_date' and not row['write_requested'] and not calls


def test_orphan_manifest_is_preserved(transaction):
    state,installed,services,calls,run,commit=transaction
    orphan=state/'manifest.json';orphan.write_bytes(b'pending original bytes')
    with pytest.raises(Deferred,match='orphan_manifest'):
        m.maintain({},state,install=True,run=run,commit=commit)
    assert orphan.read_bytes()==b'pending original bytes' and not calls


def test_writer_keeps_native_journal_sink_and_has_no_deadline():
    result=m.writer([sys.executable,'-c','pass'])
    assert result['exit']==0 and result['pid']>0 and result['output']=='guest-unit-journal'


def test_actual_child_survives_loss_of_its_python_supervisor(tmp_path):
    marker=tmp_path/'child-completed'
    child="import pathlib,time;time.sleep(.4);pathlib.Path("+repr(str(marker))+").write_text('completed')"
    parent=('from tools.children_package_maintenance import writer;writer('+repr([sys.executable,'-c',child])+')')
    process=subprocess.Popen([sys.executable,'-c',parent])
    try:
        # Wait for the actual child, not an estimated parent startup delay.
        deadline=time.monotonic()+5
        child_pid=None
        while time.monotonic()<deadline:
            p=Path('/proc')/str(process.pid)/'task'/str(process.pid)/'children'
            ids=p.read_text().split() if p.exists() else []
            if ids:child_pid=int(ids[0]);break
            time.sleep(.01)
        assert child_pid
        process.terminate();process.wait(timeout=3)
        while time.monotonic()<deadline and not marker.exists():time.sleep(.02)
        assert marker.read_text()=='completed'
    finally:
        if process.poll() is None:process.terminate();process.wait(timeout=3)


def test_real_posix_lock_refuses_a_still_running_package_actor(tmp_path):
    root=tmp_path/'dpkg';root.mkdir();state=tmp_path/'state';(state/'archives').mkdir(parents=True)
    for p in [root/'lock-frontend',root/'lock',state/'archives'/'lock']:p.touch(mode=0o600)
    code="import fcntl,sys;f=open(sys.argv[1],'r+');fcntl.lockf(f,fcntl.LOCK_EX);print('locked',flush=True);sys.stdin.read()"
    p=subprocess.Popen([sys.executable,'-c',code,str(root/'lock-frontend')],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
    try:
        assert p.stdout.readline().strip()=='locked'
        with pytest.raises(Deferred,match='still_running'):
            with m.package_locks(state,root):pass
    finally:
        p.stdin.close();p.wait(timeout=3);p.stdout.close()
    with m.package_locks(state,root):pass


def test_fleet_observes_live_guest_then_reports_current_occurrence(tmp_path):
    today=datetime.datetime.now(datetime.timezone.utc).date().isoformat();started=[];reads={}
    def run(argv,**kwargs):
        if argv[:2]==['incus','query']:return json.dumps({'usage':{'total':8*m.GIB,'used':m.GIB}}).encode()
        name=argv[2]
        if 'show' in argv:
            reads[name]=reads.get(name,0)+1
            active=reads[name]==1
            return ('ActiveState='+('active' if active else 'inactive')+'\nLoadState=loaded\nExecMainStatus=0\n').encode()
        if 'start' in argv:started.append(name);return b''
        if 'cat' in argv:return json.dumps({'schema':'children-package-maintenance/v1','occurrence':today,'phase':'up_to_date','write_requested':False}).encode()
        raise AssertionError(argv)
    result=m.fleet(tmp_path,run=run,wait=lambda seconds:None)
    assert result['complete'] and len(result['targets'])==4 and not started


def test_fleet_quota_failure_cannot_start_guest(tmp_path):
    def run(argv,**kwargs):
        assert argv[:2]==['incus','query']
        return json.dumps({'usage':{'total':8*m.GIB,'used':7*m.GIB}}).encode()
    result=m.fleet(tmp_path,run=run)
    assert not result['complete']
    assert all(row['error']=='insufficient_root_quota_headroom' for row in result['targets'].values())


def test_fleet_timeout_never_stops_or_restarts_a_running_guest(tmp_path):
    def run(argv,**kwargs):
        if argv[:2]==['incus','query']:return json.dumps({'usage':{'total':8*m.GIB,'used':0}}).encode()
        assert 'show' in argv
        return b'ActiveState=active\nLoadState=loaded\nExecMainStatus=0\n'
    row=m.fleet(tmp_path,run=run,now=lambda:100,duration=0)
    assert not row['complete'] and len(row['targets'])==1
    assert row['targets']['pixin']['error']=='guest_writer_still_running_observation_ended'


def test_precommit_rechecks_plan_hold_config_and_service_health(transaction):
    state,installed,services,calls,run,commit=transaction
    # Exercise the real precommit implementation, with native command evidence
    # fixtures. No writer is callable from this read-only preflight.
    m.selection.select({},state,download=True)
    manifest=json.loads((state/'manifest.json').read_text())
    index='\n\n'.join('Package: '+n+'\nArchitecture: amd64\nVersion: 2\nSHA256: '+v['sha256']+
                      '\nSize: '+str(v['bytes'])+'\nFilename: pool/updates/main/c/chromium/'+n+'.deb'
                      for n,v in manifest['packages'].items()).encode()
    held=[]
    def native(argv,**kwargs):
        if argv==['apt-config','dump']:return b''
        if argv==['apt-get','indextargets']:return b'index fixture'
        if 'cat-file' in argv:return index
        if argv==['apt-mark','showhold']:return '\n'.join(held).encode()
        if '-s' in argv:
            assert 'Dir::Cache::archives='+str(state/'archives') in argv
            return '\n'.join('Inst '+n+' [1] (2 Debian-Security:13/security)' for n in installed).encode()
        return run(argv,**kwargs)
    # The fixture overrides precommit for state-machine tests. Explicitly use
    # its real wrapped source here rather than that mock.
    real=ORIGINAL_PRECOMMIT
    with patch.object(m.selection,'security_target',return_value={}),\
         patch.object(m.selection,'release_fresh',return_value=Path('/fixture-index')),\
         patch.object(m,'idle_package_scope'):
        assert real({},state,manifest,native)==services
        held.append('chromium')
        with pytest.raises(Deferred,match='held_browser'):real({},state,manifest,native)
        held.clear();(state/'transaction.apt.conf').write_bytes(b'unreviewed hook')
        with pytest.raises(Deferred,match='changed_transaction_config'):real({},state,manifest,native)
    assert not calls


ORIGINAL_PRECOMMIT=m.precommit


def test_coordinator_overlay_resolves_actual_frozen_guard_file(tmp_path):
    original=tmp_path/'original';original.mkdir();guard=original/'children_package_guard.py';guard.write_text('inert fixture')
    overlay=tmp_path/'overlay';overlay.mkdir();(overlay/'children_package_guard.py').symlink_to(guard)
    with patch.object(m,'__file__',str(overlay/'children_package_maintenance.py')):
        assert str(guard) in m.expected_config(tmp_path).decode()
        assert str(overlay/'children_package_guard.py') not in m.expected_config(tmp_path).decode()


def test_brotli_commit_bytes_health_and_uncertain_postcheck_do_not_replay(transaction):
    state,installed,services,calls,run,commit=transaction
    installed.clear();installed['libbrotli1']='1'
    original=m.selection.select.side_effect
    def select(*args,**kwargs):
        result=original(*args,**kwargs)
        manifest=json.loads((state/'manifest.json').read_bytes())
        manifest.update(installed_files_sha256={n:'a'*64 for n in m.selection.LIBRARY_FILES},
                        trigger_runtime={n:'b'*64 for n in m.selection.TRIGGER_FILES})
        m.save(state/'manifest.json',manifest)
        result['manifest_sha256']=hashlib.sha256((state/'manifest.json').read_bytes()).hexdigest()
        return result
    with patch.object(m.selection,'select',side_effect=select),patch.object(m,'idle_package_scope'),\
            patch.object(m,'verify_installed_library',side_effect=Deferred('installed_library_bytes_mismatch')):
        with pytest.raises(Deferred,match='library_bytes'):
            m.maintain({},state,install=True,run=run,commit=commit)
    assert len(calls)==1 and (state/'manifest.json').exists()
    with patch.object(m.selection,'select',side_effect=AssertionError('repeat writer')),\
            patch.object(m,'idle_package_scope'),patch.object(m,'verify_installed_library') as verify:
        result=m.maintain({},state,install=True,run=run,commit=commit)
    assert result['phase']=='complete' and result['observed_versions']=={'libbrotli1':'2'}
    verify.assert_called_once();assert len(calls)==1 and result['artifacts_retired']


def test_installed_library_bytes_not_only_dpkg_version(tmp_path):
    manifest={'installed_files_sha256':{n:hashlib.sha256(b'ELF!').hexdigest() for n in m.selection.LIBRARY_FILES}}
    for n in manifest['installed_files_sha256']:
        p=tmp_path/n.lstrip('/');p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b'ELF!')
    m.verify_installed_library(manifest,tmp_path,os.getuid())
    p.write_bytes(b'different')
    with pytest.raises(Deferred,match='bytes_mismatch'):m.verify_installed_library(manifest,tmp_path,os.getuid())


def test_fleet_library_failure_not_hidden_by_current_browser_receipt(tmp_path):
    today=datetime.datetime.now(datetime.timezone.utc).date().isoformat()
    def run(argv,**kwargs):
        if argv[:2]==['incus','query']:return json.dumps({'usage':{'total':8*m.GIB,'used':0}}).encode()
        if 'show' in argv:return b'ActiveState=inactive\nLoadState=loaded\nExecMainStatus=0\n'
        if 'start' in argv:return b''
        if 'cat' in argv:
            return json.dumps({'schema':'children-package-maintenance/v1','occurrence':today,
                               'phase':'deferred' if 'brotli-selection' in argv[-1] else 'complete',
                               'write_requested':False}).encode()
        raise AssertionError(argv)
    result=m.fleet(tmp_path,run=run,include_brotli=True)
    assert not result['complete'] and len(result['targets'])==4
    assert all(v['error']=='guest_library_coverage_degraded' for v in result['targets'].values())


def test_package_units_keep_writer_independent_of_observer_timeout():
    root=Path(__file__).resolve().parents[1]/'deploy/systemd'
    guest=(root/'children-guest-package-maintenance.service').read_text()
    fleet=(root/'children-packages-daily.service').read_text()
    assert 'TimeoutStartSec=infinity' in guest and 'KillMode=process' in guest
    assert 'TimeoutStopSec=infinity' in guest and 'RuntimeMaxSec=' not in guest
    assert 'MemoryMax=1G' in guest and 'StandardOutput=journal' in guest
    assert 'TimeoutStartSec=900' in fleet and 'MemoryMax=128M' in fleet
    assert '--fleet' in fleet and '--install' not in fleet
