"""Actual metadata parsing without package execution and live-image binding."""
import hashlib
import json
import os
from pathlib import Path
from unittest.mock import patch
import pytest
from tools import children_application_inventory as inventory


def component_fixture(root):
    binary=root/'usr/lib/chromium/chromium';binary.parent.mkdir(parents=True);binary.write_bytes(b'ELF fixture only')
    library=root/'usr/lib/x86_64-linux-gnu/libfreetype.so.6.20.2';library.parent.mkdir(parents=True);library.write_bytes(b'library fixture; never load')
    (library.parent/'libfreetype.so.6').symlink_to(library.name)
    return binary,library


def test_static_browser_dependency_uses_readelf_only_and_hashes_library(tmp_path):
    import os
    from types import SimpleNamespace
    _,library=component_fixture(tmp_path);calls=[]
    def run(argv,**kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=0,stdout=b' (NEEDED) Shared library: [libfreetype.so.6]\n',stderr=b'')
    result=inventory.browser_components(root=tmp_path,owner_uid=os.getuid(),run=run)
    assert result['direct_freetype_needed'] and not result['custom_search_path']
    assert result['freetype_file_sha256']==hashlib.sha256(library.read_bytes()).hexdigest()
    assert calls==[['/usr/bin/readelf','-dW',str(tmp_path/'usr/lib/chromium/chromium')]]
    assert result['scope']=='static-package-dependency-only' and result['unassessed']


@pytest.mark.parametrize('mode',['changed-binary','oversized-output','bad-metadata','library-cap','external-link'])
def test_static_component_failure_never_reports_observed(tmp_path,mode):
    import os
    from types import SimpleNamespace
    binary,library=component_fixture(tmp_path)
    if mode=='external-link':
        alias=library.parent/'libfreetype.so.6';alias.unlink();alias.symlink_to(binary)
    def run(*args,**kwargs):
        if mode=='changed-binary':binary.write_bytes(b'changed')
        raw=b'x'*65537 if mode=='oversized-output' else (b'unknown' if mode=='bad-metadata' else b' (NEEDED) [libfreetype.so.6]\n')
        return SimpleNamespace(returncode=0,stdout=raw,stderr=b'')
    with pytest.raises(ValueError):inventory.browser_components(root=tmp_path,owner_uid=os.getuid(),run=run,budget=1 if mode=='library-cap' else 4096)


def test_custom_runtime_search_is_recorded_for_pending_assessment(tmp_path):
    import os
    from types import SimpleNamespace
    component_fixture(tmp_path)
    result=inventory.browser_components(root=tmp_path,owner_uid=os.getuid(),run=lambda *a,**k:SimpleNamespace(
        returncode=0,stdout=b' (NEEDED) [libfreetype.so.6]\n (RUNPATH) [$ORIGIN]\n',stderr=b''))
    assert result['state']=='observed' and result['custom_search_path'] is True


def test_metadata_is_data_not_imports_or_private_direct_urls(tmp_path):
    site=tmp_path/'site-packages';site.mkdir();dist=site/'fictional-1.dist-info';dist.mkdir()
    (dist/'METADATA').write_text('Name: fictional\nVersion: 1.2.3\n\nnot executed\n')
    private=dist/'direct_url.json';private.write_text('{"url":"https://private-secret.example"}')
    marker=tmp_path/'must-not-exist'
    (site/'dangerous.pth').write_text('import pathlib;pathlib.Path('+repr(str(marker))+').touch()')
    result=inventory.metadata(site,lambda:None)
    assert result[0]['name']=='fictional' and result[0]['version']=='1.2.3'
    assert result[0]['direct_url_present'] is True
    assert 'private-secret' not in json.dumps(result) and not marker.exists()


def test_metadata_refuses_symlinks_and_oversized_or_invalid_identity(tmp_path):
    dist=tmp_path/'one.dist-info';dist.mkdir();p=dist/'METADATA'
    for raw in ('Name: bad name\nVersion: 1\n','Name: one\nVersion: 1\n'+'x'*inventory.MAX_METADATA):
        p.write_text(raw)
        with pytest.raises(ValueError):inventory.metadata(tmp_path,lambda:None)
    p.unlink();other=tmp_path/'private';other.write_text('Name: one\nVersion: 1\n');p.symlink_to(other)
    with pytest.raises(ValueError):inventory.metadata(tmp_path,lambda:None)


def fixture_process(root,pid,entry):
    image=root/'running-image';image.write_bytes(b'actual selected executable fixture')
    process=root/str(pid);process.mkdir();(process/'exe').symlink_to(image)
    (process/'stat').write_bytes(str(pid).encode()+b' (fixture process) S '+b'0 '*18+b'100 0\n')
    (process/'environ').write_bytes(b'PRIVATE_TOKEN=PRIVATE-MUST-NOT-BE-RETAINED\0')
    (process/'cmdline').write_bytes(str(entry).encode()+b'\0--token\0PRIVATE-MUST-NOT-BE-RETAINED\0')
    return image


def test_selected_live_image_hash_and_venv_metadata_keep_no_arguments(tmp_path):
    venv=tmp_path/'venv';(venv/'bin').mkdir(parents=True);(venv/'pyvenv.cfg').write_text('home = fixture')
    dist=venv/'lib/python3.13/site-packages/one.dist-info';dist.mkdir(parents=True)
    (dist/'METADATA').write_text('Name: one\nVersion: 2.3\n')
    proc=tmp_path/'proc';proc.mkdir();image=fixture_process(proc,42,venv/'bin/python')
    props={'ActiveState':'active','MainPID':'42'}
    with patch.object(inventory,'properties',return_value=props):
        result=inventory.collect(['own.service'],proc=proc)
    assert result['units']['own.service']['state']=='observed'
    assert result['units']['own.service']['executable_sha256']==hashlib.sha256(image.read_bytes()).hexdigest()
    assert next(iter(result['environments'].values()))['packages'][0]['version']=='2.3'
    assert 'PRIVATE-MUST-NOT-BE-RETAINED' not in json.dumps(result)
    assert result['coverage']=='partial' and result['unassessed']


def test_changed_process_and_hash_capacity_are_unavailable_not_empty_green(tmp_path):
    image=fixture_process(tmp_path,3,tmp_path/'python')
    active={'ActiveState':'active','MainPID':'3'}
    with patch.object(inventory,'properties',side_effect=[active,dict(active,MainPID='4')]):
        result=inventory.collect(['own.service'],proc=tmp_path)
    assert result['units']['own.service']['reason']=='service_changed_during_observation'
    with patch.object(inventory,'properties',return_value=active),patch.object(inventory,'MAX_FILE',1):
        result=inventory.collect(['own.service'],proc=tmp_path)
    assert result['units']['own.service']['reason']=='executable_hash_capacity'
    assert image.read_bytes()==b'actual selected executable fixture'


@pytest.mark.parametrize('change', ['same-size-write', 'new-executable', 'reused-pid'])
def test_same_pid_does_not_prove_image_or_process_stayed_current(tmp_path, change):
    image=fixture_process(tmp_path,3,tmp_path/'python')
    original=image.read_bytes()
    def paths(process):
        if change=='same-size-write':
            before=image.stat()
            image.write_bytes(b'x'*len(original))
            # Keep the race deterministic even on filesystems whose timestamp
            # resolution coalesces immediate writes into the same tick.
            os.utime(image,ns=(before.st_atime_ns,before.st_mtime_ns+1_000_000_000))
        elif change=='new-executable':
            other=tmp_path/'replacement';other.write_bytes(original)
            (process/'exe').unlink();(process/'exe').symlink_to(other)
        else:
            (process/'stat').write_bytes(b'3 (different process) S '+b'0 '*18+b'200 0\n')
        return []
    with patch.object(inventory,'properties',return_value={'ActiveState':'active','MainPID':'3'}), \
            patch.object(inventory,'declared_python_paths',side_effect=paths):
        result=inventory.collect(['own.service'],proc=tmp_path)
    unit=result['units']['own.service']
    assert unit['state']=='unavailable'
    assert unit['reason']==('process_changed_during_observation' if change=='reused-pid'
                            else 'executable_changed_during_observation')


def test_same_size_mutation_during_hash_is_not_accepted(tmp_path):
    image=fixture_process(tmp_path,3,tmp_path/'python');original=Path.open
    class ChangedStream:
        def __enter__(self):
            self.stream=original(tmp_path/'3/exe','rb');self.changed=False
            return self
        def __exit__(self,*args):self.stream.close()
        def fileno(self):return self.stream.fileno()
        def read(self,count):
            raw=self.stream.read(count)
            if raw and not self.changed:
                self.changed=True;before=image.stat();image.write_bytes(b'x'*len(raw))
                os.utime(image,ns=(before.st_atime_ns,before.st_mtime_ns+1_000_000_000))
            return raw
    def opened(path,*args,**kwargs):
        return ChangedStream() if path==tmp_path/'3/exe' else original(path,*args,**kwargs)
    with patch.object(inventory,'properties',return_value={'ActiveState':'active','MainPID':'3'}), \
            patch.object(Path,'open',opened):
        result=inventory.collect(['own.service'],proc=tmp_path)
    assert result['units']['own.service']['state']=='unavailable'
    assert result['units']['own.service']['reason']=='executable_changed_during_read'


def test_invalid_service_never_becomes_a_shell_command():
    with patch.object(inventory.subprocess,'run',side_effect=AssertionError('must not execute')):
        with pytest.raises(ValueError):inventory.properties('own.service; secret')
    with pytest.raises(ValueError):inventory.collect(['own.service']*2)


def test_deployed_pythonpath_outside_empty_venv_is_observed_without_other_env(tmp_path):
    proc=tmp_path/'proc';proc.mkdir();fixture_process(proc,42,tmp_path/'python')
    site=tmp_path/'vendor-site';dist=site/'one.dist-info';dist.mkdir(parents=True)
    (dist/'METADATA').write_text('Name: one\nVersion: 4.5\n')
    (proc/'42/environ').write_bytes(b'PRIVATE_TOKEN=must-not-retain\0PYTHONPATH='+str(site).encode()+b'\0')
    with patch.object(inventory,'properties',return_value={'ActiveState':'active','MainPID':'42'}):
        result=inventory.collect(['own.service'],proc=proc)
    assert next(iter(result['environments'].values()))['packages'][0]['version']=='4.5'
    assert 'must-not-retain' not in json.dumps(result)
    assert result['environments'][str(site)]['ecosystem']=='unqualified-Python-metadata'


def test_long_description_does_not_exhaust_bounded_header_read(tmp_path):
    dist=tmp_path/'one.dist-info';dist.mkdir();p=dist/'METADATA'
    headers=b'Name: one\nVersion: 9.1\n\n';p.write_bytes(headers+b'x'*(inventory.MAX_METADATA*3))
    result=inventory.metadata(tmp_path,lambda:None)
    assert result[0]['version']=='9.1'
    assert result[0]['metadata_header_sha256']==hashlib.sha256(headers).hexdigest()
    assert result[0]['metadata_file_bytes']>inventory.MAX_METADATA


@pytest.fixture
def selected_deployment(tmp_path, monkeypatch):
    monkeypatch.setattr(inventory, 'TRUSTED_UID', os.getuid())
    monkeypatch.setattr(inventory, 'PUBLIC_ROOTS', (tmp_path,))
    root = tmp_path/'public-runtime'
    root.mkdir()
    proc = tmp_path/'proc'
    proc.mkdir()
    image = fixture_process(proc, 3, root/'python')
    target = root/'native'
    image.rename(target)
    (proc/'3/exe').unlink()
    (proc/'3/exe').symlink_to(target)
    (proc/'3/cwd').symlink_to(root)
    source = root/'app.py'
    source.write_text('raise RuntimeError("public code must never execute")\n')
    manifest = dict(schema='children-selected-deployments/v1', units={'own.service': dict(
        root=str(root), bind='cwd', source_ref='App-source-qualified',
        files={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir()})})
    monkeypatch.setattr(inventory, 'properties', lambda u:dict(ActiveState='active', MainPID='3'))
    return root, proc, target, source, manifest


def test_exact_source_and_loaded_image_binding_without_executing_source(selected_deployment):
    root, proc, _target, _source, manifest = selected_deployment
    cache=root/'__pycache__'
    cache.mkdir()
    (cache/'runtime.pyc').write_bytes(b'unqualified bytecode')
    result=inventory.collect(['own.service'],proc=proc,deployments=manifest)
    row=result['units']['own.service']
    assert row['state']=='observed' and row['deployment']['state']=='verified'
    assert row['deployment']['files']==2 and row['deployment']['loaded_main_executable'] is False
    assert 'unassessed' in row['deployment']['meaning']
    manifest['units']['own.service']['bind']='executable'
    with patch.object(inventory,'MAX_FILE',sum(p.stat().st_size for p in root.iterdir() if p.is_file())):
        result=inventory.collect(['own.service'],proc=proc,deployments=manifest)
    assert result['units']['own.service']['deployment']['loaded_main_executable'] is True
    assert 'PRIVATE-MUST-NOT-BE-RETAINED' not in json.dumps(result)


@pytest.mark.parametrize('change',['content','extra','missing','symlink','writable','cwd','executable'])
def test_changed_source_selection_never_becomes_verified(selected_deployment,change):
    root, proc, target, source, manifest=selected_deployment
    if change=='content':
        source.write_text('changed')
    elif change=='extra':
        (root/'unrecorded.py').write_text('never execute')
    elif change=='missing':
        source.unlink()
    elif change=='symlink':
        source.unlink()
        source.symlink_to(target)
    elif change=='writable':
        source.chmod(0o666)
    elif change=='cwd':
        (proc/'3/cwd').unlink()
        (proc/'3/cwd').symlink_to(proc)
    else:
        manifest['units']['own.service']['bind']='executable'
        outside=proc/'outside'
        outside.write_bytes(target.read_bytes())
        (proc/'3/exe').unlink()
        (proc/'3/exe').symlink_to(outside)
    result=inventory.collect(['own.service'],proc=proc,deployments=manifest)
    assert result['units']['own.service']['state']=='unavailable'


def test_same_pid_cwd_change_during_final_check_is_not_current_binding(selected_deployment,monkeypatch):
    root,proc,_target,_source,manifest=selected_deployment
    count=0
    def properties(unit):
        nonlocal count
        count+=1
        if count==2:
            (proc/'3/cwd').unlink()
            (proc/'3/cwd').symlink_to(proc)
        return dict(ActiveState='active',MainPID='3')
    monkeypatch.setattr(inventory,'properties',properties)
    result=inventory.collect(['own.service'],proc=proc,deployments=manifest)
    assert result['units']['own.service']['reason']=='selected_deployment_cwd_changed'


@pytest.mark.parametrize('change',['escape','wrong-unit','bad-hash','capacity'])
def test_manifest_bounds_apply_before_reading_source(selected_deployment,change):
    _root,proc,_target,_source,manifest=selected_deployment
    row=manifest['units']['own.service']
    if change=='escape':
        row['files']['../outside']='a'*64
    elif change=='wrong-unit':
        manifest['units']['other.service']=row
    elif change=='bad-hash':
        row['files']['app.py']='not-a-hash'
    else:
        row['files']={f'file-{i}':'a'*64 for i in range(1025)}
    with pytest.raises(ValueError,match='selected_deployment_'):
        inventory.collect(['own.service'],proc=proc,deployments=manifest)
