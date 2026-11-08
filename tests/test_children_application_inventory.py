"""Actual metadata parsing without package execution and live-image binding."""
import hashlib
import json
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
