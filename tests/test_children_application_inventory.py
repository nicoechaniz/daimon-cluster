"""Actual metadata parsing without package execution and live-image binding."""
import hashlib
import json
from pathlib import Path
from unittest.mock import patch
import pytest
from tools import children_application_inventory as inventory


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
