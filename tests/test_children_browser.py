"""Private retained profile, public artifact integrity and intentional standby."""
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch,Mock
import pytest
from tools import children_browser as browser


@pytest.fixture
def runtime(tmp_path):
    root=tmp_path/'public';root.mkdir();(root/'extension').mkdir()
    (root/'kimi-webbridge').write_bytes(b'public fixture binary')
    (root/'extension/manifest.json').write_text('{"version":"2.0.22"}')
    files={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob('*') if p.is_file()}
    (root/'runtime.json').write_text(json.dumps({'schema':'children-webbridge-runtime/v1','version':'2.0.22','files':files}))
    return root


def test_public_runtime_checks_bytes_traversal_and_modes(runtime,tmp_path):
    browser.verify_runtime(runtime,base=tmp_path,owner_uid=os.getuid())
    (runtime/'kimi-webbridge').write_bytes(b'changed executable')
    with pytest.raises(ValueError,match='runtime_bytes'):
        browser.verify_runtime(runtime,base=tmp_path,owner_uid=os.getuid())
    with pytest.raises(ValueError,match='selected_public'):
        browser.verify_runtime(runtime,base=tmp_path/'other',owner_uid=os.getuid())


def test_init_retains_profile_and_display_auth_without_exposing_secret_argv(runtime,tmp_path):
    home=tmp_path/'home';home.mkdir();calls=[]
    original=browser.verify_runtime
    def xauth(argv,**kwargs):
        calls.append(argv)
        assert argv[-2:]==['source','-'] and 'input' in kwargs
        assert kwargs['input'].startswith('add :77 . ')
        assert kwargs['input'].split()[-1] not in argv
        p=Path(argv[2]);p.write_bytes(b'private own display fixture');p.chmod(0o600)
        return SimpleNamespace(returncode=0)
    with patch.object(browser,'home',return_value=home),\
         patch.object(browser,'verify_runtime',side_effect=lambda r:original(r,base=tmp_path,owner_uid=os.getuid())),\
         patch.object(browser.subprocess,'run',side_effect=xauth):
        assert browser.initialize(runtime)['state']=='installed'
        profile=home/'.kimi-webbridge/chromium-profile';(profile/'retained-cookie-fixture').write_bytes(b'own private profile')
        authority=(home/'.kimi-webbridge/Xauthority').read_bytes()
        assert browser.initialize(runtime)['profile_preserved']
        assert len(calls)==1
        assert (profile/'retained-cookie-fixture').read_bytes()==b'own private profile'
        assert (home/'.kimi-webbridge/Xauthority').read_bytes()==authority
        with pytest.raises(ValueError,match='reconciliation'):browser.initialize(tmp_path/'new-runtime')


def test_foreign_or_symlinked_private_profile_is_kept(tmp_path):
    root=tmp_path/'state';root.mkdir(mode=0o700)
    linked=tmp_path/'linked';linked.symlink_to(root,target_is_directory=True)
    with pytest.raises(ValueError,match='private_browser_state'):browser.private(linked,True)
    root.chmod(0o755)
    with pytest.raises(ValueError,match='private_browser_state'):browser.private(root,True)


def test_intentional_standby_never_starts_browser_or_queries_private_tabs():
    units={n:{'ActiveState':'inactive','SubState':'dead'} for n in browser.UNITS}
    with patch.object(browser,'binding',return_value={}),patch.object(browser,'units',return_value=units),\
         patch.object(browser,'daemon',side_effect=AssertionError('standby woke daemon')):
        assert browser.inspect()['state']=='standby'


def test_running_browser_needs_actual_extension_capability():
    units={n:{'ActiveState':'active','SubState':'running'} for n in browser.UNITS}
    for connected,version,expected in [(False,'2.0.22','unavailable'),(True,'2.0.22','ready'),(True,'v2.0.22','ready'),(True,'2.0.23','unavailable')]:
        with patch.object(browser,'binding',return_value={}),patch.object(browser,'units',return_value=units),\
             patch.object(browser,'daemon',return_value={'running':True,'version':version,'extension_connected':connected}):
            assert browser.inspect()['state']==expected


def test_units_are_own_user_loopback_bounded_and_preserve_chromium_sandbox():
    root=Path(__file__).resolve().parents[1]/'deploy/systemd/user'
    text='\n'.join((root/n).read_text() for n in browser.UNITS)
    assert '--no-sandbox' not in text and '--disable-setuid-sandbox' not in text
    assert '--addr 127.0.0.1:10086' in text and '-nolisten tcp' in text
    assert 'MemoryMax=1280M' in text and 'TasksMax=512' in text
    assert 'XAUTHORITY=%h/.kimi-webbridge/Xauthority' in text
    assert 'SystemCallFilter=~connect' in text and 'SystemCallErrorNumber=EPERM' in text
    assert '[Install]' not in text, 'browser is not enabled at user-manager boot'
