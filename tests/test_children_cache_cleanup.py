"""Bounded owner-project discovery and private inherited IPC framing."""
import json
from pathlib import Path
import socket
import subprocess
import pytest
from unittest.mock import patch
from tools import children_cache_cleanup as cleanup


def repo(path):
    path.mkdir();subprocess.run(['git','init','-q',str(path)],check=True)
    (path/'Cargo.toml').write_text('[workspace]\n')
    for profile in ['debug','dev-small','release']:
        (path/'target'/profile/'incremental').mkdir(parents=True)
    return path


def test_discovery_selects_only_real_git_cargo_debug_caches(tmp_path):
    selected=repo(tmp_path/'real')
    (tmp_path/'linked').symlink_to(selected,target_is_directory=True)
    other=tmp_path/'not-git';other.mkdir();(other/'Cargo.toml').write_text('untracked source')
    (other/'target/debug/incremental').mkdir(parents=True)
    repos,roots=cleanup.discover(tmp_path)
    assert repos==[selected]
    assert set(roots)=={selected/'target/debug/incremental',selected/'target/dev-small/incremental'}


def test_discovery_limits_project_growth_without_full_host_walk(tmp_path):
    for n in range(65):(tmp_path/str(n)).touch()
    with pytest.raises(ValueError,match='project_inventory_limit'):cleanup.discover(tmp_path)


def test_inherited_ipc_is_bounded_json_without_pickle_or_command_capability():
    a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    try:
        cleanup.frame(a,{'request':'scan'});assert cleanup.receive(b)=={'request':'scan'}
        with pytest.raises(ValueError,match='frame_limit'):cleanup.frame(a,{'bad':'x'*cleanup.MAX_FRAME})
        a.send(b'x'*(cleanup.MAX_FRAME+1))
        with pytest.raises(ValueError,match='frame_limit'):cleanup.receive(b)
    finally:a.close();b.close()


def test_unknown_configuration_refuses_before_owner_lookup_or_mutation():
    with pytest.raises(ValueError,match='selected_guest_owner_required'):
        cleanup.run({'schema':'unknown','user':'root'})


def test_no_new_privileges_comes_from_actual_kernel_process_state():
    for text,expected in [('NoNewPrivs:\t1\n',True),('NoNewPrivs:\t0\n',False),
                          ('NoNewPrivs:\tinvalid\n',False),('Name:\tfixture\n',False)]:
        with patch.object(Path,'read_text',return_value=text):
            assert cleanup.no_new_privileges() is expected
