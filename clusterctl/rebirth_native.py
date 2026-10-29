"""Qualified native Matrix profile under the ordinary H8 admission supervisor.

This selects existing Source hosting, including its approved group applications;
it does not create authority, provision applications or start a model harness.
"""
from __future__ import annotations

import hmac
import os
from pathlib import Path

from . import onboarding_code_successor, onboarding_release, onboarding_sdk
from .onboarding import digest


def prepare(state: Path, identity: dict, profile: Path, password_fd: int) -> dict:
    from .matrix_host import matrix_root
    from .rebirth_host import RebirthHostError, _owner_file, _read_json

    try:
        value = _read_json(_owner_file(profile))
        if (not isinstance(value, dict) or set(value) != {
                'schema', 'config', 'code', 'code_digest', 'home'}
                or value['schema'] != 'dm.cluster.rebirth-native-profile/v1'
                or any(not isinstance(value[k], str) or not Path(value[k]).is_absolute()
                       for k in ('config', 'code', 'home'))):
            raise ValueError('profile')
        config = Path(value['config'])
        settings = _read_json(_owner_file(config))
        root = matrix_root(state, identity['origin']['embodiment_id'])
        if (settings.get('schema') != 'cluster-onboarding-source/v1'
                or settings.get('runtime_root') != str(root)):
            raise ValueError('root')
        password = _owner_file(Path(settings['password_file'])).read_bytes()
        supplied = bytearray()
        while len(supplied) <= 4096:
            part = os.read(password_fd, 4097 - len(supplied))
            if not part:
                break
            supplied.extend(part)
        matches = bool(password) and len(supplied) <= 4096 and hmac.compare_digest(password, supplied)
        supplied[:] = b'\0' * len(supplied)
        if not matches:
            raise ValueError('password')
        code = Path(value['code'])
        onboarding_release.verify(code, value['code_digest'], uid=0)
        parameters = onboarding_code_successor.sdk_parameters(code, uid=0)
        if not parameters:
            raise ValueError('qualified SDK required')
        sdk = onboarding_sdk.verify(code, uid=0, **parameters)
        sdk_root = Path(value['home']) / '.local/share/daimon-matrix/sdk' / digest(sdk)
        venv = sdk_root / 'venv'
        if not (venv / 'bin/python').is_file():
            raise ValueError('SDK not installed')
        return {'config':str(config), 'config_sha256':digest(settings),
                    'code':str(code), 'code_digest':value['code_digest'], 'venv':str(venv),
                    'sdk_digest':digest(sdk)}
    except Exception as error:
        raise RebirthHostError('rebirth_host_native_profile_rejected') from error


def command(selection: dict, ready_fd: int) -> list[str]:
    """Use the qualified SDK bootstrap and a kernel-enforced parent lifetime."""
    venv, code = Path(selection['venv']), Path(selection['code'])
    result = onboarding_sdk.runtime_command(venv, venv.parent / 'runtime-imports', code,
        'clusterctl.onboarding_source', ['--config', selection['config'], '--code-digest',
        selection['code_digest'], '--code-owner', '0', '--ready-fd', str(ready_fd),
        '--expected-config-sha256', selection['config_sha256']])
    # No preexec_fn: admission supervision has live threads. Set PDEATHSIG in
    # the fresh interpreter before any runtime import, checking both race edges.
    guard = ('import os,signal,ctypes,hashlib,json\n'
             f'expected_parent={os.getpid()}\n'
             'if os.getppid()!=expected_parent: raise SystemExit(1)\n'
             'if ctypes.CDLL(None,use_errno=True).prctl(1,signal.SIGKILL,0,0,0)!=0: raise SystemExit(1)\n'
             'if os.getppid()!=expected_parent: raise SystemExit(1)\n'
             f'with open({selection["config"]!r},"rb") as stream: config=json.load(stream)\n'
             f'if hashlib.sha256(json.dumps(config,sort_keys=True,separators=(",", ":")).encode()).hexdigest()!={selection["config_sha256"]!r}: raise SystemExit(1)\n')
    result[5] = guard + result[5]
    return result


def verify_ready(state: Path, identity: dict, process_pid: int, selection: dict) -> dict:
    from .distributed_rebirth import _native_peer_observation
    from .matrix_host import matrix_root
    from .rebirth_host import RebirthHostError, _read_json

    root = matrix_root(state, identity['origin']['embodiment_id'])
    try:
        status, me, we, proof = _native_peer_observation(root, _read_json(root / 'runtime.json'))
    except Exception as error:
        raise RebirthHostError('rebirth_host_native_readiness_rejected') from error
    active = sorted(row['embodiment_id'] for row in we.get('embodiments', [])
                    if row.get('manifest_status') == 'active')
    if (status.get('integrity') != 'ok' or status.get('being_ref') != identity['being_ref']
            or status.get('manifest_hash') != identity['manifest_hash']
            or status.get('local_origin') != identity['origin'] or me.get('origin') != identity['origin']
            or identity['origin']['embodiment_id'] not in active
            or proof['process']['pid'] != process_pid
            or status.get('loaded_runtime', {}).get('qualified_startup', {}).get('sdk_digest')
                != selection['sdk_digest']):
        raise RebirthHostError('rebirth_host_native_readiness_mismatch')
    return {'integrity':'ok', 'active_embodiment_ids':active, 'native_process':proof['process'],
                'harness_lifecycle_claimed':False}
