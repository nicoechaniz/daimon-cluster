"""Dedicated SSH forced-command transport for fixed Home service operations.

The new transport account has no administrative login key. Its sudo rules name
only a protected dispatcher plus explicitly selected operation arguments.
Runtime/route configs and maintenance selections stay operator-owned.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import sys

from ..onboarding_conversation_maintenance import BOOTSTRAP
from ..onboarding_conversation import read as read_code
from ..onboarding_release import regular
from .service_package import exact, path

ROOT_WRAPPER = '/usr/local/libexec/daimon-home-service-root'
OPERATION = re.compile(r'(runtime|route|maintenance)-[a-z][a-z0-9-]{0,47}')


def forward():
    """Unprivileged key forced-command: never execute SSH_ORIGINAL_COMMAND."""
    original = os.environ.get('SSH_ORIGINAL_COMMAND', '')
    if len(original) > 16384:
        raise ValueError('service_remote_operation_denied')
    args = shlex.split(original)
    if not args or not OPERATION.fullmatch(args[0]):
        raise ValueError('service_remote_operation_denied')
    if args[0].startswith('maintenance-'):
        # Existing guard transport has one program placeholder. Match that
        # public protocol, but execute only our installed trusted implementation.
        if len(args) != 2 or args[1] != BOOTSTRAP:
            raise ValueError('service_remote_operation_denied')
    elif len(args) != 1:
        raise ValueError('service_remote_operation_denied')
    os.execv('/usr/bin/sudo', ['sudo', '-n', ROOT_WRAPPER, args[0]])


def configuration(value):
    exact(value, 'schema operations', 'invalid_service_remote_configuration')
    if (value['schema'] != 'dm.home-service-remote/v1'
            or not isinstance(value['operations'], dict)
            or not 1 <= len(value['operations']) <= 32):
        raise ValueError('invalid_service_remote_configuration')
    for name, row in value['operations'].items():
        if not OPERATION.fullmatch(name):
            raise ValueError('invalid_service_remote_operation')
        if isinstance(row, dict) and row.get('kind') == 'executor':
            # Existing fixed host wrapper, e.g. the exact Incus instance/quota
            # observer. Its executable is operator input, never SSH payload.
            exact(row, 'kind executable', 'invalid_service_remote_operation')
            path(row['executable'])
        elif name.startswith(('runtime-', 'route-')):
            exact(row, 'kind config', 'invalid_service_remote_operation')
            if row['kind'] != name.split('-', 1)[0]:
                raise ValueError('invalid_service_remote_operation')
            path(row['config'])
        else:
            exact(row, 'kind selection', 'invalid_service_remote_operation')
            if row['kind'] != 'maintenance':
                raise ValueError('invalid_service_remote_operation')
            selection = row['selection']
            exact(selection, 'python script script_sha256 config owner_uid health_url',
                  'invalid_service_remote_maintenance')
            for field in ('python', 'script', 'config'):
                path(selection[field])
            if (type(selection['owner_uid']) is not int or selection['owner_uid'] <= 0
                    or not re.fullmatch('[0-9a-f]{64}', selection['script_sha256'])
                    or not isinstance(selection['health_url'], str)):
                raise ValueError('invalid_service_remote_maintenance')
    return value


def maintenance(selection):
    """Read one exact guard frame, drop privilege and retain its live stream."""
    raw = sys.stdin.buffer.readline(16385)
    if len(raw) > 16384:
        raise ValueError('service_remote_maintenance_denied')
    value = json.loads(raw)
    exact(value, 'python script script_sha256 config owner_uid health_url nonce',
          'service_remote_maintenance_denied')
    if ({k: value[k] for k in selection} != selection
            or not isinstance(value['nonce'], str)
            or not re.fullmatch('[0-9a-f]{32}', value['nonce'])):
        raise ValueError('service_remote_maintenance_denied')
    script = path(selection['script'])
    if hashlib.sha256(read_code(script, uid=0, limit=65536, allow_hardlinks=True)).hexdigest() != selection['script_sha256']:
        raise ValueError('service_remote_maintenance_denied')
    # The client waits for the first held frame before sending checks, so the
    # initial read cannot consume future stream messages. No caller code runs.
    program = BOOTSTRAP.replace('value=json.loads(sys.stdin.buffer.readline(16385))',
                                'value=' + repr(value), 1)
    os.setgroups([])
    os.setgid(pwd.getpwuid(selection['owner_uid']).pw_gid)
    os.setuid(selection['owner_uid'])
    os.execv(selection['python'], [selection['python'], '-B', '-c', program])


def dispatch(value, operation):
    value = configuration(value)
    row = value['operations'].get(operation)
    if row is None:
        raise ValueError('service_remote_operation_denied')
    if row['kind'] == 'executor':
        executable = path(row['executable'])
        regular(executable, uid=0, limit=65536)
        os.execv(str(executable), [str(executable)])
        return
    if row['kind'] == 'maintenance':
        return maintenance(row['selection'])
    # Entire argv/config is fixed independently of the SSH caller and payload.
    sys.argv = ['fixed-home-service', '--config', row['config']]
    if row['kind'] == 'runtime':
        from .service_runtime import main as run
    else:
        from .service_routes import main as run
    return run()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('operation')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError('service_remote_operator_required')
    value = json.loads(regular(args.config, uid=0, limit=65536))
    dispatch(value, args.operation)


if __name__ == '__main__':
    main()
