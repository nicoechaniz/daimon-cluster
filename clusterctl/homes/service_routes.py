"""One fixed, privileged Caddy writer; no owner-selected path or command."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys

from ..onboarding_release import regular
from .service_package import canonical, exact, sha


def declaration(grant, origin):
    from .service_runtime import key
    c = grant['receiver']
    return dict(schema='dm.home-service-route/v1', home=c['home'], owner=c['owner'],
                name='s-'+key(c), origin=origin, prefix=grant['prefix'], upstream=grant['upstream'],
                auth_backend=grant['auth_backend'], routes=grant['routes'])


def apply(config, call):
    from .service_deploy import ServiceRoutes
    exact(config, 'schema home owner name origin prefix upstream auth_backend routes', 'invalid_service_route')
    exact(call, 'schema capability', 'invalid_service_route_call')
    if (config['schema'] != 'dm.home-service-route/v1'
            or call['schema'] != 'dm.home-service-route-call/v1'
            or call['capability'] != sha(canonical(config))):
        raise ValueError('service_route_capability_denied')
    # All bytes are from the independently protected, operator-selected route
    # declaration. stdin supplies only its exact digest, never Caddy directives.
    request = {k: config[k] for k in ('name', 'origin', 'prefix')}
    listener = {k: config[k] for k in ('prefix', 'upstream', 'auth_backend')}
    return ServiceRoutes(config['routes']).reconcile(request, listener, config['auth_backend'],
                                                     apply=True, authorize=lambda: True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    args = parser.parse_args()
    def expired(*_):
        raise TimeoutError('service_route_deadline')
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(180)
    try:
        config = json.loads(regular(args.config, uid=os.geteuid(), limit=65536))
        raw = sys.stdin.buffer.read(4097)
        if len(raw) > 4096:
            raise ValueError('service_route_call_capacity')
        print(json.dumps(apply(config, json.loads(raw))))
    except (ValueError, OSError, subprocess.SubprocessError, TimeoutError):
        print(json.dumps({'state': 'unconfirmed'}))
        raise SystemExit(2) from None


if __name__ == '__main__':
    main()
