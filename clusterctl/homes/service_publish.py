"""One finite owner command: deploy, ordinary Home link/sync, exact finalization.

The operator installs this alongside the existing publisher. Its binding and
private-token reader are reused; no login, account or credential is introduced.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import signal
from pathlib import Path
import time
from types import SimpleNamespace
import urllib.request
from urllib.parse import quote, urlsplit

from ..onboarding_release import regular
from .service_package import request


def publish(publisher, binding, value, *, seconds=300):
    request(value)
    deadline = time.monotonic() + seconds

    def owner_call(selected_binding, operation, payload):
        access = selected_binding['access']
        destination = urlsplit(access['owner_url'])
        if (destination.scheme != 'http' or destination.hostname != '127.0.0.1'
                or destination.username or destination.password or destination.path not in ('', '/')
                or destination.query or destination.fragment):
            raise ValueError('service_own_owner_adapter_required')
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('service_publication_deadline')
        url = access['owner_url'].rstrip('/') + '/owner/' + quote(access['home_ref'], safe='') + '/' + operation
        token = publisher.private_token(access['owner_token_file'])
        req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                    headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
        with urllib.request.build_opener(publisher.NoRedirect).open(req, timeout=remaining) as response:
            raw = response.read(65537)
            if len(raw) > 65536:
                raise ValueError('service_result_capacity')
            return json.loads(raw)

    original = publisher.owner_request
    publisher.owner_request = owner_call
    try:
        result = owner_call(binding, 'service-deploy', value)
        if result['state'] == 'complete':
            return result  # Exact retained completion, not a new publication.
        if result['state'] != 'publication-required':
            return result  # No polling, resubmission or speculative activation.
        audience = value['audience']
        existing = [e for e in publisher.submitted_state(binding)['entries'] if e.get('id') == value['service']]
        if any(e.get('kind') != 'link' or e.get('url') != result['url']
               or e.get('visibility') != audience['visibility']
               or e.get('application') != {'schema': 'dm.application/v1', 'mode': 'shared'} for e in existing):
            return {**result, 'state': 'publication-conflict', 'error': 'service_existing_app_preserved'}
        args = SimpleNamespace(command='link', id=value['service'], url=result['url'],
                app=True, app_mode='shared', app_capability=None, app_dependency=None,
                title=value['app']['title'], summary=value['app']['summary'],
                decision=value['app']['decision'], visibility=audience['visibility'],
                recipient=audience.get('recipients', []), tribe=audience.get('tribes', []))
        publisher.publish(binding, args)
        entry = next(e for e in publisher.submitted_state(binding)['entries']
                     if e.get('id') == value['service'] and e['visibility'] == audience['visibility'])
        return owner_call(binding, 'service-finalize', {'request': value,
                          'resource': entry['artifact_ref'], 'version': entry['version_ref']})
    finally:
        publisher.owner_request = original


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--publisher', type=Path, required=True, help='Existing installed Home publisher home.py')
    parser.add_argument('--binding', type=Path, required=True)
    parser.add_argument('--request', type=Path, required=True)
    args = parser.parse_args()
    def expired(*_):
        raise TimeoutError('service_publication_deadline')
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(300)  # Includes the existing publisher's file lock and local I/O.
    try:
        regular(args.publisher, uid=os.geteuid(), limit=256*1024)
        spec = importlib.util.spec_from_file_location('own_home_publisher', args.publisher)
        if spec is None or spec.loader is None:
            raise ValueError('service_existing_publisher_required')
        publisher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(publisher)
        value = json.loads(regular(args.request, uid=os.geteuid(), limit=65536))
        result = publish(publisher, publisher.read_binding(args.binding), value)
        print(json.dumps(result))
        if result['state'] != 'complete':
            raise SystemExit(2)
    except (ValueError, KeyError, OSError, TimeoutError):
        # Do not print credential-bearing HTTP exceptions or provider output.
        print(json.dumps({'state': 'unconfirmed', 'action': 'inspect the retained request; retry the same request only'}))
        raise SystemExit(2) from None


if __name__ == '__main__':
    main()
