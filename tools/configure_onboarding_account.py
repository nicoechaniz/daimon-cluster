"""Select account metadata without copying native credentials to another body."""
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path

from clusterctl import being_seed, onboarding_release
from clusterctl.onboarding import OnboardingError, private_directory
from clusterctl.onboarding_service import publish


def configure(root: Path, name: str, cache: Path, *, source_uid: int) -> dict:
    if not being_seed.NAME.fullmatch(name):
        raise OnboardingError('account_authorization_required')
    private_directory(root)
    raw = onboarding_release.regular(cache, uid=source_uid, limit=65536)
    if cache.stat().st_mode & 0o077:
        raise OnboardingError('private_provider_login_required')
    value = json.loads(raw)
    if not isinstance(value, dict) or value.get('auth_mode') not in {'chatgpt', 'chatgptAuthTokens'}:
        raise OnboardingError('account_authorization_required')
    tokens = value.get('tokens')
    account = tokens.get('account_id') if isinstance(tokens, dict) else None
    if not isinstance(account, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,160}', account):
        raise OnboardingError('account_authorization_required')
    selected = dict(schema='cluster-onboarding-account/v1', name=name, account_id=account)
    publish(root / (name + '.json'), json.dumps(selected, sort_keys=True).encode())
    return dict(configured=True, profile=name, credentials_copied=False)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--accounts', type=Path, required=True)
    parser.add_argument('--name', required=True)
    parser.add_argument('--native-cache', type=Path, required=True)
    parser.add_argument('--source-uid', type=int, required=True)
    args = parser.parse_args(argv)
    try:
        if os.geteuid() != 0 or args.source_uid < 0:
            raise OnboardingError('host_account_configuration_required')
        print(json.dumps(configure(args.accounts, args.name, args.native_cache, source_uid=args.source_uid)))
        return 0
    except (OSError, ValueError, KeyError):
        print(json.dumps(dict(configured=False, error='account_configuration_refused')))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
