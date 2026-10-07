"""Select account metadata and explicitly authorize optional shared login."""
from __future__ import annotations

import argparse
import json
import os
import re
import hashlib
from pathlib import Path

from clusterctl import being_seed, onboarding_release
from clusterctl.onboarding import OnboardingError, private_directory
from clusterctl.onboarding_service import publish


def configure(root: Path, name: str, cache: Path, *, source_uid: int,
              shared_pairs: dict | None = None, instruction: Path | None = None,
              instruction_uid: int | None = None) -> dict:
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
    authorization = None
    if shared_pairs is not None:
        if (not isinstance(shared_pairs, dict) or not shared_pairs or instruction is None
                or instruction_uid is None or value.get('auth_mode') != 'chatgpt'
                or any(not isinstance(k, str) or not being_seed.NAME.fullmatch(k)
                       or not isinstance(v, str) or not being_seed.NAME.fullmatch(v)
                       for k, v in shared_pairs.items())):
            raise OnboardingError('account_authorization_required')
        human = onboarding_release.regular(instruction, uid=instruction_uid, limit=65536)
        if not human.strip() or instruction.stat().st_mode & 0o077:
            raise OnboardingError('private_provider_login_required')
        authorization = dict(schema='cluster-onboarding-shared-login/v1', name=name, account_id=account,
            cache=str(cache), source_uid=source_uid, pairs=shared_pairs,
            human_instruction_digest=hashlib.sha256(human).hexdigest(), revoked=False)
    publish(root / (name + '.json'), json.dumps(selected, sort_keys=True).encode())
    result = dict(configured=True, profile=name, credentials_copied=False)
    if authorization is not None:
        publish(root / (name + '.credentials.json'), json.dumps(authorization, sort_keys=True).encode())
        result['sharing_authorized'] = True
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--accounts', type=Path, required=True)
    parser.add_argument('--name', required=True)
    parser.add_argument('--native-cache', type=Path, required=True)
    parser.add_argument('--source-uid', type=int, required=True)
    parser.add_argument('--shared-pair', action='append', default=[], metavar='BEING=OWNER')
    parser.add_argument('--instruction', type=Path)
    parser.add_argument('--instruction-uid', type=int)
    args = parser.parse_args(argv)
    try:
        if os.geteuid() != 0 or args.source_uid < 0:
            raise OnboardingError('host_account_configuration_required')
        pairs = dict(item.split('=', 1) for item in args.shared_pair) if args.shared_pair else None
        print(json.dumps(configure(args.accounts, args.name, args.native_cache, source_uid=args.source_uid,
            shared_pairs=pairs, instruction=args.instruction, instruction_uid=args.instruction_uid)))
        return 0
    except (OSError, ValueError, KeyError):
        print(json.dumps(dict(configured=False, error='account_configuration_refused')))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
