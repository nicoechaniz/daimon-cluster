"""Independent native Codex login for an authorized receiving account.

Device login is the independent fallback when no operator-approved shared
provider login was installed by the host adapter. It runs in its own durable
guest service; only a bounded owner action leaves its home.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import time
from pathlib import Path

from . import being_seed, onboarding_release
from .onboarding import OnboardingError, digest, private_directory, validate_plan
from .onboarding_guest import mkdir_chain, new_bytes
from .onboarding_service import publish

UNIT = 'daimon-onboarding-provider-login.service'
DEVICE_URL = 'https://auth.openai.com/codex/device'
SCHEMA = 'cluster-onboarding-provider/v1'


def service(code: Path) -> bytes:
    launcher = ('import sys;sys.path.insert(0,sys.argv.pop(1));'
                'from clusterctl.onboarding_provider import main;raise SystemExit(main())')
    argv = ['/usr/bin/python3', '-B', '-I', '-c', launcher, str(code), 'login',
            '--code', str(code), '--plan', '/home/agent/.onboarding-input/plan.json']
    encoded = ' '.join(json.dumps(arg.replace('%', '%%').replace('$', '$$')) for arg in argv)
    return ('[Unit]\nDescription=Independent receiving Codex device login\n'
            'After=network-online.target\nWants=network-online.target\n'
            '[Service]\nType=oneshot\nUser=agent\nGroup=agent\n'
            'Environment=HOME=/home/agent\nEnvironment=CODEX_HOME=/home/agent/.codex\n'
            'Environment=PATH=/usr/local/bin:/usr/bin:/bin\nUMask=0077\n'
            'StandardOutput=null\nStandardError=null\nKillMode=control-group\n'
            'TimeoutStartSec=960\nExecStart=' + encoded + '\n').encode()


class Provider:
    def __init__(self, home: Path, plan: dict, *, run=None):
        self.home, self.plan = home, validate_plan(plan)
        private_directory(home)
        private_directory(home / '.codex')
        self.state = home / '.local/state/daimon-onboarding/provider'
        mkdir_chain(home, self.state)
        new_bytes(self.state / 'binding.json', json.dumps(dict(schema=SCHEMA,
            plan_digest=digest(plan), account_profile=plan['account_profile']), sort_keys=True).encode())
        self.run = run or subprocess.run

    def _environment(self) -> dict:
        # Inference/login must never receive host bot tokens or another cache.
        return dict(HOME=str(self.home), CODEX_HOME=str(self.home / '.codex'),
                    PATH='/usr/local/bin:/usr/bin:/bin', LANG='C.UTF-8')

    def authorized(self) -> bool:
        result = self.run(['codex', '-c', 'cli_auth_credentials_store="file"', 'login', 'status'], env=self._environment(),
                          capture_output=True, timeout=30, check=False)
        return result.returncode == 0

    def login(self) -> None:
        """One supervised process owns the interactive native login attempt."""
        if self.authorized():
            return
        with being_seed._locked(self.state):
            now = int(time.time() * 1000)
            being_seed._write(self.state / 'attempt.json', dict(started_ms=now, deadline_ms=now + 900000))
            path = being_seed._path(self.state / 'login.txt')
            if path.exists():
                onboarding_release.regular(path, uid=os.geteuid(), limit=65536)
                if path.stat().st_mode & 0o077:
                    raise OnboardingError('private_provider_login_required')
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as output:
                result = self.run(['codex', '-c', 'cli_auth_credentials_store="file"', 'login', '--device-auth'], env=self._environment(),
                                  stdout=output, stderr=subprocess.STDOUT, timeout=900, check=False)
            if result.returncode != 0 or not self.authorized():
                raise OnboardingError('provider_login_incomplete')

    def account(self) -> str | None:
        """Private matcher input, never a public progress field or login receipt."""
        path = self.home / '.codex/auth.json'
        try:
            raw = onboarding_release.regular(path, uid=os.geteuid(), limit=65536)
        except FileNotFoundError:
            return None
        if path.stat().st_mode & 0o077:
            raise OnboardingError('private_provider_login_required')
        value = json.loads(raw)
        if not isinstance(value, dict) or value.get('auth_mode') != 'chatgpt':
            return None
        tokens = value.get('tokens')
        account = tokens.get('account_id') if isinstance(tokens, dict) else None
        if not isinstance(account, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,160}', account):
            return None
        return account

    def probe(self, expected_account: str, model: str, reasoning: str) -> dict:
        """Record a real native model turn; recover its output after a lost ACK."""
        if not self.authorized() or self.account() != expected_account:
            raise OnboardingError('account_authorization_required')
        marker = self.state / 'probe.json'
        result = dict(schema=SCHEMA, plan_digest=digest(self.plan), provider_verified=True,
                      model=model, reasoning=reasoning)
        if marker.exists():
            if being_seed._read(marker) != result:
                raise OnboardingError('existing_provider_probe_preserved')
            return result
        intent = dict(plan_digest=digest(self.plan), account=expected_account, model=model, reasoning=reasoning)
        started = self.state / 'probe-intent.json'
        output = self.state / 'probe-output.jsonl'
        token = 'PROVIDER_OK_' + digest(self.plan)[:20]
        with being_seed._locked(self.state):
            if started.exists():
                if being_seed._read(started) != intent:
                    raise OnboardingError('existing_provider_probe_preserved')
            else:
                # No invocation is repeated after uncertainty. A complete native
                # event stream can be recovered without another inference.
                new_bytes(started, json.dumps(intent, sort_keys=True).encode())
                fd = os.open(being_seed._path(output), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'wb') as stream:
                    self.run(['codex', '-c', 'cli_auth_credentials_store="file"',
                        '-c', 'approval_policy="never"', '-c', 'model_reasoning_effort=' + json.dumps(reasoning),
                        'exec', '--ephemeral', '--json', '--skip-git-repo-check', '--sandbox', 'read-only',
                        '--model', model, '-C', str(self.state),
                        'Do not use tools, read memory or change files. Reply with exactly: ' + token],
                        env=self._environment(), stdout=stream, stderr=subprocess.DEVNULL,
                        timeout=240, check=False)
            if not output.exists():
                raise OnboardingError('uncertain_external_effect')
            raw = onboarding_release.regular(output, uid=os.geteuid(), limit=1024**2)
            events = [json.loads(line) for line in raw.splitlines() if line.strip()]
            if (not any(event.get('type') == 'turn.completed' for event in events)
                    or any(event.get('type') in {'error', 'turn.failed'} for event in events)
                    or any(event.get('type', '').startswith('item.')
                           and event.get('item', {}).get('type') not in {'agent_message', 'reasoning'} for event in events)
                    or not any(event.get('type') == 'item.completed'
                           and event.get('item', {}).get('type') == 'agent_message'
                           and event['item'].get('text', '').strip() == token for event in events)):
                raise OnboardingError('uncertain_external_effect')
            new_bytes(marker, json.dumps(result, sort_keys=True).encode())
        return result

    def observe(self) -> dict:
        if self.authorized():
            marker = self.state / 'probe.json'
            receipt = being_seed._read(marker) if marker.exists() else None
            return dict(schema=SCHEMA, plan_digest=digest(self.plan), authorized=True,
                        provider_verified=receipt is not None, probe_receipt=receipt,
                        account_id=self.account(), login_running=False, action=None)
        action = None
        try:
            attempt = being_seed._read(self.state / 'attempt.json')
            path = self.state / 'login.txt'
            raw = onboarding_release.regular(path, uid=os.geteuid(), limit=65536)
            if path.stat().st_mode & 0o077:
                raise OnboardingError('private_provider_login_required')
            # Only the maintained native device URI and a one-time user code
            # can be returned. Raw diagnostics/tokens never leave this file.
            text = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', raw.decode(errors='replace'))
            code = re.search(r'(?<![A-Z0-9-])([A-Z0-9]{4,6}-[A-Z0-9]{4,6})(?![A-Z0-9-])', text)
            if (DEVICE_URL in text and code and type(attempt.get('deadline_ms')) is int
                    and int(time.time() * 1000) < attempt['deadline_ms']):
                action = dict(kind='openai-device-login', verification_uri=DEVICE_URL,
                              user_code=code.group(1), deadline_ms=attempt['deadline_ms'])
        except FileNotFoundError:
            pass
        status = self.run(['systemctl', 'show', UNIT, '--property=ActiveState'],
                          env=self._environment(), capture_output=True, text=True, timeout=30, check=False)
        running = getattr(status, 'stdout', '').strip() in {'ActiveState=activating', 'ActiveState=active'}
        return dict(schema=SCHEMA, plan_digest=digest(self.plan), authorized=False,
                    provider_verified=False, probe_receipt=None, account_id=None,
                    login_running=running, action=action)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('install', 'login', 'observe', 'probe'))
    parser.add_argument('--code', type=Path, required=True)
    parser.add_argument('--plan', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        import pwd
        account = pwd.getpwnam('agent')
        if (account.pw_uid != 1000 or account.pw_gid != 1000 or account.pw_dir != '/home/agent'
                or args.plan != Path('/home/agent/.onboarding-input/plan.json')):
            raise OnboardingError('qualified_guest_provider_required')
        plan = validate_plan(json.loads(onboarding_release.regular(args.plan, uid=1000)))
        if args.code != Path('/opt/daimon-onboarding') / plan['release_digest']:
            raise OnboardingError('qualified_guest_provider_required')
        onboarding_release.verify(args.code, plan['release_digest'], uid=0)
        if args.action == 'install':
            if os.geteuid() != 0:
                raise OnboardingError('qualified_guest_provider_required')
            publish(Path('/etc/systemd/system') / UNIT, service(args.code))
            for command in (['systemctl', 'daemon-reload'], ['systemctl', 'start', '--no-block', UNIT]):
                result = subprocess.run(command, capture_output=True, timeout=30, check=False)
                if result.returncode:
                    raise OnboardingError('provider_login_incomplete')
            value = dict(installed=True)
        else:
            if os.geteuid() != 1000:
                raise OnboardingError('qualified_guest_provider_required')
            provider = Provider(Path('/home/agent'), plan)
            if args.action == 'login':
                provider.login()
                return 0
            if args.action == 'probe':
                # Root supplies only the independently selected account ID,
                # never another body's tokens. Host dispatch must verify the
                # exact read-only profile mount before invoking this action.
                profile_path = Path('/home/agent/.onboarding-account/profile.json')
                profile = json.loads(onboarding_release.regular(profile_path, uid=0, limit=65536))
                if (not isinstance(profile, dict) or set(profile) != {'schema', 'name', 'account_id'}
                        or profile.get('schema') != 'cluster-onboarding-account/v1'
                        or profile.get('name') != plan['account_profile']
                        or not isinstance(profile.get('account_id'), str)
                        or not re.fullmatch(r'[A-Za-z0-9_-]{1,160}', profile['account_id'])):
                    raise OnboardingError('account_authorization_required')
                release = onboarding_release.verify(args.code, plan['release_digest'], uid=0)
                value = provider.probe(profile['account_id'], release['profile']['model'], release['profile']['reasoning'])
            else:
                value = provider.observe()
        print(json.dumps(value))
        return 0
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired):
        # Device action stays on the authenticated owner surface. No exception
        # or native login output is emitted into system journals or receipts.
        if args.action != 'login':
            print(json.dumps(dict(error='native_onboarding_provider_refused')))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
