"""Dedicated native Telegram configuration and receiving token preparation."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

from . import being_seed, onboarding_release
from .onboarding import OnboardingError, digest, validate_plan
from .onboarding_guest import mkdir_chain, new_bytes
from .onboarding_service import publish

COMMIT = '5af79bdf0716dadf92ae982bfbeafdf2eb21f6a9'
ARCHIVE = '6ab8a38ec08274eeb036c40632ffbeb6dc8b5d14d385d7d5de4a8428a3fcd9b5'
BINARY = 'e29bff3da0682e4c8f37ae75c9a724f5c0f3be6238063f14d86eb1123fd2e620'
SCHEMA = 'cluster-onboarding-telegram/v1'
UNIT = 'daimon-onboarding-telegram.service'


def connections(value: object) -> dict:
    if (not isinstance(value, dict) or set(value) != {'telegram_bot_token', 'telegram_chat_id'}
            or not isinstance(value['telegram_bot_token'], str)
            or not re.fullmatch(r'[0-9]{6,15}:[A-Za-z0-9_-]{30,100}', value['telegram_bot_token'])
            or type(value['telegram_chat_id']) is not int or not 0 < value['telegram_chat_id'] < 2**53):
        raise OnboardingError('connection_data_required')
    return value


def configuration(home: Path, code: Path, codex: Path, human: int, profile: dict) -> bytes:
    state = home / '.local/state/daimon-onboarding/telegram'
    # Values use TOML-compatible JSON strings; no token or source instruction
    # is interpolated into this file or any executable command.
    quote = json.dumps
    lines = [f'db_path = {quote(str(state / "telegram.sqlite3"))}',
        f'startup_admin_ids = [{human}]', 'poll_timeout_seconds = 30', 'edit_debounce_ms = 900',
        'max_text_chunk = 3500', f'tmp_dir = {quote(str(state / "tmp"))}',
        'background_maintenance = false', '[telegram]',
        f'bot_token_file = {quote(str(state / "bot.token"))}', 'api_base = "https://api.telegram.org"',
        'use_message_drafts = false', 'show_unfinished_messages = false',
        'lifecycle_notifications = false', 'auto_create_topics = false',
        'stale_topic_action = "none"', 'completion_notify_usernames = []', '[codex]',
        f'binary = {quote(str(codex))}', 'shared_app_server = true',
        'auto_attach_latest_history = false', f'default_cwd = {quote(str(home / "Projects/being"))}',
        f'default_model = {quote(profile["model"])}',
        f'default_reasoning_effort = {quote(profile["reasoning"])}',
        f'default_sandbox = {quote(profile["sandbox"])}',
        f'default_approval = {quote(profile["approval"])}', 'default_search_mode = "live"',
        'import_desktop_history = false', 'import_cli_history = false',
        'seed_workspaces = []', 'default_add_dirs = []']
    return ('\n'.join(lines) + '\n').encode()


def service(home: Path, code: Path, codex: Path = Path('/usr/local/bin/codex')) -> bytes:
    argv = [str(code / 'telegram/telecodex'), str(home / '.local/state/daimon-onboarding/telegram/config.toml')]
    encoded = ' '.join(json.dumps(arg.replace('%', '%%').replace('$', '$$')) for arg in argv)
    return ('[Unit]\nDescription=Dedicated receiving Telegram human listener\n'
        'After=network-online.target daimon-onboarding-matrix.service\nWants=network-online.target\n'
        '[Service]\nType=simple\nUser=agent\nGroup=agent\n'
        f'Environment=HOME={home}\nEnvironment=CODEX_HOME={home}/.codex\n'
        'Environment=PATH=/usr/local/bin:/usr/bin:/bin\nUMask=0077\n'
        'Restart=on-failure\nRestartSec=5\nKillMode=control-group\nTimeoutStartSec=180\nTimeoutStopSec=30\n'
        f'WorkingDirectory={home}/Projects/being\n'
        f'ExecStartPre={json.dumps(str(codex))} app-server daemon start\nExecStart={encoded}\n'
        '[Install]\nWantedBy=multi-user.target\n').encode()


def api(token: str, method: str) -> dict:
    if method not in {'getMe', 'getWebhookInfo'}:
        raise OnboardingError('unsupported_telegram_preflight')
    try:
        request = urllib.request.Request('https://api.telegram.org/bot' + token + '/' + method, data=b'')
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read(65537)
        value = json.loads(raw)
        if (len(raw) > 65536 or not isinstance(value, dict) or value.get('ok') is not True
                or not isinstance(value.get('result'), dict)):
            raise ValueError()
        return value['result']
    except (OSError, ValueError, urllib.error.URLError):
        # Never disclose a credential-bearing URL, vendor description or trace.
        raise OnboardingError('telegram_preflight_failed') from None


def prepare(home: Path, code: Path, codex: Path, plan: dict, profile: dict,
            supplied: dict, *, request=api) -> dict:
    validate_plan(plan)
    value = connections(supplied)
    token = value['telegram_bot_token']
    bot = request(token, 'getMe')
    if (bot.get('is_bot') is not True or type(bot.get('id')) is not int or bot['id'] <= 0
            or bot['id'] != int(token.split(':', 1)[0])
            or not isinstance(bot.get('username'), str) or not re.fullmatch(r'[A-Za-z0-9_]{5,64}', bot['username'])):
        raise OnboardingError('telegram_preflight_failed')
    if bot.get('has_topics_enabled') is not True:
        raise OnboardingError('telegram_topics_required')
    webhook = request(token, 'getWebhookInfo')
    if webhook.get('url') != '':
        raise OnboardingError('existing_telegram_consumer_preserved')
    state = home / '.local/state/daimon-onboarding/telegram'
    mkdir_chain(home, state)
    binding = dict(schema=SCHEMA, plan_digest=digest(plan), bot_id=bot['id'],
                   human_id=value['telegram_chat_id'], token_sha256=hashlib.sha256(token.encode()).hexdigest())
    # Invalid or incompatible bot data never freezes the receiving binding.
    with being_seed._locked(state):
        new_bytes(state / 'binding.json', json.dumps(binding, sort_keys=True).encode())
        new_bytes(state / 'bot.token', token.encode())
        mkdir_chain(home, state / 'tmp')
        new_bytes(state / 'config.toml', configuration(home, code, codex, value['telegram_chat_id'], profile))
    return dict(configured=True, plan_digest=digest(plan), bot_id=bot['id'], topics_enabled=True)


def reserve(root: Path, plan: dict, supplied: dict) -> None:
    """Keep one durable bot reservation across all jobs, including crashes."""
    from .onboarding import private_directory
    validate_plan(plan)
    supplied = connections(supplied)
    private_directory(root)
    catalog = root / 'telegram-consumers'
    private_directory(catalog, create=True)
    bot_id = int(supplied['telegram_bot_token'].split(':', 1)[0])
    record = dict(schema='cluster-onboarding-telegram-consumer/v1', bot_id=bot_id,
                  plan_digest=digest(plan))
    with being_seed._locked(catalog):
        path = catalog / (str(bot_id) + '.json')
        if path.exists():
            if being_seed._read(path) != record:
                raise OnboardingError('existing_telegram_consumer_preserved')
        else:
            being_seed._write(path, record)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'install', 'observe', 'probe', 'native-start'))
    parser.add_argument('--code', type=Path, required=True)
    parser.add_argument('--plan', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        import pwd
        account = pwd.getpwnam('agent')
        if (account.pw_uid != 1000 or account.pw_gid != 1000 or account.pw_dir != '/home/agent'
                or args.plan != Path('/home/agent/.onboarding-input/plan.json')):
            raise OnboardingError('qualified_guest_telegram_required')
        plan = validate_plan(json.loads(onboarding_release.regular(args.plan, uid=1000)))
        if args.code != Path('/opt/daimon-onboarding') / plan['release_digest']:
            raise OnboardingError('qualified_guest_telegram_required')
        release = onboarding_release.verify(args.code, plan['release_digest'], uid=0)
        binary = args.code / 'telegram/telecodex'
        raw = onboarding_release.regular(binary, uid=0)
        if hashlib.sha256(raw).hexdigest() != BINARY or binary.stat().st_mode & 0o111 != 0o111:
            raise OnboardingError('qualified_telegram_binary_required')
        home = Path('/home/agent')
        state = home / '.local/state/daimon-onboarding/telegram'
        codex_path = shutil.which('codex', path='/usr/local/bin:/usr/bin:/bin')
        if not codex_path:
            raise OnboardingError('native_codex_required')
        codex = Path(codex_path)
        if args.action == 'prepare':
            if os.geteuid() != 1000:
                raise OnboardingError('qualified_guest_telegram_required')
            incoming = Path('/home/agent/.onboarding-connections/connections.json')
            supplied = json.loads(onboarding_release.regular(incoming, uid=1000, limit=65536))
            if incoming.stat().st_mode & 0o077:
                raise OnboardingError('private_telegram_connections_required')
            value = prepare(home, args.code, codex, plan, release['profile'], supplied)
        elif args.action == 'native-start':
            if os.geteuid() != 1000:
                raise OnboardingError('qualified_guest_telegram_required')
            result = subprocess.run([str(codex), 'app-server', 'daemon', 'start'],
                capture_output=True, text=True, timeout=180, check=False,
                env=dict(HOME=str(home), CODEX_HOME=str(home / '.codex'), PATH='/usr/local/bin:/usr/bin:/bin'))
            if result.returncode:
                raise OnboardingError('native_codex_daemon_start_failed')
            value = dict(native_started=True, plan_digest=digest(plan))
        elif args.action == 'probe':
            if os.geteuid() != 1000:
                raise OnboardingError('qualified_guest_telegram_required')
            # No bot read, listener, history import or model inference.
            result = subprocess.run([str(binary), '--probe-native', str(codex), str(home / 'Projects/being')],
                capture_output=True, text=True, timeout=60, check=False,
                env=dict(HOME=str(home), CODEX_HOME=str(home / '.codex'), PATH='/usr/local/bin:/usr/bin:/bin'))
            if result.returncode:
                raise OnboardingError('native_telegram_probe_failed')
            value = dict(native_probe=json.loads(result.stdout), inference=False, bot_read=False)
        else:
            if os.geteuid() != 0:
                raise OnboardingError('qualified_guest_telegram_required')
            marker = state / 'binding.json'
            if not marker.exists():
                value = dict(configured=False, listening=False, plan_digest=digest(plan))
            else:
                binding = json.loads(onboarding_release.regular(marker, uid=1000, limit=65536))
                if binding.get('schema') != SCHEMA or binding.get('plan_digest') != digest(plan):
                    raise OnboardingError('existing_telegram_binding_preserved')
                expected = configuration(home, args.code, codex, binding['human_id'], release['profile'])
                if not (state / 'config.toml').exists() or not (state / 'bot.token').exists():
                    if args.action == 'install':
                        raise OnboardingError('telegram_preparation_required')
                    print(json.dumps(dict(configured=False, listening=False, plan_digest=digest(plan))))
                    return 0
                configured = onboarding_release.regular(state / 'config.toml', uid=1000, limit=65536)
                token_path = state / 'bot.token'
                token = onboarding_release.regular(token_path, uid=1000, limit=1024)
                if (configured != expected or marker.stat().st_mode & 0o077
                        or (state / 'config.toml').stat().st_mode & 0o077 or token_path.stat().st_mode & 0o077
                        or hashlib.sha256(token).hexdigest() != binding['token_sha256']):
                    raise OnboardingError('existing_telegram_binding_preserved')
                unit = Path('/etc/systemd/system') / UNIT
                unit_bytes = service(home, args.code, codex)
                if args.action == 'install':
                    publish(unit, unit_bytes)
                    for command in (['systemctl', 'daemon-reload'], ['systemctl', 'enable', '--now', UNIT]):
                        result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
                        if result.returncode:
                            raise OnboardingError('telegram_service_failed')
                if unit.exists() and onboarding_release.regular(unit, uid=0) != unit_bytes:
                    raise OnboardingError('existing_telegram_service_preserved')
                result = subprocess.run(['systemctl', 'show', UNIT, '--property=ActiveState', '--property=MainPID'],
                                        capture_output=True, text=True, timeout=30, check=False)
                fields = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
                pid = fields.get('MainPID', '')
                listening = (fields.get('ActiveState') == 'active' and pid.isdecimal() and int(pid) > 0
                             and Path('/proc', pid, 'exe').resolve() == binary)
                value = dict(configured=True, listening=listening, plan_digest=digest(plan),
                             bot_id=binding['bot_id'], telegram_verified=False)
        print(json.dumps(value))
        return 0
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired):
        print(json.dumps(dict(error='native_onboarding_telegram_refused')))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
