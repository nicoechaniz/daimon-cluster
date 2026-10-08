"""Root-selected accounts, delegated shared login, and native provider proof."""
from __future__ import annotations

import json
import inspect
import os
import re
from pathlib import Path

from . import being_seed
from .onboarding import Observation, OnboardingError, digest, private_directory
from .onboarding_actions import Actions, SCHEMA as ACTION_SCHEMA
from .onboarding_provider import SCHEMA
from .onboarding_service import publish
from .onboarding_custody import document
from . import onboarding_release


def install_shared_cache(source, destination, *, uid: int, gid: int, account: str) -> None:
    """Atomic, restartable transfer to an empty or byte-identical private cache."""
    import fcntl
    import json
    import os
    import stat
    from pathlib import Path

    source, destination = Path(source), Path(destination)
    def read(path, owner, *, links=1):
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner
                    or info.st_nlink != links or info.st_mode & 0o077 or not 0 < info.st_size <= 65536):
                raise ValueError('private_shared_login_required')
            return stream.read(65537)
    raw = read(source, os.geteuid())
    value = json.loads(raw)
    if (not isinstance(value, dict) or value.get('auth_mode') != 'chatgpt'
            or not isinstance(value.get('tokens'), dict) or value['tokens'].get('account_id') != account):
        raise ValueError('shared_login_account_mismatch')
    parent = destination.parent
    info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_mode & 0o077:
        raise ValueError('private_shared_login_required')
    lock = parent / '.shared-login.lock'
    fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError('private_shared_login_required')
        fcntl.flock(fd, fcntl.LOCK_EX)
        temporary = parent / '.shared-login-candidate'
        if destination.exists() or destination.is_symlink():
            if temporary.exists() and not temporary.is_symlink() and not destination.is_symlink():
                current, candidate = destination.lstat(), temporary.lstat()
                if (stat.S_ISREG(current.st_mode) and stat.S_ISREG(candidate.st_mode)
                        and (current.st_dev, current.st_ino) == (candidate.st_dev, candidate.st_ino)
                        and current.st_nlink == 2 and read(destination, uid, links=2) == raw):
                    # Recover the crash window between atomic link and cleanup.
                    temporary.unlink()
            if read(destination, uid) != raw:
                raise ValueError('existing_shared_login_preserved')
            return
        if temporary.exists() or temporary.is_symlink():
            # A crash may leave a partial private candidate. Only the installer
            # owns this marker, and a foreign inode is never removed.
            fd_tmp = os.open(temporary, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                info = os.fstat(fd_tmp)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid not in {os.geteuid(), uid}
                        or info.st_nlink != 1 or info.st_mode & 0o077):
                    raise ValueError('existing_shared_login_preserved')
            finally:
                os.close(fd_tmp)
            temporary.unlink()
        fd_tmp = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd_tmp, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fchown(stream.fileno(), uid, gid)
            os.fsync(stream.fileno())
        # Linking refuses a foreign credential installed during this operation.
        os.link(temporary, destination, follow_symlinks=False)
        temporary.unlink()
        parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        os.close(fd)


class ManagedAccount:
    def __init__(self, host):
        self.host, self.config = host, host.config

    def shared(self, plan: dict, profile: dict) -> dict | None:
        path = self.config.accounts / (plan['account_profile'] + '.credentials.json')
        if not path.exists():
            return None
        value = document(path)
        if (set(value) != {'schema', 'name', 'account_id', 'cache', 'source_uid',
                          'pairs', 'human_instruction_digest', 'revoked'}
                or value['schema'] != 'cluster-onboarding-shared-login/v1'
                or value['name'] != profile['name'] or value['account_id'] != profile['account_id']
                or not isinstance(value['cache'], str) or not Path(value['cache']).is_absolute()
                or type(value['source_uid']) is not int or value['source_uid'] < 0
                or type(value['revoked']) is not bool or not isinstance(value['pairs'], dict)
                or not isinstance(value['human_instruction_digest'], str)
                or not re.fullmatch(r'[0-9a-f]{64}', value['human_instruction_digest'])):
            raise OnboardingError('account_authorization_required')
        if value['revoked'] or value['pairs'].get(plan['name']) != plan['owner']:
            raise OnboardingError('account_authorization_required')
        return value

    def install_shared(self, plan: dict, profile: dict, authorization: dict) -> None:
        """Transfer only explicitly shared provider login through a private mount.

        Matrix custody, conversation history and other body files never enter
        this handoff. A foreign receiving credential is preserved. Credential
        bytes never become command arguments, diagnostics or job receipts.
        """
        cache = Path(authorization['cache'])
        raw = onboarding_release.regular(cache, uid=authorization['source_uid'], limit=65536)
        if cache.stat().st_mode & 0o077:
            raise OnboardingError('private_provider_login_required')
        value = json.loads(raw)
        if (not isinstance(value, dict) or value.get('auth_mode') != 'chatgpt'
                or not isinstance(value.get('tokens'), dict)
                or value['tokens'].get('account_id') != profile['account_id']):
            raise OnboardingError('account_authorization_required')
        root = self.config.views / digest(plan) / 'account-private'
        private_directory(root, create=True)
        path = root / 'auth.json'
        device = 'onboarding-account-private'
        mount = dict(type='disk', source=str(root), path='/run/daimon-onboarding-account-private',
                     readonly='true', shift='true')
        _, code, _ = self.host._guest_paths(plan)
        # Native code owns this login service, so a pending fresh-device attempt
        # can be quiesced before the already-approved shared login is installed.
        program = (
            'import sys,subprocess; from pathlib import Path; '
            'sys.path.insert(0,sys.argv[1]); '
            'from clusterctl.onboarding_provider import service,UNIT; '
            'unit=Path("/etc/systemd/system")/UNIT; '
            'assert not unit.exists() or unit.read_bytes()==service(Path(sys.argv[1])); '
            'subprocess.run(["systemctl","stop",UNIT],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);\n'
        ) + inspect.getsource(install_shared_cache) + (
            '\ninstall_shared_cache("/run/daimon-onboarding-account-private/auth.json",'
            '"/home/agent/.codex/auth.json",uid=1000,gid=1000,account=sys.argv[2])'
        )
        try:
            publish(path, raw)
            if not self.host._mounted(plan, {device: mount}):
                self.host._dispatch(plan, ['config', 'device', 'add', self.host.instance(plan), device,
                    'disk', *[key+'='+value for key, value in mount.items() if key != 'type']])
            self.host._dispatch(plan, ['exec', self.host.instance(plan), '--',
                'python3', '-B', '-I', '-c', program, str(code), profile['account_id']])
        finally:
            if self.host._mounted(plan, {device: mount}):
                self.host._dispatch(plan, ['config', 'device', 'remove', self.host.instance(plan), device])
            path.unlink(missing_ok=True)

    def profile(self, plan: dict) -> dict:
        if self.config.accounts is None:
            raise OnboardingError('account_authorization_required')
        private_directory(self.config.accounts)
        value = being_seed._read(self.config.accounts / (plan['account_profile'] + '.json'))
        if (set(value) != {'schema', 'name', 'account_id'}
                or value.get('schema') != 'cluster-onboarding-account/v1'
                or value.get('name') != plan['account_profile']
                or not isinstance(value.get('account_id'), str)
                or not re.fullmatch(r'[A-Za-z0-9_-]{1,160}', value['account_id'])):
            raise OnboardingError('account_authorization_required')
        return value

    def mount(self, plan: dict) -> dict:
        if self.config.views is None:
            raise OnboardingError('receiving_code_configuration_required')
        return dict(type='disk', source=str(self.config.views / digest(plan) / 'account-public'),
                    path='/home/agent/.onboarding-account', readonly='true', shift='true')

    def command(self, plan: dict, action: str) -> dict:
        _, code, _ = self.host._guest_paths(plan)
        launcher = ('import sys;sys.path.insert(0,sys.argv.pop(1));'
                    'from clusterctl.onboarding_provider import main;raise SystemExit(main())')
        identity = [] if action == 'install' else ['--user', '1000', '--group', '1000', '--env', 'HOME=/home/agent']
        output = self.host._dispatch(plan, ['exec', self.host.instance(plan), *identity, '--',
            'python3', '-B', '-I', '-c', launcher, str(code), action, '--code', str(code),
            '--plan', '/home/agent/.onboarding-input/plan.json'])
        value = json.loads(output)
        if (not isinstance(value, dict) or action != 'install' and (
                value.get('schema') != SCHEMA or value.get('plan_digest') != digest(plan))):
            raise OnboardingError('invalid_onboarding_observation')
        return value

    def _action(self, plan: dict, action: dict | None) -> None:
        if self.config.progress is None:
            raise OnboardingError('invalid_onboarding_host_configuration')
        Actions(self.config.progress, worker_uid=os.geteuid()).publish(dict(schema=ACTION_SCHEMA,
            name=plan['name'], owner=plan['owner'], plan_digest=digest(plan), action=action))

    def observe(self, plan: dict) -> Observation:
        try:
            profile = self.profile(plan)
        except FileNotFoundError:
            return Observation('waiting', reason='account_authorization_required')
        if not self.host._mounted(plan, {'onboarding-account-public': self.mount(plan)}):
            return Observation('absent', safe_to_execute=True)
        value = self.command(plan, 'observe')
        self._action(plan, value.get('action'))
        if value.get('authorized') is not True:
            if self.shared(plan, profile) is not None:
                return Observation('absent', safe_to_execute=True)
            return (Observation('waiting', reason='account_authorization_required') if value.get('login_running')
                    else Observation('absent', safe_to_execute=True))
        if value.get('account_id') != profile['account_id']:
            return Observation('waiting', reason='account_authorization_required')
        receipt = value.get('probe_receipt')
        if receipt is None:
            return Observation('absent', safe_to_execute=True)
        if (not isinstance(receipt, dict) or receipt.get('schema') != SCHEMA
                or receipt.get('plan_digest') != digest(plan) or receipt.get('provider_verified') is not True):
            raise OnboardingError('invalid_onboarding_observation')
        # Host access observation has already verified its dedicated SSH
        # listener. Readiness permits Telegram setup; final acceptance still
        # requires an actual owner SSH/native Codex session.
        return Observation('complete', dict(verified=True, ssh_ready=True, provider_verified=True))

    def execute(self, plan: dict) -> None:
        profile, mount = self.profile(plan), self.mount(plan)
        source = Path(mount['source'])
        being_seed._path(source)
        source.mkdir(mode=0o755, exist_ok=True)
        if not source.is_dir() or source.stat().st_uid != os.geteuid():
            raise OnboardingError('owned_onboarding_account_profile_required')
        # The worker uses umask 0077. This nonsecret, read-only mount must still
        # be traversable by the receiving agent, including after a prior retry.
        source.chmod(0o755)
        publish(source / 'profile.json', json.dumps(profile, sort_keys=True).encode(), mode=0o644)
        if not self.host._mounted(plan, {'onboarding-account-public': mount}):
            self.host._dispatch(plan, ['config', 'device', 'add', self.host.instance(plan),
                'onboarding-account-public', 'disk', *[key + '=' + value for key, value in mount.items() if key != 'type']])
        value = self.command(plan, 'observe')
        if value.get('authorized'):
            if value.get('account_id') != profile['account_id']:
                raise OnboardingError('account_authorization_required')
            self.command(plan, 'probe')
        else:
            shared = self.shared(plan, profile)
            if shared is not None:
                self.install_shared(plan, profile, shared)
                observed = self.command(plan, 'observe')
                if not observed.get('authorized') or observed.get('account_id') != profile['account_id']:
                    raise OnboardingError('account_authorization_required')
                self.command(plan, 'probe')
            else:
                self.command(plan, 'install')
