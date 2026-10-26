"""Physical execution on a retained native body, separate from Incus inventory.

The protected placement binds an existing plan to a pinned SSH host. It grants
no Matrix identity or lifecycle authority; callers retain those checks and their
operation journals. Transport loss leaves the attempted operation uncertain.
"""
from __future__ import annotations

import json
import fcntl
import math
import os
import re
import shlex
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from . import being_seed, onboarding_release
from .onboarding import OnboardingError, digest, private_directory


# A remote monotonic clock and /proc namespace belong to the receiving kernel.
# Rebase only the closed owner-control options, bounded by the original sender
# wall expiry as well as its remaining duration. Never manufacture process proof.
REMOTE_LAUNCH = '''import hashlib,json,os,sys,time
request=json.loads(sys.argv[1])
if hashlib.sha256(open('/etc/machine-id','rb').read().strip()).hexdigest()!=request['machine_id_sha256']:
    raise SystemExit('native_receiving_host_changed')
remaining=min(request['remaining_seconds'],request['expires_at_ms']/1000-time.time())
if remaining<=0:raise SystemExit('receiving_host_deadline_expired')
argv=request['argv']
if request['owner_clock']:
    if argv.count('--deadline-ns')!=1 or argv.count('--time-namespace')!=1:
        raise SystemExit('receiving_owner_deadline_binding_required')
    argv[argv.index('--deadline-ns')+1]=str(time.monotonic_ns()+int(min(remaining,60)*1e9))
    argv[argv.index('--time-namespace')+1]=os.readlink('/proc/self/ns/time')
os.setgroups([])
os.setgid(request['gid']);os.setuid(request['uid'])
os.chdir(request['home'])
os.execvpe(argv[0],argv,{'PATH':'/usr/local/bin:'+os.defpath,'LANG':'C.UTF-8',
    'PYTHONDONTWRITEBYTECODE':'1',**request['env']})
'''

PUBLIC_CODE = '''import hashlib,json,os,stat,sys
from pathlib import Path
root=Path(sys.argv[1]);expected=sys.argv[2]
if not root.exists():
    print(json.dumps({'available':False}));raise SystemExit(0)
for path in (root,*root.parents):
    s=path.lstat()
    if not stat.S_ISDIR(s.st_mode) or s.st_uid!=0 or s.st_mode&0o022:
        raise SystemExit('native_receiving_code_changed')
rows=[]
for path in sorted(root.rglob('*')):
    s=path.lstat()
    if s.st_uid!=0 or s.st_mode&0o022:
        raise SystemExit('native_receiving_code_changed')
    if stat.S_ISDIR(s.st_mode):continue
    if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1:
        raise SystemExit('native_receiving_code_changed')
    if path.name=='release.json' and path.parent==root:continue
    rows.append({'path':path.relative_to(root).as_posix(),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
release=json.loads((root/'release.json').read_bytes())
fingerprint=hashlib.sha256(json.dumps(release,sort_keys=True,separators=(',',':')).encode()).hexdigest()
if fingerprint!=expected or release.get('files')!=rows:
    raise SystemExit('native_receiving_code_changed')
print(json.dumps({'available':True,'code_digest':fingerprint}))
'''


@dataclass(frozen=True)
class NativeBody:
    value: dict
    locator: Path

    @classmethod
    def load(cls, locator: Path, plan: dict, *, expected_digest: str | None = None) -> NativeBody:
        value = being_seed._read(locator)
        if expected_digest is not None and digest(value) != expected_digest:
            raise OnboardingError('native_receiving_placement_changed')
        required = {'schema', 'plan_digest', 'host', 'port', 'ssh_user',
                    'identity_file', 'identity_uid', 'known_hosts', 'machine_id_sha256',
                    'bootstrap_python', 'home'}
        if (set(value) != required or value['schema'] != 'cluster-native-body-placement/v1'
                or value['plan_digest'] != digest(plan)
                or not isinstance(value['host'], str)
                or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.:-]{0,252}', value['host']) is None
                or not isinstance(value['ssh_user'], str)
                or re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', value['ssh_user']) is None
                or type(value['port']) is not int or not 1 <= value['port'] <= 65535
                or type(value['identity_uid']) is not int or not 0 <= value['identity_uid'] < 2**32
                or not isinstance(value['machine_id_sha256'], str)
                or re.fullmatch(r'[0-9a-f]{64}', value['machine_id_sha256']) is None
                or value['home'] != '/home/agent'):
            raise OnboardingError('native_receiving_placement_required')
        for key in ('identity_file', 'known_hosts', 'bootstrap_python'):
            if (not isinstance(value[key], str) or not Path(value[key]).is_absolute()
                    or '..' in Path(value[key]).parts):
                raise OnboardingError('native_receiving_placement_required')
        # These are references, never credential values. Do not follow replaced
        # paths or accept keys writable by another participant.
        for key in ('identity_file', 'known_hosts'):
            onboarding_release.regular(Path(value[key]),
                uid=value['identity_uid'] if key == 'identity_file' else os.geteuid())
        if Path(value['identity_file']).stat().st_mode & 0o077:
            raise OnboardingError('native_receiving_placement_required')
        return cls(value, locator)

    @property
    def python(self) -> Path:
        return Path(self.value['bootstrap_python'])

    def ssh(self) -> list[str]:
        return ['ssh', '-F', '/dev/null', '-o', 'BatchMode=yes',
                '-o', 'StrictHostKeyChecking=yes', '-o', 'IdentitiesOnly=yes',
                '-o', 'ConnectTimeout=8', '-o', 'UserKnownHostsFile=' + self.value['known_hosts'],
                '-i', self.value['identity_file'], '-p', str(self.value['port'])]

    def code_available(self, code: Path, fingerprint: str, *, deadline_ns: int | None = None) -> bool:
        value = json.loads(self.execute([str(self.python), '-B', '-I', '-c', PUBLIC_CODE,
            str(code), fingerprint], uid=0, gid=0, deadline_ns=deadline_ns))
        if value == {'available': False}:
            return False
        if value != {'available': True, 'code_digest': fingerprint}:
            raise OnboardingError('native_receiving_code_changed')
        return True

    def prepare_code(self, source: Path, fingerprint: str, *, deadline_ns: int | None = None) -> Path:
        """Copy only an already-qualified public artifact; never a private home.

        Partial bytes stay resumable on the receiver. An existing selected
        generation is verified, never changed. No native runtime is restarted.
        """
        onboarding_release.verify(source, fingerprint, uid=os.geteuid())
        state = private_directory(self.locator.parent / (self.locator.name + '.preparations'), create=True)
        descriptor = os.open(state / (fingerprint + '.lock'), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'r+') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise OnboardingError('native_receiving_preparation_in_flight') from None
            return self._prepare_code(source, fingerprint, state=state, deadline_ns=deadline_ns)

    def _prepare_code(self, source: Path, fingerprint: str, *, state: Path,
                      deadline_ns: int | None) -> Path:
        code = Path('/opt/daimon-onboarding-runtime') / fingerprint
        if self.code_available(code, fingerprint, deadline_ns=deadline_ns):
            return code
        deadline = min(deadline_ns or time.monotonic_ns() + 60_000_000_000,
                       time.monotonic_ns() + 60_000_000_000)
        progress = state / (fingerprint + '.json')
        if progress.exists():
            retained = being_seed._read(progress)
            if (set(retained) != {'schema', 'code_digest', 'stage_id'}
                    or retained['schema'] != 'cluster-native-code-preparation/v1'
                    or retained['code_digest'] != fingerprint
                    or not isinstance(retained['stage_id'], str)
                    or re.fullmatch(r'[0-9a-f]{32}', retained['stage_id']) is None):
                raise OnboardingError('native_receiving_preparation_changed')
        else:
            retained = dict(schema='cluster-native-code-preparation/v1', code_digest=fingerprint,
                            stage_id=uuid.uuid4().hex)
            being_seed._write(progress, retained)
        stage = code.with_name('.partial-' + fingerprint + '-' + retained['stage_id'])
        self.execute([str(self.python), '-B', '-I', '-c',
            'import os,sys;os.makedirs(sys.argv[1],mode=0o755,exist_ok=True)', str(stage)],
            uid=0, gid=0, deadline_ns=deadline)
        remaining = (deadline - time.monotonic_ns()) / 1e9
        if remaining <= 0:
            raise OnboardingError('receiving_host_deadline_expired')
        host = self.value['host']
        if ':' in host:
            host = '[' + host + ']'
        destination = self.value['ssh_user'] + '@' + host + ':' + str(stage) + '/'
        try:
            result = subprocess.run(['rsync', '--archive', '--checksum', '--protect-args',
                '--chmod=D755,F644', '-e', shlex.join(self.ssh()), '--', str(source) + '/', destination],
                capture_output=True, timeout=remaining, env={'PATH': os.defpath, 'LANG': 'C.UTF-8'})
        except subprocess.TimeoutExpired:
            raise OnboardingError('receiving_host_deadline_expired') from None
        except OSError:
            raise OnboardingError('receiving_host_launch_failed') from None
        if result.returncode or not self.code_available(stage, fingerprint, deadline_ns=deadline):
            raise OnboardingError('native_receiving_code_unconfirmed')
        # Never replace even an empty foreign directory. Another operator may
        # publish the same qualified generation, in which case verify it below.
        publish = '''import ctypes,errno,os,sys
libc=ctypes.CDLL(None,use_errno=True)
result=libc.renameat2(-100,os.fsencode(sys.argv[1]),-100,os.fsencode(sys.argv[2]),1)
if result!=0 and ctypes.get_errno()!=errno.EEXIST:raise OSError(ctypes.get_errno(),'native code publication failed')
'''
        self.execute([str(self.python), '-B', '-I', '-c', publish, str(stage), str(code)],
            uid=0, gid=0, deadline_ns=deadline)
        if not self.code_available(code, fingerprint, deadline_ns=deadline):
            raise OnboardingError('native_receiving_code_unconfirmed')
        return code

    def execute(self, argv: list[str], *, uid: int = 1000, gid: int = 1000,
                env: dict | None = None, input_data: str | None = None,
                timeout_seconds: float = 60, deadline_ns: int | None = None,
                owner_clock: bool = False) -> str:
        if (not argv or any(not isinstance(item, str) or '\0' in item for item in argv)
                or (uid, gid) not in {(0, 0), (1000, 1000)}
                or not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 65
                or type(owner_clock) is not bool
                or env is not None and env != {'HOME': '/home/agent'}
                or input_data is not None and (not isinstance(input_data, str)
                    or len(input_data.encode()) > being_seed.MAX_SELECTION)):
            raise OnboardingError('invalid_native_receiving_request')
        remaining = timeout_seconds
        if deadline_ns is not None:
            remaining = min(remaining, (deadline_ns - time.monotonic_ns()) / 1e9)
        if remaining <= 0:
            raise OnboardingError('receiving_host_deadline_expired')
        request = dict(argv=argv, uid=uid, gid=gid, env=env or {'HOME': self.value['home']},
                       home=self.value['home'], machine_id_sha256=self.value['machine_id_sha256'],
                       remaining_seconds=remaining, expires_at_ms=time.time_ns() // 1_000_000 + int(remaining * 1000),
                       owner_clock=owner_clock)
        command = [str(self.python), '-B', '-I', '-c', REMOTE_LAUNCH, json.dumps(request)]
        target = self.value['ssh_user'] + '@' + self.value['host']
        try:
            result = subprocess.run([*self.ssh(), '--', target, shlex.join(command)],
                input=input_data, capture_output=True, text=True, timeout=remaining,
                env={'PATH': os.defpath, 'LANG': 'C.UTF-8'})
        except subprocess.TimeoutExpired:
            raise OnboardingError('receiving_host_deadline_expired') from None
        except OSError:
            raise OnboardingError('receiving_host_launch_failed') from None
        if result.returncode:
            from .onboarding_owner_control import PUBLIC_ERRORS
            for line in result.stderr.splitlines():
                if line in {'native_receiving_host_changed', 'receiving_host_deadline_expired',
                            'native_receiving_code_changed'}:
                    raise OnboardingError(line)
                try:
                    detail = json.loads(line)
                except ValueError:
                    continue
                if (isinstance(detail, dict) and set(detail) == {'error'}
                        and isinstance(detail.get('error'), str) and detail['error'] in PUBLIC_ERRORS):
                    raise OnboardingError(detail['error'])
            raise OnboardingError('native_receiving_operation_unconfirmed')
        if deadline_ns is not None and time.monotonic_ns() >= deadline_ns:
            raise OnboardingError('receiving_host_deadline_expired')
        return result.stdout
