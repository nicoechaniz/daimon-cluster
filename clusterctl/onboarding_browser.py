"""Install selected pinned browser code into the receiving home, without starting it."""
from __future__ import annotations

import hashlib
import inspect
import json

from . import browser
from .onboarding import Observation, OnboardingError


def artifact(value: object, image: str) -> dict:
    if (not isinstance(value, dict) or set(value) != {'image', 'daemon_sha256', 'extension_sha256'}
            or value['image'] != image
            or any(not isinstance(v, str) or len(v) != 64 or any(c not in '0123456789abcdef' for c in v)
                   for v in value.values())):
        raise OnboardingError('qualified_browser_artifact_required')
    return value


class Browser:
    def __init__(self, backend):
        self.backend = backend
        self.artifact = artifact(backend.config.browser_artifact, backend.config.browser_image)
        self.code = inspect.getsource(browser)
        self.code_digest = hashlib.sha256(self.code.encode()).hexdigest()

    def _call(self, plan, install):
        if self.backend._environment(plan).state != 'complete':
            raise OnboardingError('browser_environment_not_ready')
        # Only maintained host code is executed. Seed/archive code is never input.
        program = '''import json,sys,types
from pathlib import Path
code=sys.argv[1]
module=types.ModuleType('qualified_browser')
exec(compile(code,'qualified_browser.py','exec'),module.__dict__)
home=Path('/home/agent')
source=Path('/opt/browser-code')
expected=module.prepare(source/'daemon',sys.argv[2],source/'extension',sys.argv[3],home,
 apply=sys.argv[4]=='install',launcher=code.encode())
if sys.argv[4]=='observe':
 root=home/'.kimi-webbridge'
 if not root.exists(): result={'ready':False,'absent':True}
 else:
  marker=json.loads(module._regular(root/'cluster-code.json'))
  expected['applied']=True
  assert marker==expected,'existing_browser_state_preserved'
  assert module._regular(root/'bin/cluster-browser.py')==code.encode(),'installed_browser_code_changed'
  assert module.prepare(root/'bin/kimi-webbridge',sys.argv[2],root/'extension',sys.argv[3],home,
   apply=True,launcher=code.encode())==expected
  result={'ready':True,'launcher_sha256':marker['launcher_sha256']}
else: result={'installed':True,'launcher_sha256':expected['launcher_sha256']}
print(json.dumps(result))
'''
        value = json.loads(self.backend._dispatch(plan, ['exec', self.backend.instance(plan),
            '--user', '1000', '--group', '1000', '--', 'python3', '-B', '-I', '-c', program,
            self.code, self.artifact['daemon_sha256'], self.artifact['extension_sha256'],
            'install' if install else 'observe']))
        expected = ({'installed': True, 'launcher_sha256': self.code_digest} if install else
            {'ready': True, 'launcher_sha256': self.code_digest})
        if value not in (expected, {'ready': False, 'absent': True}) or install and value != expected:
            raise OnboardingError('browser_code_verification_failed')
        return value

    def observe(self, plan):
        if not plan['browser']:
            raise OnboardingError('browser_not_selected')
        value = self._call(plan, False)
        return (Observation('complete', dict(verified=True, browser_code_verified=True)) if value.get('ready') else
            Observation('absent', safe_to_execute=True))

    def execute(self, plan):
        if not plan['browser']:
            raise OnboardingError('browser_not_selected')
        self._call(plan, True)

    @staticmethod
    def command():
        return ['python3', '/home/agent/.kimi-webbridge/bin/cluster-browser.py', 'run']
