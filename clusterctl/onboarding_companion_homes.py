"""Home preparation in the existing worker after committed native identity.

One plan, existing gateway writers and technical access only. This installs no
watcher, scheduler, browser session or model input. HTTPS routing remains owned
by the receiving host's selected route adapter.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import pwd
import subprocess

from . import being_seed
from .onboarding import CONVERSATION_JOB_SCHEMA, OnboardingError, Observation, digest, private_directory
from .onboarding_custody import document
from .onboarding_progress import Progress

SCHEMA = 'dm.home-companion-onboarding/v1'
UNIT = 'daimon-home-access.service'

# Runs under the actual gateway configuration owner's UID. Keys stay there.
GATEWAY = r'''
import json,sys,urllib.error,urllib.request
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from clusterctl.homes.host import register_companion
from clusterctl.homes.provision import regular
from clusterctl.homes.service import validate_config,private_text
value=json.load(sys.stdin);path=Path(value['config'])
if value['action']=='register':
 raw=regular(path)
 result=register_companion(path,value['request'],value['public'],
  human_name=value['human_name'],vpn_url=value['vpn_url'],previous_digest=__import__('hashlib').sha256(raw).hexdigest())
else:
 cfg=validate_config(json.loads(regular(path)));request=value['request'];home=cfg['homes'].get(request['home_ref'])
 if home is None:result={'state':'configuration-missing'}
 elif home['owner_being_ref']!=request['being_ref'] or home['public_url']!=request['origin']:
  raise ValueError('companion_home_binding_conflict')
 else:
  url='http://127.0.0.1:'+str(cfg['owner_port'])+'/owner/'+request['home_ref']+'/human-endpoint'
  class NoRedirect(urllib.request.HTTPRedirectHandler):
   def redirect_request(self,*a,**k):return None
  opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
  try:
   with opener.open(urllib.request.Request(url,data=b'{}',headers={
    'Authorization':'Bearer '+private_text(home['owner_token_file']),'Content-Type':'application/json'}),timeout=3) as response:
    raw=response.read(65537)
    if response.status!=200 or response.geturl()!=url or len(raw)>65536:raise ValueError('companion_home_probe_refused')
    observed=json.loads(raw)
   if observed['human']['ref']!=request['human_ref'] or observed['owner_being_ref']!=request['being_ref']:
    raise ValueError('companion_home_binding_conflict')
   result={'state':'ready','pair_matched':True}
  except urllib.error.HTTPError as error:
   result={'state':'not-loaded' if error.code==404 else 'unavailable'}
  except (OSError,ValueError,KeyError):result={'state':'unavailable'}
print(json.dumps(result))
'''


class CompanionHomes:
    def __init__(self, value, *, progress, store, backend, worker_uid, selection_path=None):
        self.value = value
        self.progress = Path(progress)
        self.store, self.backend, self.worker_uid = store, backend, worker_uid
        self.state = private_directory(Path(value['state']), create=True)
        self.selection_path = Path(selection_path) if selection_path is not None else None
        entries = list(self.state.iterdir())
        if len(entries)>64 or any(p.is_symlink() or not p.is_file() for p in entries):
            raise OnboardingError('companion_home_state_capacity')
        caps = {p:65536 if p.name.endswith('.technical-browser.json') else 4096 for p in entries}
        if any(p.stat().st_size>caps[p] for p in entries):
            raise OnboardingError('companion_home_state_capacity')
        for name in value['pairs']:
            for suffix,limit in (('.json',4096),('.access.json',4096),('.technical-browser.json',65536)):
                caps[self.state/(name+suffix)] = limit
        # Reserve every selected pair's terminal and temporary files up front.
        # Doubling also covers one atomic staging file per active writer.
        if len(caps)>64 or 2*sum(caps.values())>4*1024*1024:
            raise OnboardingError('companion_home_state_capacity')

    def _save(self, path, value):
        if len(json.dumps(value).encode())>4096:
            raise OnboardingError('companion_home_state_capacity')
        being_seed._write(path,value)

    def _selected(self):
        if os.geteuid()!=self.worker_uid:
            raise OnboardingError('trusted_home_progress_required')
        if self.selection_path is not None and document(self.selection_path)!=self.value:
            raise OnboardingError('companion_home_configuration_changed')

    def _gateway(self, action, request, *, public=None, pair=None):
        from .onboarding_release import regular
        gateway = self.value['gateway']
        path = Path(gateway['config'])
        uid = path.stat().st_uid
        regular(path, uid=uid, limit=1024*1024)
        # Reuse this one coherent worker release, not a second client overlay.
        argv = [gateway['python'], '-B', '-I', '-c', GATEWAY,
                str(Path(__file__).resolve().parents[1])]
        if uid != os.geteuid():
            if os.geteuid() != 0:
                raise OnboardingError('companion_gateway_owner_required')
            argv = ['/usr/sbin/runuser', '-u', pwd.getpwuid(uid).pw_name, '--', *argv]
        payload = dict(action=action, config=str(path), request=request)
        if action == 'register':
            payload.update(public=public, human_name=pair['human_name'], vpn_url=pair['vpn_url'])
        raw = json.dumps(payload).encode()
        if len(raw)>5*1024*1024:
            raise OnboardingError('companion_gateway_input_capacity')
        try:
            result = subprocess.run(argv, input=raw, capture_output=True, timeout=30)
        except subprocess.TimeoutExpired:
            raise OnboardingError('companion_gateway_operation_unconfirmed') from None
        if result.returncode or len(result.stdout)>65536 or len(result.stderr)>65536:
            raise OnboardingError('companion_gateway_operation_refused')
        value = json.loads(result.stdout)
        if not isinstance(value,dict):
            raise OnboardingError('companion_gateway_operation_refused')
        return value

    def _unit(self):
        result = subprocess.run(['systemctl','show',UNIT,'-p','MainPID','-p','InvocationID',
            '-p','ActiveState'],capture_output=True,text=True,timeout=5)
        if result.returncode or len(result.stdout)>8192:
            raise OnboardingError('companion_gateway_service_unobserved')
        value = dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
        pid = value.get('MainPID','0')
        if not pid.isdigit() or pid=='0':
            raise OnboardingError('companion_gateway_service_unobserved')
        with (Path('/proc')/pid/'cmdline').open('rb') as stream:
            raw = stream.read(65537)
        args = raw.split(b'\0')
        target = os.fsencode(self.value['gateway']['config'])
        if len(raw)>65536 or not any(a==b'--config' and b==target for a,b in zip(args,args[1:])):
            raise OnboardingError('companion_gateway_service_binding_changed')
        return value

    def _reload(self):
        try:
            result = subprocess.run(['systemctl','restart',UNIT],capture_output=True,timeout=30)
        except subprocess.TimeoutExpired:
            raise OnboardingError('companion_gateway_reload_unconfirmed') from None
        if result.returncode:
            raise OnboardingError('companion_gateway_reload_unconfirmed')

    def reconcile_committed(self, name):
        pair = self.value['pairs'].get(name)
        if pair is None:
            return {'state':'not-selected'}
        try:
            value = Progress(self.progress,worker_uid=self.worker_uid).read(name,owner=pair['owner'])
        except FileNotFoundError:
            return {'state':'waiting'}
        return self(value)

    def __call__(self, value):
        self._selected()
        value = Progress.validate(value)
        pair = self.value['pairs'].get(value['name'])
        if pair is None or value['schema']!=CONVERSATION_JOB_SCHEMA or 'identity' not in value['completed_steps']:
            return {'state':'not-selected'}
        committed = Progress(self.progress,worker_uid=self.worker_uid).read(value['name'],owner=pair['owner'])
        if (value['owner']!=pair['owner'] or value['plan_digest']!=pair['plan_digest']
                or committed['plan_digest']!=pair['plan_digest']
                or committed['schema']!=CONVERSATION_JOB_SCHEMA or 'identity' not in committed['completed_steps']):
            raise OnboardingError('companion_home_committed_identity_required')
        with being_seed._locked(private_directory(self.store.directory(value['name']))):
            backend = self.backend() if callable(self.backend) else self.backend
            record = self.store._load(value['name'])
            plan = record['plan']
            if record['plan_digest']!=pair['plan_digest'] or not backend.authorize(plan,pair['plan_digest']):
                raise OnboardingError('host_authorization_required')
            request = backend._conversation_request(plan)
            if request is None:
                raise OnboardingError('conversation_selection_required')
            pins = digest(dict(plan_digest=pair['plan_digest'],request=request,
                gateway=self.value['gateway'],pair=pair))
            path = self.state/(value['name']+'.json')
            observed = document(path) if path.exists() else dict(
                schema='cluster-companion-home-job/v1',pins=pins,phase='prepared')
            if (observed.get('schema')!='cluster-companion-home-job/v1' or observed.get('pins')!=pins
                    or observed.get('phase') not in {'prepared','configured','reload-intent','complete'}):
                raise OnboardingError('existing_companion_home_job_preserved')
            if observed['phase']=='complete':
                # This is a terminal provisioning receipt, not another health
                # monitor. Final access does its own fresh paired-owner read.
                return {'state':'complete'}
            if observed['phase']=='prepared':
                # Registration itself reconciles the same native pair/resource
                # keys after a lost child-process receipt. No replacement intent.
                public = backend._ceremony(plan).public_identity(plan)
                result = self._gateway('register',request,public=public,pair=pair)
                if (result.get('status')!='home-configured' or result.get('home_ref')!=request['home_ref']
                        or result.get('actor')!=request['being_ref'] or result.get('human_ref')!=request['human_ref']):
                    raise OnboardingError('companion_gateway_operation_refused')
                observed.update(phase='configured',registration=result)
                self._save(path,observed)
            probe = self._gateway('probe',request)
            if probe.get('state')=='ready' and probe.get('pair_matched') is True:
                observed.update(phase='complete',own_pair_observed=True)
                self._save(path,observed)
                return {'state':'complete'}
            if probe.get('state')=='not-loaded' and observed['phase']=='configured':
                self._selected()
                if not backend.authorize(plan,pair['plan_digest']):
                    raise OnboardingError('host_authorization_required')
                unit = self._unit()
                if unit.get('ActiveState')!='active' or unit.get('MainPID') in {None,'0'}:
                    raise OnboardingError('companion_gateway_service_unobserved')
                observed.update(phase='reload-intent',reload_predecessor=unit)
                self._save(path,observed)
                self._reload()
                # Read back next cadence, including after a lost reload reply.
            return {'state':'waiting','reason':'companion_gateway_receiving_unconfirmed'}

    def conversation_access(self, plan, request, apply):
        self._selected()
        from .onboarding_homes import verify_conversation_access
        from .homes.service import validate_config
        from .onboarding_release import regular
        path = self.state/(plan['name']+'.json')
        pair = self.value['pairs'].get(plan['name'])
        if not path.exists() or pair is None or pair['plan_digest']!=digest(plan):
            return Observation('waiting',reason='connection_data_required')
        value = document(path)
        expected = digest(dict(plan_digest=digest(plan),request=request,
            gateway=self.value['gateway'],pair=pair))
        if value.get('pins')!=expected or value.get('phase')!='complete':
            return Observation('waiting',reason='connection_data_required')
        if self._gateway('probe',request)!={'state':'ready','pair_matched':True}:
            return Observation('waiting',reason='connection_data_required')
        receipt = self.state/(plan['name']+'.access.json')
        journal = self.state/(plan['name']+'.technical-browser.json')
        def retire(checks):
            if journal.exists():
                saved = document(journal)
                if saved.get('phase')!='signed-out' or saved.get('checks')!=checks:
                    raise OnboardingError('conversation_browser_checkpoint_changed')
                journal.unlink()
        if receipt.exists():
            saved = document(receipt)
            if saved.get('pins')!=expected:
                raise OnboardingError('conversation_access_receipt_changed')
            if saved.get('verified') is True:
                retire(saved['checks'])
                return Observation('complete',{'conversation_verified':True,'shared_login_verified':True})
        if not apply:
            return Observation('absent',safe_to_execute=True)
        gateway_path = Path(self.value['gateway']['config'])
        uid = gateway_path.stat().st_uid
        config = validate_config(json.loads(regular(gateway_path,uid=uid)),credential_uid=uid)
        home = config['homes'][request['home_ref']]
        if home['owner_being_ref']!=request['being_ref'] or home['public_url']!=request['origin']:
            raise OnboardingError('companion_gateway_operation_refused')
        token = regular(Path(home['owner_token_file']),uid=uid,limit=4096).decode().strip()
        result = verify_conversation_access(request,owner_url='http://127.0.0.1:'+str(config['owner_port']),
            owner_token=token,journal=journal)
        if result!={'own_human':True,'conversation':True,'anonymous_denied':True,
                    'admin_denied':True,'signed_out':True}:
            raise OnboardingError('conversation_access_unconfirmed')
        self._save(receipt,dict(pins=expected,verified=True,checks=result))
        retire(result)
        return Observation('complete',{'conversation_verified':True,'shared_login_verified':True})


def configure(value, *, progress, store, backend, worker_uid, selection_path=None):
    if (set(value)!={'schema','state','gateway','pairs'} or value.get('schema')!=SCHEMA
            or not isinstance(value['state'],str) or not Path(value['state']).is_absolute()
            or '..' in Path(value['state']).parts
            or not isinstance(value['gateway'],dict) or set(value['gateway'])!={'config','python'}
            or any(not isinstance(p,str) or not Path(p).is_absolute() or '..' in Path(p).parts
                for p in value['gateway'].values())
            or not isinstance(value['pairs'],dict) or not 1<=len(value['pairs'])<=16):
        raise OnboardingError('companion_home_configuration_required')
    for name,pair in value['pairs'].items():
        if (not isinstance(name,str) or not being_seed.NAME.fullmatch(name)
                or not isinstance(pair,dict) or set(pair)!={'owner','plan_digest','human_name','vpn_url'}
                or not isinstance(pair['owner'],str) or not being_seed.NAME.fullmatch(pair['owner'])
                or not isinstance(pair['plan_digest'],str) or len(pair['plan_digest'])!=64
                or any(c not in '0123456789abcdef' for c in pair['plan_digest'])
                or not isinstance(pair['human_name'],str) or not 1<=len(pair['human_name'])<=512
                or not isinstance(pair['vpn_url'],str) or len(pair['vpn_url'])>512):
            raise OnboardingError('companion_home_configuration_required')
    return CompanionHomes(value,progress=progress,store=store,backend=backend,
        worker_uid=worker_uid,selection_path=selection_path)
