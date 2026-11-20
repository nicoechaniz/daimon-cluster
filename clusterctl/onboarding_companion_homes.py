"""Home preparation in the existing worker after committed native identity.

One plan, existing gateway writers and technical access only. This installs no
watcher, scheduler, browser session or model input. HTTPS routing remains owned
by the receiving host's selected route adapter.
"""
from __future__ import annotations

import json
import os
import hashlib
import re
from pathlib import Path
import pwd
import subprocess

from . import being_seed
from .onboarding import CONVERSATION_JOB_SCHEMA, OnboardingError, Observation, digest, private_directory
from .onboarding_custody import document
from .onboarding_progress import Progress

SCHEMA = 'dm.home-companion-onboarding/v1'
ROUTED_SCHEMA = 'dm.home-companion-onboarding/v2'
UNIT = 'daimon-home-access.service'

# Runs under the actual gateway configuration owner's UID. Keys stay there.
GATEWAY = r'''
import json,sys,urllib.error,urllib.request
from pathlib import Path
sys.path.insert(0,sys.argv[1])
value=json.load(sys.stdin)
if value.get('runtime_imports') is not None:
 from clusterctl.onboarding_companion_homes import gateway_imports
 sys.path.insert(1,str(gateway_imports(value['runtime_imports'])))
from clusterctl.homes.host import register_companion
from clusterctl.homes.provision import regular
from clusterctl.homes.service import validate_config,private_text
path=Path(value['config'])
if value['action']=='register':
 raw=regular(path)
 result=register_companion(path,value['request'],value['public'],
  human_name=value['human_name'],vpn_url=value['vpn_url'],previous_digest=__import__('hashlib').sha256(raw).hexdigest(),
  receivers_file=value['receivers_file'])
else:
 cfg=validate_config(json.loads(regular(path)));request=value['request'];home=cfg['homes'].get(request['home_ref'])
 if home is None:result={'state':'configuration-missing'}
 elif home['owner_being_ref']!=request['being_ref'] or home['public_url']!=request['origin']:
  raise ValueError('companion_home_binding_conflict')
 elif value['action']=='routing':
  result={'state':'configured','home_backend':'http://127.0.0.1:'+str(cfg['viewer_port'])}
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
   expected={'capability':'interaction','url':request['origin']+'/interaction/','state':'configured'}
   result=({'schema':observed['schema'],'home_ref':observed['home_ref'],
    'owner_being_ref':observed['owner_being_ref'],'human':{'ref':observed['human']['ref']}}
    if value['action']=='pairing' else
    ({'state':'ready','pair_matched':True} if expected in observed.get('applications',[])
     else {'state':'not-loaded'}))
  except urllib.error.HTTPError as error:
   result={'state':'not-loaded' if error.code==404 else 'unavailable'}
  except (OSError,ValueError,KeyError):result={'state':'unavailable'}
print(json.dumps(result))
'''


def import_selection(value):
    if (not isinstance(value, dict) or set(value) != {'path', 'sdk_digest', 'files_sha256'}
            or not isinstance(value['path'], str) or not Path(value['path']).is_absolute()
            or Path(value['path']).name != 'runtime-imports' or '..' in Path(value['path']).parts
            or any(not isinstance(value[k], str) or not re.fullmatch('[0-9a-f]{64}', value[k])
                   for k in ('sdk_digest', 'files_sha256'))):
        raise OnboardingError('companion_gateway_imports_required')
    return value


def gateway_imports(value):
    """Reuse the gateway's explicitly selected, protected native SDK imports.

    The ordinary gateway Python can have a legacy installed SDK while its
    actual service imports a newer qualified tree. Never silently fall back.
    """
    from .onboarding_release import regular
    value = import_selection(value)
    root = Path(value['path'])
    expected = dict(schema='cluster-onboarding-runtime-imports/v1',
        sdk_digest=value['sdk_digest'], files_sha256=value['files_sha256'])
    if document(root.parent/'runtime-imports.json') != expected:
        raise OnboardingError('companion_gateway_imports_changed')
    pending, files, total, entries = [root], {}, 0, 0
    while pending:
        parent = pending.pop()
        private_directory(parent)
        for path in parent.iterdir():
            entries += 1
            if entries > 20000 or path.is_symlink():
                raise OnboardingError('companion_gateway_imports_changed')
            if path.is_dir():
                pending.append(path)
            else:
                raw = regular(path, uid=os.geteuid())
                total += len(raw)
                if total > 256*1024**2:
                    raise OnboardingError('companion_gateway_imports_changed')
                files[path.relative_to(root).as_posix()] = hashlib.sha256(raw).hexdigest()
    if not files or digest(files) != value['files_sha256']:
        raise OnboardingError('companion_gateway_imports_changed')
    return root


class CompanionHomes:
    def __init__(self, value, *, progress, store, backend, worker_uid, selection_path=None):
        self.value = value
        self.progress = Path(progress)
        self.store, self.backend, self.worker_uid = store, backend, worker_uid
        self.state = private_directory(Path(value['state']), create=True)
        self.selection_path = Path(selection_path) if selection_path is not None else None
        entries = list(self.state.iterdir())
        file_limit = 64 + (len(value['pairs']) if 'native_client' in value else 0)
        if len(entries)>file_limit or any(p.is_symlink() or not p.is_file() for p in entries):
            raise OnboardingError('companion_home_state_capacity')
        caps = {p:65536 if p.name.endswith('.technical-browser.json') else 4096 for p in entries}
        if any(p.stat().st_size>caps[p] for p in entries):
            raise OnboardingError('companion_home_state_capacity')
        for name in value['pairs']:
            for suffix,limit in (('.json',4096),('.access.json',4096),('.technical-browser.json',65536)):
                caps[self.state/(name+suffix)] = limit
            if 'native_client' in value:
                caps[self.state/(name+'.client.json')] = 4096
        # Reserve every selected pair's terminal and temporary files up front.
        # Doubling also covers one atomic staging file per active writer.
        if len(caps)>file_limit or 2*sum(caps.values())>4*1024*1024:
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
        if 'runtime_imports' in gateway:
            payload['runtime_imports'] = gateway['runtime_imports']
        if action == 'register':
            receiving = self._unit(receivers=True)
            selected_receivers = Path(receiving['receivers_file'])
            regular(selected_receivers, uid=uid, limit=4*1024*1024)
            payload.update(public=public, human_name=pair['human_name'], vpn_url=pair['vpn_url'])
            payload['receivers_file'] = str(selected_receivers)
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

    def _unit(self, *, receivers=False):
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
        boot = next(line.split()[1] for line in Path('/proc/stat').read_text().splitlines()
                    if line.startswith('btime '))
        process = (Path('/proc')/pid/'stat').read_text().rsplit(')',1)[1].split()
        value['process_start_epoch_ns'] = (int(boot)*1_000_000_000
            + int(process[19])*1_000_000_000//os.sysconf('SC_CLK_TCK'))
        value['config_mtime_ns'] = Path(self.value['gateway']['config']).stat().st_mtime_ns
        if receivers:
            matches = [value for flag,value in zip(args,args[1:]) if flag==b'--miniapp-receivers']
            if len(matches)!=1 or not Path(os.fsdecode(matches[0])).is_absolute():
                raise OnboardingError('companion_gateway_receivers_required')
            value['receivers_file'] = os.fsdecode(matches[0])
        return value

    def _reload(self):
        try:
            result = subprocess.run(['systemctl','restart',UNIT],capture_output=True,timeout=30)
        except subprocess.TimeoutExpired:
            raise OnboardingError('companion_gateway_reload_unconfirmed') from None
        if result.returncode:
            raise OnboardingError('companion_gateway_reload_unconfirmed')

    def _pins(self, plan_digest, request, pair):
        value = dict(plan_digest=plan_digest, request=request, gateway=self.value['gateway'], pair=pair)
        if self.value['schema'] == ROUTED_SCHEMA:
            # Maintenance transport describes current upstreams, not the
            # companion's immutable Home/route selection. It may be refreshed
            # without reenrolling a completed registration.
            value['routes'] = {k:v for k,v in self.value['routes'].items() if k != 'maintenance'}
        return digest(value)

    def _routes(self, backend, plan, request):
        from .onboarding_conversation_routes import Routes
        selected = backend.config.conversation_proxy_by_name
        if selected is None or plan['name'] not in selected:
            raise OnboardingError('conversation_proxy_configuration_required')
        gateway = self._gateway('routing', request)
        if gateway.get('state') != 'configured' or not isinstance(gateway.get('home_backend'), str):
            raise OnboardingError('conversation_route_home_backend_required')
        def authorized():
            self._selected()
            return backend.authorize(plan, digest(plan))
        return Routes(self.value['routes']).reconcile(request, selected[plan['name']],
            gateway['home_backend'], apply=True, authorize=authorized)

    def _native_client(self, backend, plan, request, observed):
        selected = self.value.get('native_client')
        if selected is None:
            return  # Existing completed/legacy Home contracts are unchanged.
        from .onboarding_homes import IncusProvider
        from .homes.service import validate_config
        from .onboarding_release import regular
        gateway = self.value['gateway']
        path = Path(gateway['config'])
        uid = path.stat().st_uid
        config = validate_config(json.loads(regular(path, uid=uid)), credential_uid=uid)
        home = config['homes'][request['home_ref']]
        if home['owner_being_ref'] != request['being_ref'] or home['public_url'] != request['origin']:
            raise OnboardingError('companion_home_binding_conflict')
        binding = dict(schema='dm.home-human-client/v1', name=request['label'],
            public_url=request['origin'], being_ref=request['being_ref'],
            access=dict(owner_url=request['origin'], home_ref=request['home_ref'],
                        owner_token_file='/home/agent/.config/daimon-home/owner.key'))
        declaration = dict(schema='dm.home.receiving/v1', binding=binding,
                           skills_commit=selected['skills_commit'], previous={})
        client_file = self.state/(plan['name']+'.client.json')
        if client_file.exists():
            if document(client_file) != declaration:
                raise OnboardingError('existing_native_client_selection_preserved')
        else:
            self._save(client_file, declaration)
        placement = dict(name=plan['name'], owner=plan['owner'], plan_digest=digest(plan),
            **selected, declaration_file=str(client_file),
            declaration_sha256=hashlib.sha256(client_file.read_bytes()).hexdigest(),
            delivery=dict(home=home, home_ref=request['home_ref'],
                owner_being_ref=request['being_ref'], gateway_config=str(path),
                gateway_uid=uid, gateway_gid=path.stat().st_gid,
                gateway_python=gateway['python'], gateway_code=str(Path(__file__).resolve().parents[1]),
                previous_unit_sha256=None))
        selection = digest(placement)
        retained = observed.get('native_client')
        if retained is not None:
            if retained.get('selection_digest') != selection:
                raise OnboardingError('existing_native_client_selection_preserved')
            return
        # Caller already holds this exact job lock and fresh authorization.
        result = IncusProvider(self.store, backend)._reconcile(placement)
        projection = result.get('human_endpoint', {})
        if (result.get('state') != 'complete'
                or projection.get('human', {}).get('ref') != request['human_ref']
                or not any(a.get('capability') == 'interaction'
                           and a.get('url') == request['origin']+'/interaction/'
                           for a in projection.get('applications', []))):
            raise OnboardingError('native_client_receiving_unconfirmed')
        observed['native_client'] = dict(selection_digest=selection,
            human_ref=request['human_ref'], home_ref=request['home_ref'],
            client_verified=True, model_uptake=False)

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
            pins = self._pins(pair['plan_digest'], request, pair)
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
                if self.value['schema'] == ROUTED_SCHEMA:
                    try:
                        route = self._routes(backend, plan, request)
                    except OnboardingError as error:
                        if str(error) not in {'conversation_route_voice_active',
                            'conversation_route_maintenance_unavailable','conversation_route_maintenance_lost'}:
                            raise
                        return {'state':'waiting', 'reason':str(error)}
                    if route.get('state') != 'complete' or route.get('route_loaded') is not True:
                        return {'state':'waiting', 'reason':route.get('reason', 'conversation_route_runtime_unconfirmed')}
                self._native_client(backend, plan, request, observed)
                observed.update(phase='complete',own_pair_observed=True)
                self._save(path,observed)
                return {'state':'complete'}
            # Unknown newly registered owners receive 403, not 404. Reload
            # once only when this exact registered config demonstrably postdates
            # the running process; an ordinary live auth failure is not absence.
            pending_unit = self._unit() if (probe.get('state') == 'unavailable'
                and observed['phase'] == 'configured') else None
            pending_config = (pending_unit is not None
                and pending_unit.get('process_start_epoch_ns', 2**63)
                    < pending_unit.get('config_mtime_ns', 0)
                and hashlib.sha256(Path(self.value['gateway']['config']).read_bytes()).hexdigest()
                    == observed['registration'].get('config_digest'))
            if (probe.get('state')=='not-loaded' or pending_config) and observed['phase']=='configured':
                self._selected()
                if not backend.authorize(plan,pair['plan_digest']):
                    raise OnboardingError('host_authorization_required')
                unit = pending_unit if pending_unit is not None else self._unit()
                if unit.get('ActiveState')!='active' or unit.get('MainPID') in {None,'0'}:
                    raise OnboardingError('companion_gateway_service_unobserved')
                observed.update(phase='reload-intent',reload_predecessor=unit)
                self._save(path,observed)
                self._reload()
                # Read back next cadence, including after a lost reload reply.
            return {'state':'waiting','reason':'companion_gateway_receiving_unconfirmed'}

    def conversation_pairing(self, plan, request):
        self._selected()
        pair = self.value['pairs'].get(plan['name'])
        if (pair is None or pair['owner'] != plan['owner']
                or pair['plan_digest'] != digest(plan)):
            raise OnboardingError('companion_gateway_operation_refused')
        return self._gateway('pairing', request)

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
        expected = self._pins(digest(plan), request, pair)
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
                return Observation('complete',{'verified':True,'conversation_verified':True,'shared_login_verified':True})
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
        return Observation('complete',{'verified':True,'conversation_verified':True,'shared_login_verified':True})


def configure(value, *, progress, store, backend, worker_uid, selection_path=None):
    routed = value.get('schema') == ROUTED_SCHEMA
    if (set(value)-{'native_client'}!={'schema','state','gateway','pairs'} | ({'routes'} if routed else set())
            or value.get('schema') not in {SCHEMA, ROUTED_SCHEMA}
            or not isinstance(value['state'],str) or not Path(value['state']).is_absolute()
            or '..' in Path(value['state']).parts
            or not isinstance(value['gateway'],dict) or set(value['gateway'])-{'runtime_imports'}!={'config','python'}
            or any(not isinstance(p,str) or not Path(p).is_absolute() or '..' in Path(p).parts
                for p in (value['gateway'].get('config'),value['gateway'].get('python')))
            or not isinstance(value['pairs'],dict) or not 1<=len(value['pairs'])<=16):
        raise OnboardingError('companion_home_configuration_required')
    if 'runtime_imports' in value['gateway']:
        import_selection(value['gateway']['runtime_imports'])
    if 'native_client' in value:
        client = value['native_client']
        if (not isinstance(client, dict)
                or set(client) != {'provider_file', 'provider_sha256', 'repository', 'skills_commit'}
                or any(not isinstance(v, str) for v in client.values())
                or any(not isinstance(client[k], str) or not Path(client[k]).is_absolute()
                       or '..' in Path(client[k]).parts for k in ('provider_file', 'repository'))
                or re.fullmatch('[a-f0-9]{64}', client.get('provider_sha256', '')) is None
                or re.fullmatch('[a-f0-9]{40}', client.get('skills_commit', '')) is None):
            raise OnboardingError('native_client_source_required')
    if routed:
        from .onboarding_conversation_routes import configuration as route_configuration
        route_configuration(value['routes'])
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
