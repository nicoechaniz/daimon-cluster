"""Synthetic only. All candidate imports are installed; legacy executes pinned archive."""
import os,sys,json,ast,subprocess,pathlib,hashlib,shutil,time,select
os.umask(0o077)
P=pathlib.Path(os.environ.get('DM_PAIR_LAB','/tmp/dm132-real-pair-lab'));P.mkdir(mode=0o700)
C=pathlib.Path('/tmp/dm132-cluster-maintenance');sys.path.insert(0,str(C));sys.path.insert(0,str(C/'tests'))
import test_matrix_status_transition as native
from daimon_matrix import operator_runtime_upgrade as upgrade
from daimon_matrix.canonical import canonical_bytes
from clusterctl.matrix_host import matrix_root,matrix_client_root,matrix_client_factory
from clusterctl.embodiments import Registry
from clusterctl.matrix_fencing.fences import Ed25519Signer,ResourceFenceStore
from clusterctl.matrix_fencing.production_fences import create_holder_enrollment,create_holder_authorization,ed25519_fingerprint
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
legacy=P/'legacy';legacy.mkdir()
raw=subprocess.check_output(['git','-C','/tmp/dm-codex-messaging-discovery','archive',upgrade.LEGACY_REVISION,'src'])
subprocess.run(['tar','-x','-C',str(legacy)],input=raw,check=True)
legacy=legacy/'src';assert upgrade._inventory(upgrade._snapshot(legacy,private=False))==upgrade.LEGACY_SOURCE_SHA256
# Execute the reviewed native bootstrap fixture program, not the obsolete V2 constructor.
tree=ast.parse((C/'tests/test_matrix_status_transition.py').read_text())
fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='journey')
program=next(n.value.value for n in fn.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='script' for t in n.targets))
seed=P/'seed';seed.mkdir()
subprocess.run([sys.executable,'-I','-B','-c',program,str(legacy),str(seed)],check=True)
bundle=json.loads((seed/'ceremony/runtimes/alpha/runtime.json').read_bytes()); origin=bundle['local_origin'];state=P/'s';state.mkdir();root=matrix_root(state,origin['embodiment_id']);root.parent.mkdir();shutil.copytree(seed/'ceremony/runtimes/alpha',root)
# Legacy V7 requires a nonempty target list. Its loader does not send traffic.
# Zero-peer candidate configuration is applied only after migration below.
password=native.PASSWORD;now=lambda:time.time_ns()//1000000
upgrade._validate(root,legacy,password)
(root/'.daimon-matrixd.lock').touch(mode=0o600)
from clusterctl import matrix_status_transition as transition
native_pair=seed/'ceremony/host-clients/alpha'
native.legacy_client_load(legacy,native_pair)
assert json.loads((native_pair/'client.json').read_bytes())['schema']=='dm.local.client-config/v1'
side=matrix_client_root(state,origin['embodiment_id']);side.parent.mkdir()
upgrade._copy(upgrade._snapshot(native_pair),side)
old_side=upgrade.inventory_digest(side)
print('NATIVE_V1_ACTUAL_LOADER_PASS',old_side,flush=True)

transaction=root.parent/'upgrade'
ready=upgrade.stage(source=root,transaction=transaction,legacy_source=legacy,legacy_sha256=upgrade.LEGACY_SOURCE_SHA256,expected_source_sha256=upgrade.inventory_digest(root),expected_counter=bundle['keystore']['counter'],expected_control_head=bundle['control_head'],expected_being_ref=bundle['manifest']['being_ref'],expected_origin=origin,password=password,expires_at_ms=now()+3600000,externally_quiesced=True)
receipt=upgrade.publish(source=root,transaction=transaction,expected_receipt_sha256=hashlib.sha256((transaction/'ready.json').read_bytes()).hexdigest(),password=password,externally_quiesced=True)
current=json.loads((root/'runtime.json').read_bytes())
for key in ['manifest','local_origin','control_head']:assert current[key]==bundle[key]
assert (root/bundle['ledger']).read_bytes()==(transaction/'checkpoint'/bundle['ledger']).read_bytes()
# Preserve legacy target inventory for this base-host control; ordinary relationships are zero-peer.
assert (root/'runtime.json').read_bytes()==canonical_bytes(current)
print('MIGRATION_PASS',json.dumps({'before':bundle['keystore']['counter'],'after':current['keystore']['counter'],'capabilities':len(current['capabilities']),'origin':origin}),flush=True)
registry=Registry(state);registry.register(body_ref=origin['body_ref'],embodiment_id=origin['embodiment_id']);registry.start(origin['embodiment_id'],incarnation_id=origin['incarnation_id'],started_at_ms=now()-1000)
def signer(label):
 key=Ed25519PrivateKey.generate();p=P/(label+'.pem');p.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));p.chmod(0o600);return Ed25519Signer(p,'synthetic-'+label)
owner=signer('registrar');holder=signer('holder')
fences=ResourceFenceStore.production(state,signer=owner,key_id=owner.key_id,holder_registrars={owner.key_id:owner.public_key})
fences.admit_holder(create_holder_enrollment(owner,holder_key_id=holder.key_id,holder_pubkey=holder.public_key,being_ref=bundle['manifest']['being_ref'],body_ref=origin['body_ref'],embodiment_id=origin['embodiment_id'],incarnation_id=origin['incarnation_id'],activation_id='dm:activation:synthetic-pair',credential_id='dm:credential:synthetic-pair',manifest_hash='sha256:'+hashlib.sha256(canonical_bytes(bundle['manifest'])).hexdigest(),issued_ms=now(),nonce='synthetic-pair-enrollment'))
resource='volume:synthetic-pair';pos=fences.position(resource)
auth=create_holder_authorization(holder,operation='acquire',body_ref=origin['body_ref'],embodiment_id=origin['embodiment_id'],incarnation_id=origin['incarnation_id'],resource_ref=resource,expected_epoch=pos['epoch'],expected_proof=pos['proof'],expected_current=pos['current'],fence_ttl_s=3600,issued_ms=now(),ttl_s=60,nonce='synthetic-pair-acquire')
fences.acquire(resource,holder.public_key,ed25519_fingerprint(holder.public_key),holder_embodiment_id=origin['embodiment_id'],body_ref=origin['body_ref'],holder_incarnation_id=origin['incarnation_id'],holder_key_id=holder.key_id,expected_epoch=pos['epoch'],expected_proof=pos['proof'],authorization=auth)
assert ResourceFenceStore.production_verifier(state).verify_current(resource) is not None
# Private modern authority does not invent old fleet resource fences.
assert ResourceFenceStore.__module__=='clusterctl.matrix_fencing.fences'
print('AUTHENTICATED_FENCE_PASS',flush=True)
side_tx=side.parent/'transition'
req=dict(runtime=root,upgrade_transaction=transaction,transaction=side_tx,target=side,expected_target_sha256=old_side,expected_upgrade_sha256=hashlib.sha256((transaction/'published.json').read_bytes()).hexdigest(),expected_origin=origin,expected_being_ref=bundle['manifest']['being_ref'],externally_quiesced=True)
staged=transition.stage(**req)
args=dict(transaction=side_tx,expected_receipt_sha256=hashlib.sha256((side_tx/'ready.json').read_bytes()).hexdigest(),externally_quiesced=True)
mode=os.environ.get('DM_STATUS_MODE','host')
if mode in ('exchange','receipt'):
 original=upgrade._exchange if mode=='exchange' else upgrade._write
 def fault(*a,**kw):
  if mode=='exchange':
   original(*a,**kw);raise OSError('synthetic exchange lost return')
  if 'published' in a[0].name:
   original(a[0],a[1][:10]);raise OSError('synthetic receipt interruption')
  return original(*a,**kw)
 setattr(upgrade,'_exchange' if mode=='exchange' else '_write',fault)
 try:
  transition.publish(**args);raise AssertionError('fault did not fire')
 except OSError as e:print('EXPECTED_INTERRUPTION',str(e),flush=True)
 finally:setattr(upgrade,'_exchange' if mode=='exchange' else '_write',original)
pub=transition.publish(**args);assert pub['state']=='stopped-published'
assert transition.publish(**args)==pub
assert upgrade.inventory_digest(side)==staged['new_sha256']
assert upgrade.inventory_digest(side_tx/'checkpoint')==old_side
print('SIDECAR_PUBLISH_PASS',json.dumps(pub),flush=True)
def hashes(path):return {str(f.relative_to(path)):hashlib.sha256(f.read_bytes()).hexdigest() for f in path.rglob('*') if f.is_file()}

def record(label, roots):
 (P/(label+'.json')).write_text(json.dumps({str(x):hashes(x) for x in roots},indent=2,sort_keys=True))

def reverse():
 ra=dict(source=root,transaction=transaction,expected_receipt_sha256=hashlib.sha256((transaction/'ready.json').read_bytes()).hexdigest(),password=password,externally_quiesced=True)
 before_counter=json.loads((root/'runtime.json').read_bytes())['keystore']['counter']
 upgrade.stage_rollback(**ra)
 ra['expected_receipt_sha256']=hashlib.sha256((transaction/'rollback-ready.json').read_bytes()).hexdigest()
 upgrade.publish_rollback(**ra)
 assert json.loads((root/'runtime.json').read_bytes())['keystore']['counter']==before_counter+1
 rev=dict(**args,expected_rollback_sha256=hashlib.sha256((transaction/'rolled-back.json').read_bytes()).hexdigest(),password=password)
 answer=transition.rollback(**rev);assert answer['state']=='stopped-rolled-back'
 assert transition.rollback(**rev)==answer
 assert upgrade.inventory_digest(side)==old_side
 print('MONOTONIC_REVERSE_PASS',json.dumps(answer),flush=True)
if mode=='reverse':
 reverse()
 native.legacy_client_load(legacy,side)
 before=upgrade.inventory_digest(root)
 record('before-legacy-reads',[root,side,transaction,side_tx])
 native.legacy_status_calls(legacy,root,side)
 print('RESTORED_V1_FIVE_ACTUAL_LEGACY_CALLS_PASS',flush=True)
 assert upgrade.inventory_digest(root)!=before
 roots=[root,side,transaction,side_tx]
 inventories=[upgrade.inventory_digest(x) for x in roots]
 record('after-legacy-reads',roots)
 rev=dict(**args,expected_rollback_sha256=hashlib.sha256((transaction/'rolled-back.json').read_bytes()).hexdigest(),password=password)
 try:
  transition.rollback(**rev);raise AssertionError('post-read reverse replay accepted')
 except (upgrade.UpgradeError,transition.TransitionError) as e:
  print('POST_LEGACY_READ_REVERSE_REFUSED',str(e),flush=True)
 assert inventories==[upgrade.inventory_digest(x) for x in roots]
 record('after-legacy-refusal',roots)
 print('REVERSE_CLEANUP_PASS',flush=True)
 sys.exit(0)
pre=upgrade.inventory_digest(root)
pre_files=hashes(root)
record('before-host', [root,side,transaction,side_tx])

(P/'context.json').write_text(json.dumps({'state':str(state),'root':str(root),'origin':origin}))
r,w=os.pipe();rr,rw=os.pipe();os.write(w,password);os.close(w)
command=[sys.executable,'-m','clusterctl.matrix_host','--state-dir',str(state),'--embodiment-id',origin['embodiment_id'],'--password-fd',str(r),'--ready-fd',str(rw)]
p=subprocess.Popen(command,cwd=C,env={k:v for k,v in os.environ.items() if k!='PYTHONPATH'},pass_fds=(r,rw),stdout=subprocess.PIPE,stderr=subprocess.PIPE);os.close(r);os.close(rw)
try:
 assert select.select([rr],[],[],30)[0], 'readiness timeout'
 ready=os.read(rr,64);print('READY',repr(ready),flush=True)
 if ready!=b'READY\n':
  out,err=p.communicate(timeout=10);print('HOST_FAILURE',p.returncode,repr(err),flush=True);raise AssertionError('host refused')
 client=matrix_client_factory(state)(origin['embodiment_id'])
 for name in ['runtime_status','scope_me','scope_we','scope_diff','scope_sync_plan']:
  result=getattr(client,name)({'request_id':__import__('uuid').uuid4().__str__(),'limit':100}) if name=='scope_sync_plan' else getattr(client,name)()
  print('STATUS',name,json.dumps(result[1]),flush=True);assert result[1]['ok']
 # Actual loopback clusterd status; no substrate adapter is invoked.
 import threading,http.client
 from clusterd.auth import create_token
 from clusterd.handlers import Deps
 from clusterd.server import make_server
 _,token=create_token(str(state),actor='synthetic-status-composed',scopes=['read'],owner='*',ttl_days=1)
 srv=make_server(Deps(config_path=str(P/'unused.yaml'),state_dir=str(state),matrix_client_factory=matrix_client_factory(state)),'127.0.0.1',0)
 thread=threading.Thread(target=srv.serve_forever);thread.start()
 try:
  conn=http.client.HTTPConnection('127.0.0.1',srv.server_address[1]);conn.request('GET','/v1/weave/status');response=conn.getresponse();response.read();assert response.status==401
  conn.request('GET','/v1/weave/status',headers={'Authorization':'Bearer '+token});response=conn.getresponse();data=json.loads(response.read());conn.close();assert response.status==200
  assert data['embodiments'][0]['runtime']['integrity']=='ok'
  assert data['embodiments'][0]['me']['body']['state']=='running'
  assert data['embodiments'][0]['me']['body']['resource_fences']==[{'resource_ref':resource,'epoch':0}]
  conn=http.client.HTTPConnection('127.0.0.1',srv.server_address[1]);conn.request('POST','/v1/instances/missing/start',headers={'Authorization':'Bearer '+token});response=conn.getresponse();response.read();assert response.status==403;conn.close()
  print('CLUSTERD_HTTP_PASS',json.dumps(data),flush=True)
 finally:
  srv.shutdown();thread.join(10);srv.server_close();assert not thread.is_alive()
finally:
 os.close(rr)
 if p.poll() is None:p.terminate()
 out,err=p.communicate(timeout=10);print('SHUTDOWN',p.returncode,repr(err),flush=True)

assert p.returncode==0
assert not (root/'matrix.sock').exists()
from daimon_matrix.daemon import acquire_lock
fd=acquire_lock(root);os.close(fd)
post=upgrade.inventory_digest(root);post_files=hashes(root)
record('after-host',[root,side,transaction,side_tx])
changed={k:{'before':pre_files.get(k),'after':post_files.get(k)} for k in pre_files.keys()|post_files.keys() if pre_files.get(k)!=post_files.get(k)}
(P/'inventory-observation.json').write_text(json.dumps(dict(before=pre,after=post,changed=changed),indent=2))
print('INVENTORY_AFTER_HOST',json.dumps(dict(before=pre,after=post,changed=changed)),flush=True)
assert pre!=post, 'expected real host/read ledger effect'
roots=[root,side,transaction,side_tx]
inventories=[upgrade.inventory_digest(x) for x in roots]
if pre!=post:
 try:reverse();raise AssertionError('changed-state reverse accepted')
 except upgrade.UpgradeError as e:print('CHANGED_STATE_REVERSE_REFUSED',str(e),flush=True)
 assert upgrade.inventory_digest(root)==post
 assert inventories==[upgrade.inventory_digest(x) for x in roots]
else:reverse()
record('after-host-refusal',roots)
print('CLEANUP_PASS',p.pid,flush=True)
