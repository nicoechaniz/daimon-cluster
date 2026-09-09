"""Read-only post-run integrity and cleanup check."""
from pathlib import Path
import hashlib
import json
import os
import sys
sys.path.insert(0,'/tmp/dm132-cluster-maintenance')
from daimon_matrix import operator_runtime_upgrade as upgrade
from daimon_matrix.daemon import acquire_lock
h=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
a=Path('/tmp/dm132-integrated-provenance-before.json');b=Path('/tmp/dm132-integrated-provenance-after.json')
assert a.read_bytes()==b.read_bytes()
legacy=Path('/tmp/dm132-sidecar-legacy/src')
assert upgrade._inventory(upgrade._snapshot(legacy,private=False))==upgrade.LEGACY_SOURCE_SHA256
labs=[Path('/tmp',f'dmi-{mode}-{i:02}') for mode in ['host','reverse'] for i in [1,2,3]]
pids=[]
for lab in labs:
 assert lab.is_dir()
 assert not [p for p in lab.rglob('*') if p.is_socket()]
 context=lab/'context.json'
 if context.exists():
  root=Path(json.loads(context.read_text())['root'])
  fd=acquire_lock(root);os.close(fd)
for p in Path('/proc').iterdir():
 if not p.name.isdigit(): continue
 try: args=(p/'cmdline').read_bytes().split(b'\0')
 except (FileNotFoundError,PermissionError): continue
 if b'clusterctl.matrix_host' in args and any(str(lab).encode()+b'/s' in args for lab in labs): pids.append(p.name)
assert not pids,pids
for mode,tag in [('host','host'),('reverse','legacy')]:
 lab=Path('/tmp',f'dmi-{mode}-03')
 after=lab/('after-host.json' if mode=='host' else 'after-legacy-reads.json')
 refusal=lab/('after-host-refusal.json' if mode=='host' else 'after-legacy-refusal.json')
 assert after.read_bytes()==refusal.read_bytes()
print(json.dumps({'installed_before_after_identical':h(a),'legacy_inventory':upgrade.LEGACY_SOURCE_SHA256,'labs_checked':[str(p) for p in labs],'remaining_owned_host_pids':pids,'remaining_sockets':[],'post_read_refusals_complete_inventories_unchanged':True},indent=2))
