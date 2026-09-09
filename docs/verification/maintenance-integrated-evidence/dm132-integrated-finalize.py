"""Freeze-only verifier. Run after every qualification writer has stopped."""
from pathlib import Path
import difflib
import hashlib
import json
import os
import shutil
import stat
import subprocess

root=Path('/tmp/dm132-cluster-maintenance')
base='4a2571a6b22c6e504c1f78ce6594f1a2ad445097'
evidence=root/'docs/verification/maintenance-integrated-evidence'
evidence.mkdir(exist_ok=False)
def sha(raw): return hashlib.sha256(raw).hexdigest()
def git(*args): return subprocess.check_output(['git','-C',str(root),*args])
assert git('rev-parse','HEAD').decode().strip()==base
index=Path(git('rev-parse','--git-path','index').decode().strip())
assert sha(index.read_bytes())=='ef0ede88ad7210499a87f5732b28b05267dffe43b014c461ab330beefb575fff'
assert not git('diff','--cached')
old_manifest=root/'docs/verification/maintenance-freeze-manifest.json'
assert sha(old_manifest.read_bytes())=='8a4c5da79a5c5fcbb0723e4a1ebf34106e3c3b5b4b4829e0c5525db79983b0b3'
old=json.loads(old_manifest.read_text())['files']
changed=[n for n,v in old.items() if sha((root/n).read_bytes())!=v['sha256']]
assert set(changed)=={'.github/workflows/tests.yml','tests/test_maintenance_composition.py'}
source=Path('/tmp/dm132-status-v1-correction-frozen')
for name,digest in {'clusterctl/matrix_status_transition.py':'7c9af19614209a07a862419b963ca429544e60df6152039a32f621ac00f2d754','tests/test_matrix_status_transition.py':'54e0b32d8d4d77182854546e7c3f228e4ba85bced402af38112bb055b9706960'}.items():
 assert sha((root/name).read_bytes())==digest==sha((source/name).read_bytes())
rows={}
for name in git('ls-tree','-r','--name-only',base).decode().splitlines():
 before=sha(git('show',base+':'+name)); after=sha((root/name).read_bytes())
 rows[name]={'before':before,'after':after,'unchanged':before==after}
runtime={n:v for n,v in rows.items() if n.endswith('.py') and n.split('/')[0] in {'clusterctl','clusterd','steward_tools'}}
assert len(runtime)==30 and sum(v['unchanged'] for v in runtime.values())==29
assert {n for n,v in rows.items() if not v['unchanged']}=={'clusterctl/matrix_host.py','requirements-weave.txt','.github/workflows/tests.yml','tests/test_matrix_host.py','tests/test_matrix_host_process.py','tests/test_clusterd.py','tests/test_matrix_parity.py'}
(evidence/'baseline-parity.json').write_text(json.dumps({'base':base,'files':rows,'baseline_count':len(rows),'runtime_count':len(runtime),'runtime_unchanged':sum(v['unchanged'] for v in runtime.values()),'delta_from_maintenance_review':changed},indent=2)+'\n')
# Narrow reconstructable integration delta; validate original reviewed bytes.
allow=(root/'tests/test_maintenance_composition.py').read_text()
old_allow=allow.replace('        "clusterctl/matrix_status_transition.py",\n','')
assert sha(old_allow.encode())==old['tests/test_maintenance_composition.py']['sha256']
ci=(root/'.github/workflows/tests.yml').read_text()
a=ci.index('      - name: Check out exact legacy Matrix fixture source\n'); b=ci.index('      - name: Lint the Matrix integration boundary\n',a)
old_ci=ci[:a]+ci[b:]
old_ci=old_ci.replace('          clusterctl/matrix_status_transition.py\n','').replace('          tests/test_matrix_status_transition.py\n','').replace('        env:\n          DM_LEGACY_SOURCE: ${{ github.workspace }}/.matrix-legacy/src\n','')
assert sha(old_ci.encode())==old['.github/workflows/tests.yml']['sha256']
delta=''
for name,before,after in [('tests/test_maintenance_composition.py',old_allow,allow),('.github/workflows/tests.yml',old_ci,ci),('docs/matrix-status-transition.md',(source/'docs/matrix-status-transition.md').read_text(),(root/'docs/matrix-status-transition.md').read_text())]:
 delta+=''.join(difflib.unified_diff(before.splitlines(True),after.splitlines(True),fromfile='approved/'+name,tofile='integrated/'+name))
(evidence/'integration-only.patch').write_text(delta)
# New evidence only; do not overwrite the previous freeze or logs.
for p in Path('/tmp').glob('dm132-integrated-*'):
 if p.is_file() and p != Path(__file__): shutil.copy2(p,evidence/p.name)
shutil.copy2(Path(__file__),evidence/Path(__file__).name)
for lab in ('dmi-host-03','dmi-reverse-03'):
 dest=evidence/lab; dest.mkdir()
 for p in Path('/tmp',lab).glob('*.json'): shutil.copy2(p,dest/p.name)
 # Bind synthetic artifacts by hash, never publish private key bytes.
 artifacts={str(p.relative_to(Path('/tmp',lab))):sha(p.read_bytes()) for p in Path('/tmp',lab).rglob('*') if p.is_file()}
 (dest/'synthetic-artifacts-sha256.json').write_text(json.dumps(artifacts,indent=2)+'\n')
paths=set(git('ls-files','--cached','--others','--exclude-standard','-z').decode().split('\0'))-{''}
files={n:{'sha256':sha((root/n).read_bytes()),'mode':oct(stat.S_IMODE((root/n).stat().st_mode))} for n in sorted(paths)}
manifest={'schema':'dm132.maintenance-integrated-freeze/v1','root':str(root),'base':base,'index_sha256':sha(index.read_bytes()),'matrix':'0a80cc5c38d3c7f5cad98d440153f0cf9706686b','legacy':'915c56c8899fd53d683bd7c7c81c3465b600bed9','exclusions':['Git metadata','Git ignored caches/bytecode','external synthetic fixture bytes (separately hashed)'],'files':files}
path=Path('/tmp/dm132-maintenance-integrated-manifest.json')
path.write_text(json.dumps(manifest,indent=2)+'\n')
for n,v in files.items(): assert sha((root/n).read_bytes())==v['sha256']
print(json.dumps({'manifest':str(path),'sha256':sha(path.read_bytes()),'members':len(files),'baseline_members':len(rows),'baseline_unchanged':sum(v['unchanged'] for v in rows.values()),'runtime_members':len(runtime),'runtime_unchanged':sum(v['unchanged'] for v in runtime.values()),'delta_from_review':changed},indent=2))
