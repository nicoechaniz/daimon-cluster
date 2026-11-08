"""The APT seam refuses risky/drifted transactions before any package writer."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
from unittest.mock import patch

from tools import children_package_guard as guard


class PackageGuardTests(unittest.TestCase):
    def setUp(self):
        # Outside /tmp: production rejects any world-writable archive ancestor.
        self.temp = tempfile.TemporaryDirectory(dir=Path.cwd())
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.proc = self.root / 'proc'
        self.proc.mkdir()
        self.manifest = {'schema': 'children-reviewed-apt-transaction/v1',
                         'source': 'verified-local-debian-security',
                         'maintainer_reviewed': True, 'packages': {}}
        for name in guard.PACKAGES:
            p = self.root / (name + '.deb')
            p.write_bytes(('synthetic technical fixture: ' + name).encode())
            self.manifest['packages'][name] = {
                'old_version': '1', 'version': '2', 'archive': str(p),
                'sha256': hashlib.sha256(p.read_bytes()).hexdigest(),
                'bytes': p.stat().st_size}
        self.actions = [f'{name} 1 < 2 {item["archive"]}'
                        for name, item in self.manifest['packages'].items()]

    def protocol(self, actions=None, config=''):
        return ('VERSION 2\n' + config + '\n' + '\n'.join(
            self.actions if actions is None else actions) + '\n').encode()

    def check(self, raw=None, **kwargs):
        return guard.guard(self.protocol() if raw is None else raw, self.manifest,
                           owner_uid=os.getuid(), proc_root=self.proc, **kwargs)

    def test_qualifier_help_requires_no_root_or_fixture_mutation(self):
        result = subprocess.run([sys.executable, 'tools/qualify_children_package_guard.py',
                                 '--help'], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--state', result.stdout)

    def test_reviewed_exact_archives_and_configure_actions(self):
        actions = self.actions + [f'{n} 1 < 2 **CONFIGURE**' for n in guard.PACKAGES]
        value = self.check(self.protocol(actions))
        self.assertEqual(value['decision'], 'admitted')
        self.assertEqual(value['archives_verified'], 2)
        self.assertFalse(value['package_write_performed'])

    def test_important_package_or_removal_never_reaches_archive_stage(self):
        for action in ('systemd 1 < 2 /cache/systemd.deb',
                       'chromium 1 > - **REMOVE**'):
            with self.subTest(action=action):
                verify = unittest.mock.Mock()
                with self.assertRaises(guard.Deferred):
                    self.check(self.protocol([*self.actions, action]), verify=verify)
                verify.assert_not_called()

    def test_extra_new_downgraded_or_changed_version_is_deferred(self):
        name, item = next(iter(self.manifest['packages'].items()))
        for action in (f'{name} - < 2 {item["archive"]}',
                       f'{name} 1 > 2 {item["archive"]}',
                       f'{name} 1 < 3 {item["archive"]}',
                       f'{name} 1 < 2 /different/archive.deb'):
            with self.subTest(action=action), self.assertRaises(guard.Deferred):
                self.check(self.protocol([action, self.actions[1]]))
        with self.assertRaises(guard.Deferred):
            self.check(self.protocol([*self.actions, self.actions[0]]))

    def test_unsafe_source_options_and_apt_hooks(self):
        for config in ('APT::Get::AllowUnauthenticated=true\n',
                       'Acquire::AllowInsecureRepositories=1\n',
                       'DPkg::Post-Invoke::=systemctl restart ssh\n',
                       'DPkg::Pre-Install-Pkgs::=unreviewed-command\n',
                       'DPkg::Options::=--force-all\n'):
            with self.subTest(config=config), self.assertRaises(guard.Deferred):
                self.check(self.protocol(config=config))
        self.check(self.protocol(config='DPkg::Options::=--force-confold\n'
                                 'DPkg::Pre-Install-Pkgs::=selected-hook\n'),
                   expected_hook='selected-hook')

    def test_corrupt_or_replaced_symlink_archive_is_deferred(self):
        item = next(iter(self.manifest['packages'].values()))
        path = Path(item['archive'])
        raw = path.read_bytes()
        path.write_bytes(b'X' * len(raw))
        with self.assertRaisesRegex(guard.Deferred, 'archive_changed'):
            self.check()
        path.unlink()
        target = self.root / 'preserved'
        target.write_bytes(raw)
        path.symlink_to(target)
        with self.assertRaises(OSError):
            self.check()
        self.assertEqual(target.read_bytes(), raw)

    def test_browser_active_or_appearing_after_hashing_is_deferred(self):
        p = self.proc / '123'
        p.mkdir()
        (p / 'comm').write_text('chromium\n')
        with self.assertRaisesRegex(guard.Deferred, 'browser_active'):
            self.check()
        (p / 'comm').write_text('python3\n')
        def started_during_hash(*args):
            (p / 'comm').write_text('chromium\n')
        with self.assertRaisesRegex(guard.Deferred, 'browser_active'):
            self.check(verify=started_during_hash)

    def test_failed_observation_missing_protocol_and_input_capacity(self):
        with patch.object(Path, 'read_text', side_effect=PermissionError):
            p = self.proc / '1'
            p.mkdir()
            with self.assertRaisesRegex(guard.Deferred, 'process_observation_unavailable'):
                self.check()
        for raw in (b'/cache/a.deb\n', b'VERSION 3\n\n', b'VERSION 2\nmissing',
                    b'x' * (guard.MAX_INPUT + 1)):
            with self.subTest(raw=raw[:20]), self.assertRaises(guard.Deferred):
                self.check(raw)

    def test_custody_capacity_and_unqualified_manifest(self):
        p = self.root / 'manifest.json'
        p.write_text(json.dumps(self.manifest))
        p.chmod(0o600)
        self.assertEqual(guard.private_json(p, os.getuid()), self.manifest)
        p.chmod(0o644)
        with self.assertRaisesRegex(guard.Deferred, 'manifest_custody'):
            guard.private_json(p, os.getuid())
        for field, value in (('source', 'unverified'), ('maintainer_reviewed', False),
                             ('packages', {'systemd': {}})):
            modified = copy.deepcopy(self.manifest)
            modified[field] = value
            with self.assertRaises(guard.Deferred):
                guard.manifest_packages(modified)
        modified = copy.deepcopy(self.manifest)
        next(iter(modified['packages'].values()))['bytes'] = guard.MAX_ARCHIVES + 1
        with self.assertRaisesRegex(guard.Deferred, 'archive_capacity'):
            guard.manifest_packages(modified)

    def test_only_separate_closed_brotli_family_with_reviewed_metadata(self):
        item=next(iter(self.manifest['packages'].values()))
        self.manifest['packages']={'libbrotli1':item}
        self.manifest.update(installed_files_sha256={n:'a'*64 for n in guard.LIBRARY_FILES},
                             trigger_runtime={n:'b'*64 for n in guard.TRIGGER_FILES})
        self.actions=[f'libbrotli1 1 < 2 {item["archive"]}']
        with patch.object(guard,'verify_trigger_runtime') as runtime:
            self.assertEqual(self.check()['decision'],'admitted');self.assertEqual(runtime.call_count,2)
        self.manifest['packages']['chromium']=item
        with self.assertRaisesRegex(guard.Deferred,'unreviewed_packages'):self.check()
        self.manifest['packages'].pop('chromium')
        self.manifest['trigger_runtime'].pop(next(iter(guard.TRIGGER_FILES)))
        with self.assertRaisesRegex(guard.Deferred,'library_metadata'):self.check()

    def test_library_active_appearing_consumer_unavailable_or_oversized_maps_defers(self):
        p=self.proc/'123';p.mkdir();maps=p/'maps';maps.write_text('idle maps')
        guard.idle_package_scope(guard.BROTLI,self.proc)
        maps.write_text('/usr/lib/libbrotlidec.so.1 (deleted)')
        with self.assertRaisesRegex(guard.Deferred,'consumer_active'):
            guard.idle_package_scope(guard.BROTLI,self.proc)
        maps.write_bytes(b'x'*(2*1024*1024+1))
        with self.assertRaisesRegex(guard.Deferred,'capacity'):
            guard.idle_package_scope(guard.BROTLI,self.proc)
        with patch.object(Path,'open',side_effect=PermissionError):
            with self.assertRaisesRegex(guard.Deferred,'observation_unavailable'):
                guard.idle_package_scope(guard.BROTLI,self.proc)

    def test_brotli_hash_time_consumer_is_rechecked_before_admission(self):
        item=next(iter(self.manifest['packages'].values()))
        self.manifest['packages']={'libbrotli1':item}
        self.manifest.update(installed_files_sha256={n:'a'*64 for n in guard.LIBRARY_FILES},
                             trigger_runtime={n:'b'*64 for n in guard.TRIGGER_FILES})
        self.actions=[f'libbrotli1 1 < 2 {item["archive"]}']
        p=self.proc/'1';p.mkdir();(p/'maps').write_text('idle')
        def appeared(*a):(p/'maps').write_text('/usr/lib/libbrotlidec.so.1')
        with patch.object(guard,'verify_trigger_runtime'),self.assertRaisesRegex(guard.Deferred,'consumer_active'):
            self.check(verify=appeared)


if __name__ == '__main__':
    unittest.main()
