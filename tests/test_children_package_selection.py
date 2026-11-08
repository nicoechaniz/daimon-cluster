"""Source, maintainer, payload and plan uncertainty never authorizes a writer."""
import hashlib
import io
import json
import types
import datetime
from pathlib import Path
import tarfile
import tempfile
import unittest
import os
from unittest.mock import patch

from tools import children_package_selection as selection
from tools.children_package_guard import Deferred


class PackageSelectionTests(unittest.TestCase):
    def test_apt_configuration_rejects_hooks_and_weakened_auth(self):
        for line in ('DPkg::Post-Invoke:: "restart service";',
                     'DPkg::Pre-Install-Pkgs:: "another hook";',
                     'APT::Get::AllowUnauthenticated "true";',
                     'Acquire::AllowInsecureRepositories "1";',
                     'Acquire::Check-Valid-Until "false";',
                     'DPkg::Options:: "--force-all";'):
            with self.subTest(line=line), self.assertRaises(Deferred):
                selection.check_config(line)
        selection.check_config('APT::Get::AllowUnauthenticated "false";\n'
                               'DPkg::Options:: "--force-confold";')

    def test_native_debconf_hook_is_bound_and_only_omittable_without_package_config(self):
        script=b'existing native helper'
        policy={'omittable_preinstall':{'path':'/usr/sbin/dpkg-preconfigure',
                'command':'/usr/sbin/dpkg-preconfigure --apt || true',
                'sha256':hashlib.sha256(script).hexdigest()}}
        text='DPkg::Pre-Install-Pkgs "";\nDPkg::Pre-Install-Pkgs:: "/usr/sbin/dpkg-preconfigure --apt || true";'
        info=types.SimpleNamespace(st_uid=0,st_mode=0o755)
        with patch.object(Path,'stat',return_value=info),patch.object(Path,'is_symlink',return_value=False),\
             patch.object(Path,'read_bytes',return_value=script):
            selection.check_config(text,policy)
            with self.assertRaises(Deferred):selection.check_config(text.replace(' || true',''),policy)
        with patch.object(Path,'stat',return_value=info),patch.object(Path,'is_symlink',return_value=False),\
             patch.object(Path,'read_bytes',return_value=b'changed helper'):
            with self.assertRaises(Deferred):selection.check_config(text,policy)
        for text in ['Binary::apt-get::APT::Get::AllowUnauthenticated "true";',
                     'Binary::apt-get::DPkg::Pre-Install-Pkgs:: "/usr/sbin/dpkg-preconfigure --apt || true";']:
            with self.assertRaises(Deferred):selection.check_config(text,policy)

    def target(self):
        return ('Identifier: Packages\nCodename: trixie-security\nLabel: Debian-Security\n'
                'Origin: Debian\nComponent: main\nArchitecture: amd64\nTrusted: yes\n'
                'Repo-URI: http://deb.debian.org/debian-security/\n'
                'Sourcesentry: /etc/apt/sources.list:1\n'
                'MetaKey: main/binary-amd64/Packages\n'
                'Filename: /var/lib/apt/lists/mirror_trixie-security_main_binary-amd64_Packages')

    def test_native_index_trust_and_source_options(self):
        info=types.SimpleNamespace(st_uid=0,st_mode=0o644)
        source='deb http://deb.debian.org/debian-security/ trixie-security main contrib'
        with patch.object(Path,'stat',return_value=info),patch.object(Path,'is_symlink',return_value=False),\
             patch.object(Path,'read_text',return_value=source):
            target=selection.security_target(self.target())
            self.assertEqual(target['Trusted'],'yes')
            for bad in (self.target().replace('Trusted: yes','Trusted: no'),
                        self.target().replace('Origin: Debian','Origin: Unreviewed'),
                        self.target()+'\n\n'+self.target()):
                with self.assertRaises(Deferred):selection.security_target(bad)
        with patch.object(Path,'stat',return_value=info),patch.object(Path,'is_symlink',return_value=False),\
             patch.object(Path,'read_text',return_value=source.replace('deb http','deb [trusted=yes] http')):
            with self.assertRaisesRegex(Deferred,'unreviewed_source_options'):
                selection.security_target(self.target())

    def test_expired_release_or_absent_native_freshness_is_deferred(self):
        now=1794138110
        info=types.SimpleNamespace(st_uid=0,st_mode=0o644,st_size=1000,st_mtime=now)
        release=('-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n'
                 'Origin: Debian\nLabel: Debian-Security\nCodename: trixie-security\n'
                 'Date: Fri, 06 Nov 2026 00:00:00 UTC\nValid-Until: Fri, 13 Nov 2026 00:00:00 UTC\n'
                 '-----BEGIN PGP SIGNATURE-----\nfixture signature; APT trust tested separately')
        target=selection.paragraphs(self.target())[0]
        with patch.object(Path,'is_file',return_value=True),patch.object(Path,'is_symlink',return_value=False),\
             patch.object(Path,'stat',return_value=info),patch.object(Path,'read_text',return_value=release):
            selection.release_fresh(target,now)
        with patch.object(Path,'is_file',return_value=True),patch.object(Path,'is_symlink',return_value=False),\
             patch.object(Path,'stat',return_value=info),\
             patch.object(Path,'read_text',return_value=release.replace('13 Nov','07 Nov')):
            with self.assertRaisesRegex(Deferred,'expired_release'):selection.release_fresh(target,now)
        with patch.object(Path,'is_file',return_value=False):
            with self.assertRaisesRegex(Deferred,'native_index_refresh_required'):
                selection.release_fresh(target,now)

    def test_changed_plan_or_new_service_package_is_deferred(self):
        installed={'chromium':'1','chromium-common':'1'}
        versions={'chromium':'2','chromium-common':'2'}
        plan='\n'.join('Inst '+n+' [1] (2 Debian-Security:13/stable-security)' for n in installed)
        selection.plan_exact(plan, installed, versions)
        for extra in ('\nInst systemd [1] (2 Debian-Security:13/stable-security)',
                      '\nRemv chromium-common [1]'):
            with self.assertRaises(Deferred):selection.plan_exact(plan+extra,installed,versions)
        for bad in (plan.replace('[1]','[0]'),plan.replace('(2 ','(3 '),
                    plan.replace('Debian-Security:','Unknown:'),plan.splitlines()[0]):
            with self.assertRaises(Deferred):selection.plan_exact(bad,installed,versions)

    def test_index_requires_exact_security_records_and_sha256(self):
        versions={'chromium':'2','chromium-common':'2'}
        text='\n\n'.join('Package: '+n+'\nArchitecture: amd64\nVersion: 2\nSHA256: '+
                         'a'*64+'\nSize: 100\nFilename: pool/updates/main/c/chromium/'+n+'.deb'
                         for n in versions)
        self.assertEqual(set(selection.record_selection(text,versions)),set(versions))
        for bad in (text.replace('a'*64,'unverified'),text.replace('amd64','arm64'),
                    text.replace('pool/updates/main/c/chromium/','../../'),text+'\n\n'+text,
                    text.replace('Size: 100','Size: 999999999')):
            with self.assertRaises(Deferred):selection.record_selection(bad,versions)

    def test_payload_rejects_service_files_devices_permission_changes_and_links(self):
        policy={'paths':['/','/usr','/usr/lib/chromium','/usr/lib/chromium/browser'], 'links':{}}
        row='-rwxr-xr-x root/root 100 2026-11-08 00:00 ./usr/lib/chromium/browser'
        selection.inspect_listing('drwxr-xr-x root/root 0 2026-11-08 00:00 ./'+chr(10)+row,policy)
        for bad in (row.replace('./usr/lib/chromium/browser','./usr/lib/systemd/system/new.service'),
                    row.replace('./usr/lib/chromium/browser','./usr/lib/chromium/../../etc/passwd'),
                    row.replace('-rwxr-xr-x','-rwsr-xr-x'),row.replace('root/root','1000/1000'),
                    row.replace('-rwxr-xr-x','crw-r--r--'),row+'\n'+row,
                    row.replace('-rwxr-xr-x','lrwxrwxrwx')+' -> /etc/passwd'):
            with self.subTest(row=bad),self.assertRaises(Deferred):selection.inspect_listing(bad,policy)
        policy={'paths':['/usr/share/pixmaps/chromium.png'],
                'links':{'/usr/share/pixmaps/chromium.png':'../icons/chromium.png'}}
        selection.inspect_listing('lrwxrwxrwx root/root 0 2026-11-08 00:00 '
                                  './usr/share/pixmaps/chromium.png -> ../icons/chromium.png',policy)

    def control(self, entries):
        value=io.BytesIO()
        with tarfile.open(fileobj=value,mode='w') as tar:
            for name,raw in entries.items():
                member=tarfile.TarInfo(name);member.size=len(raw);tar.addfile(member,io.BytesIO(raw))
        return value.getvalue()

    def test_maintainer_changes_and_wrong_archive_identity_are_deferred(self):
        control=b'Package: chromium\nVersion: 2\nArchitecture: amd64\n'
        script=b'#!/bin/sh\nupdate-alternatives --install\n'
        policy={'scripts':{'postinst':hashlib.sha256(script).hexdigest()},'paths':['/etc/chromium/prefs']}
        base={'./control':control,'./postinst':script,'./conffiles':b'/etc/chromium/prefs\n'}
        selection.inspect_control(self.control(base),policy,'chromium','2')
        for name,raw in [('./postinst',b'#!/bin/sh\nsystemctl restart ssh\n'),
                         ('./control',control.replace(b'chromium',b'systemd')),
                         ('./conffiles',b'/etc/ssh/sshd_config\n'),
                         ('./triggers',b'activate systemd\n'),('./templates',b'unreviewed')]:
            with self.subTest(name=name),self.assertRaises(Deferred):
                selection.inspect_control(self.control({**base,name:raw}),policy,'chromium','2')

    def test_download_path_prepares_guard_bound_artifacts_but_never_writes_packages(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
            state=Path(directory);archives=state/'archives';archives.mkdir()
            policy={'packages':{n:{'paths':['/usr/lib/chromium/browser'],'links':{},'scripts':{}}
                                for n in selection.PACKAGES}}
            blocks=[]
            for n in selection.PACKAGES:
                payload=('inert fixture '+n).encode();archive=archives/(n+'.deb');archive.write_bytes(payload)
                blocks.append('Package: '+n+'\nArchitecture: amd64\nVersion: 2\nSHA256: '+
                              hashlib.sha256(payload).hexdigest()+'\nSize: '+str(len(payload))+
                              '\nFilename: pool/updates/main/c/chromium/'+n+'.deb')
            index='\n\n'.join(blocks).encode();calls=[]
            def run(argv,**kwargs):
                calls.append(argv)
                if argv[-2:]==['apt-config','dump']:return b''
                if argv[-2:]==['apt-get','indextargets']:return b'fixture'
                if 'policy' in argv:return b'  Installed: 1\n  Candidate: 2\n'
                if 'cat-file' in argv:return index
                if argv[:2]==['dpkg','--compare-versions']:return b''
                if argv[-2:]==['dpkg','--audit']:return b''
                if '-s' in argv:return ('\n'.join('Inst '+n+' [1] (2 Debian-Security:13/security)'
                                                  for n in selection.PACKAGES)).encode()
                if '--download-only' in argv:return b'fixture already cached'
                if '--ctrl-tarfile' in argv:
                    n=Path(argv[-1]).stem
                    return self.control({'./control':('Package: '+n+'\nVersion: 2\nArchitecture: amd64\n').encode()})
                if '--contents' in argv:return b'-rwxr-xr-x root/root 10 2026-11-08 00:00 ./usr/lib/chromium/browser'
                self.fail(str(argv))
            original_verify=selection.verify_archive
            with patch.object(selection,'security_target',return_value={}),\
                 patch.object(selection,'release_fresh',return_value=Path('/index')),\
                 patch.object(selection,'idle_browser_scope'),\
                 patch.object(selection,'verify_archive',side_effect=lambda item,uid:original_verify(item,os.getuid())):
                result=selection.select(policy,state,download=True,run=run)
            self.assertEqual(result['decision'],'reviewed_manifest_prepared')
            self.assertFalse(result['package_write_performed'])
            manifest=(state/'manifest.json').read_bytes();scoped=(state/'transaction.apt.conf').read_bytes()
            self.assertEqual(result['manifest_sha256'],hashlib.sha256(manifest).hexdigest())
            self.assertEqual(result['transaction_config_sha256'],hashlib.sha256(scoped).hexdigest())
            self.assertIn(b'#clear DPkg::Pre-Install-Pkgs;',scoped)
            self.assertIn(b'::Version "2";',scoped)
            self.assertTrue(any('--download-only' in argv for argv in calls))
            self.assertFalse(any('--unpack' in argv for argv in calls))

    def test_pending_transaction_never_starts_new_selection_or_overwrites_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            state=Path(temporary);path=state/'manifest.json';path.write_bytes(b'original pending operation')
            run=unittest.mock.Mock()
            with self.assertRaisesRegex(Deferred,'pending_transaction'):
                selection.select({},state,run=run)
            run.assert_not_called();self.assertEqual(path.read_bytes(),b'original pending operation')

    def test_up_to_date_still_checks_database_and_never_downloads(self):
        policy={'packages':{'chromium':{},'chromium-common':{}}}
        target={'Filename':'/index'}
        index='\n\n'.join('Package: '+n+'\nArchitecture: amd64\nVersion: 2\nSHA256: '+
                         'a'*64+'\nSize: 10\nFilename: pool/updates/main/c/chromium/'+n+'.deb'
                         for n in policy['packages'])
        calls=[]
        def run(argv,**kwargs):
            calls.append(argv)
            if argv[-2:]==['apt-config','dump']:return b''
            if argv[-2:]==['apt-get','indextargets']:return b'fake target; separately qualified'
            if 'policy' in argv:return b'  Installed: 2\n  Candidate: 2\n'
            if 'cat-file' in argv:return index.encode()
            if argv[-2:]==['dpkg','--audit']:return b''
            self.fail('Unexpected writer/download: '+str(argv))
        with tempfile.TemporaryDirectory() as directory,patch.object(selection,'security_target',return_value=target),\
             patch.object(selection,'release_fresh',return_value=Path('/index')):
            result=selection.select(policy,Path(directory),run=run)
        self.assertEqual(result['decision'],'up_to_date')
        self.assertFalse(result['package_write_performed'])
        self.assertTrue(any(argv[-2:]==['dpkg','--audit'] for argv in calls))
        self.assertFalse(any('--download-only' in argv for argv in calls))


if __name__=='__main__':unittest.main()
