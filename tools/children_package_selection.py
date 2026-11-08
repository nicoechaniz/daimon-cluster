#!/usr/bin/env python3
"""Select a reviewed browser security transaction; never executes a package writer.

APT owns signed-index verification. This step consumes its trusted index target,
requires fresh native periodic-update evidence and an unexpired security Release,
and binds an exact reviewed archive/plan for the existing APT guard.
"""
import argparse
import email.utils
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import sys
import tarfile
import time

# Standalone selected releases contain the same pinned read/guard helpers.
if __package__:
    from .children_daily import command, atomic
    from .children_package_guard import Deferred, PACKAGES, BROTLI, LIBRARY_FILES, TRIGGER_FILES, reviewed_packages, verify_trigger_runtime, MAX_ARCHIVES, private_json, idle_package_scope, verify_archive
else:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from children_daily import command, atomic
    from children_package_guard import Deferred, PACKAGES, BROTLI, LIBRARY_FILES, TRIGGER_FILES, reviewed_packages, verify_trigger_runtime, MAX_ARCHIVES, private_json, idle_package_scope, verify_archive

MAX_INDEX = 16 * 1024 * 1024
MAX_STATE = 512 * 1024 * 1024
SCRIPTS = {'preinst', 'postinst', 'prerm', 'postrm', 'config', 'triggers'}
SAFE_CONFIG = {'apt::get::allowunauthenticated', 'acquire::allowinsecurerepositories',
               'acquire::allowdowngradetoinsecurerepositories', 'acquire::allowweakrepositories'}


def paragraphs(text):
    rows = []
    for block in text.strip().split('\n\n'):
        item, key = {}, None
        for line in block.splitlines():
            if line[:1].isspace() and key:
                item[key] += '\n' + line.strip()
            else:
                key, separator, value = line.partition(':')
                if not separator or key in item:
                    raise Deferred('malformed_apt_metadata')
                item[key] = value.strip()
        if item:
            rows.append(item)
    return rows


def check_config(text, policy=None):
    for line in text.splitlines():
        match = re.fullmatch(r'([^ ]+) "(.*)";', line)
        if not match:
            raise Deferred('unknown_apt_config')
        key, value = match.groups()
        key = key.lower()
        if not value:
            continue
        if key.rstrip(':').endswith('dpkg::pre-install-pkgs'):
            if key.rstrip(':') != 'dpkg::pre-install-pkgs':
                raise Deferred('unreviewed_binary_hook_scope')
            known = (policy or {}).get('omittable_preinstall', {})
            helper = Path(known.get('path', '/unreviewed'))
            if (value != known.get('command') or str(helper) != '/usr/sbin/dpkg-preconfigure'
                    or helper.is_symlink() or helper.stat().st_uid != 0
                    or helper.stat().st_mode & 0o022
                    or hashlib.sha256(helper.read_bytes()).hexdigest() != known.get('sha256')):
                raise Deferred('unreviewed_apt_hook')
        elif 'invoke' in key:
            raise Deferred('unreviewed_apt_hook')
        if any(key == k or key.endswith('::' + k) for k in SAFE_CONFIG) and value.lower() not in {'false', 'no', '0'}:
            raise Deferred('insecure_apt_source')
        if key.endswith('acquire::check-valid-until') and value.lower() in {'false', 'no', '0'}:
            raise Deferred('disabled_release_expiry')
        if key.rstrip(':').endswith('dpkg::options') and value != '--force-confold':
            raise Deferred('unreviewed_dpkg_option')


def security_target(text):
    selected = [v for v in paragraphs(text) if
        (v.get('Identifier'), v.get('Codename'), v.get('Label'), v.get('Origin'),
         v.get('Component'), v.get('Architecture'), v.get('Trusted')) ==
        ('Packages', 'trixie-security', 'Debian-Security', 'Debian', 'main', 'amd64', 'yes')]
    if len(selected) != 1:
        raise Deferred('unavailable_trusted_security_index')
    v = selected[0]
    if v.get('Repo-URI') not in {'http://deb.debian.org/debian-security/',
                                'https://deb.debian.org/debian-security/',
                                'http://security.debian.org/debian-security/',
                                'https://security.debian.org/debian-security/'}:
        raise Deferred('unreviewed_security_origin')
    source, separator, number = v.get('Sourcesentry', '').rpartition(':')
    if not separator or source != '/etc/apt/sources.list' or not number.isdigit():
        raise Deferred('unreviewed_source_binding')
    source_path = Path(source)
    if source_path.is_symlink() or source_path.stat().st_uid != 0 or source_path.stat().st_mode & 0o022:
        raise Deferred('source_custody')
    lines = source_path.read_text().splitlines()
    try:
        fields = lines[int(number) - 1].split()
    except IndexError:
        raise Deferred('changed_source_binding') from None
    if (len(fields) < 4 or fields[0] != 'deb' or fields[1].rstrip('/') != v['Repo-URI'].rstrip('/')
            or fields[2] != 'trixie-security' or 'main' not in fields[3:]):
        raise Deferred('unreviewed_source_options')
    return v


def release_fresh(target, now, stamp=Path('/var/lib/apt/periodic/update-stamp')):
    if (not stamp.is_file() or stamp.is_symlink() or stamp.stat().st_uid != 0
            or now - stamp.stat().st_mtime > 26 * 3600
            or stamp.stat().st_mtime > now + 300):
        raise Deferred('native_index_refresh_required')
    filename = Path(target['Filename'])
    suffix = target['MetaKey'].replace('/', '_')
    if not filename.name.endswith(suffix) or filename.parent != Path('/var/lib/apt/lists'):
        raise Deferred('unreviewed_index_location')
    release = filename.with_name(filename.name[:-len(suffix)] + 'InRelease')
    if (release.is_symlink() or release.stat().st_uid != 0 or release.stat().st_mode & 0o022
            or release.stat().st_size > 256 * 1024):
        raise Deferred('release_capacity_or_custody')
    text = release.read_text()
    if not text.startswith('-----BEGIN PGP SIGNED MESSAGE-----\n'):
        raise Deferred('missing_signed_release')
    body = text.split('\n\n', 1)[1].split('-----BEGIN PGP SIGNATURE-----', 1)[0]
    rows = paragraphs('\n'.join(l.removeprefix('- ') for l in body.splitlines()))
    if len(rows) != 1:
        raise Deferred('malformed_release')
    row = rows[0]
    if (row.get('Origin'), row.get('Label'), row.get('Codename')) != ('Debian', 'Debian-Security', 'trixie-security'):
        raise Deferred('changed_release_identity')
    date = email.utils.parsedate_to_datetime(row['Date']).timestamp()
    expiry = email.utils.parsedate_to_datetime(row['Valid-Until']).timestamp()
    if not date <= now + 300 or not date < expiry or expiry <= now:
        raise Deferred('expired_release')
    return filename


def record_selection(index, versions):
    packages=reviewed_packages(versions)
    prefix='pool/updates/main/b/brotli/' if packages==BROTLI else 'pool/updates/main/c/chromium/'
    rows = [r for r in paragraphs(index) if r.get('Package') in packages
            and r.get('Architecture') == 'amd64' and r.get('Version') == versions[r['Package']]]
    selected = {}
    for row in rows:
        name = row['Package']
        if name in selected:
            raise Deferred('ambiguous_security_record')
        if (not re.fullmatch('[a-f0-9]{64}', row.get('SHA256', ''))
                or not row.get('Size', '').isdigit()
                or not 0 < int(row['Size']) <= MAX_ARCHIVES
                or not row.get('Filename', '').startswith(prefix)
                or '..' in PurePosixPath(row['Filename']).parts):
            raise Deferred('malformed_security_record')
        selected[name] = row
    if set(selected) != packages or sum(int(v['Size']) for v in selected.values()) > MAX_ARCHIVES:
        raise Deferred('missing_or_oversized_security_records')
    return selected


def plan_exact(text, installed, versions):
    packages=reviewed_packages(versions)
    seen = set()
    for line in text.splitlines():
        if line.startswith('Remv '):
            raise Deferred('package_removal')
        if not line.startswith('Inst '):
            continue
        match = re.match(r'Inst ([^ ]+) \[([^]]+)\] \(([^ ]+) Debian-Security:', line)
        if not match:
            raise Deferred('unreviewed_package_plan')
        name, old, new = match.groups()
        if (name not in packages or name in seen or old != installed[name]
                or new != versions[name]):
            raise Deferred('changed_package_plan')
        seen.add(name)
    if seen != packages:
        raise Deferred('incomplete_package_plan')


def inspect_listing(text, policy):
    seen = set()
    for line in text.splitlines():
        fields = line.split(None, 5)
        if len(fields) != 6:
            raise Deferred('unknown_payload_listing')
        mode, owner, size, _date, _clock, value = fields
        if owner not in {'root/root', '0/0'} or not size.isdigit():
            raise Deferred('payload_ownership')
        path, arrow, link = value.partition(' -> ')
        if (not re.fullmatch(r'[A-Za-z0-9_./+%@=,:-]+', path)
                or '..' in PurePosixPath(path).parts):
            raise Deferred('unsafe_payload_path')
        normalized = '/' if str(PurePosixPath(path)) == '.' else '/' + str(PurePosixPath(path)).lstrip('/')
        if normalized not in policy['paths'] or normalized in seen:
            raise Deferred('unreviewed_payload_path')
        seen.add(normalized)
        if mode.startswith('l'):
            if not arrow or policy['links'].get(normalized) != link:
                raise Deferred('unreviewed_payload_link')
        elif arrow or mode not in {'drwxr-xr-x', '-rw-r--r--', '-rwxr-xr-x'}:
            raise Deferred('unreviewed_payload_mode')
    if not seen:
        raise Deferred('empty_payload')


def inspect_control(raw, policy, package, version):
    scripts = {}
    control = None
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as archive:
        for member in archive:
            name = member.name.removeprefix('./')
            if name in {'config', 'templates'}:
                raise Deferred('debconf_package_requires_review')
            if name == 'control':
                if not member.isfile() or member.size > 128 * 1024:
                    raise Deferred('control_capacity')
                control = paragraphs(archive.extractfile(member).read().decode())
            elif name == 'conffiles':
                if not member.isfile() or member.size > 128 * 1024:
                    raise Deferred('conffile_capacity')
                for line in archive.extractfile(member).read().decode().splitlines():
                    if line.strip() and line.strip() not in policy['paths']:
                        raise Deferred('unreviewed_conffile')
            elif name in SCRIPTS:
                if not member.isfile() or member.size > 64 * 1024:
                    raise Deferred('maintainer_script_capacity')
                scripts[name] = hashlib.sha256(archive.extractfile(member).read()).hexdigest()
            elif name not in {'', '.', 'control', 'conffiles', 'md5sums','shlibs','symbols'}:
                raise Deferred('unreviewed_control_metadata')
            elif name in {'shlibs','symbols'} and (package!='libbrotli1' or not member.isfile() or member.size>64*1024):
                raise Deferred('unreviewed_library_metadata')
    if (not control or len(control) != 1 or (control[0].get('Package'), control[0].get('Version'),
            control[0].get('Architecture')) != (package, version, 'amd64')
            or control[0].get('Essential', 'no') != 'no'):
        raise Deferred('changed_archive_identity')
    if scripts != policy['scripts']:
        raise Deferred('changed_maintainer_scripts')


def library_payload(raw):
    expected=LIBRARY_FILES
    if len(raw)>4*1024*1024:raise Deferred('library_payload_capacity')
    files={}
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as archive:
        for member in archive:
            name='/'+member.name.removeprefix('./')
            if name not in expected:continue
            if name in files or not member.isfile() or not 0<member.size<=2*1024*1024:
                raise Deferred('library_payload_identity')
            files[name]=hashlib.sha256(archive.extractfile(member).read()).hexdigest()
    if set(files)!=expected:raise Deferred('library_payload_incomplete')
    return files


def select(policy, state, *, download=False, run=command, now=None):
    now = time.time() if now is None else now
    if (state / 'manifest.json').exists():
        raise Deferred('pending_transaction_requires_reconciliation')
    packages=reviewed_packages(policy.get('packages',{}))
    if os.environ.get('APT_CONFIG'):
        raise Deferred('unreviewed_selection_environment')
    if packages==BROTLI:
        if not isinstance(policy.get('trigger_runtime'),dict) or set(policy['trigger_runtime'])!=TRIGGER_FILES:
            raise Deferred('unreviewed_library_trigger')
        verify_trigger_runtime(policy['trigger_runtime'])
    read = lambda args, limit=256 * 1024: run(['/usr/bin/env', 'LC_ALL=C', *args], seconds=40, limit=limit)
    check_config(read(['apt-config', 'dump']).decode(), policy)
    target = security_target(read(['apt-get', 'indextargets']).decode())
    index_path = release_fresh(target, now)
    installed, versions = {}, {}
    for name in sorted(packages):
        value = read(['apt-cache', 'policy', name]).decode()
        old = re.findall(r'^\s+Installed: (\S+)$', value, re.M)
        candidate = re.findall(r'^\s+Candidate: (\S+)$', value, re.M)
        if len(old) != 1 or len(candidate) != 1 or '(none)' in old + candidate:
            raise Deferred('missing_installed_browser')
        installed[name], versions[name] = old[0], candidate[0]
    index = read(['/usr/lib/apt/apt-helper', 'cat-file', str(index_path)], MAX_INDEX)
    records = record_selection(index.decode(), versions)
    result = {'schema': 'children-package-selection/v1', 'at': now,
              'installed': installed, 'candidate': versions,
              'trusted_security_index_sha256': hashlib.sha256(index).hexdigest(),
              'policy_sha256': hashlib.sha256(json.dumps(policy, sort_keys=True).encode()).hexdigest(),
              'archives': {name: {'sha256': row['SHA256'], 'bytes': int(row['Size']),
                                   'filename': row['Filename']} for name, row in records.items()},
              'package_write_performed': False}
    if read(['dpkg', '--audit']).strip():
        raise Deferred('package_database_requires_recovery')
    if installed == versions:
        return {**result, 'decision': 'up_to_date'}
    # No reinstalls, downgrades or mixed update families in this first policy.
    for name in packages:
        run(['dpkg', '--compare-versions', installed[name], 'lt', versions[name]], seconds=5, limit=4096)
    idle_package_scope(packages)
    argv = ['apt-get', '--no-remove', '--no-install-recommends', 'install', '--only-upgrade',
            *[n + '=' + versions[n] for n in sorted(packages)]]
    plan_exact(read(['apt-get', '-s', *argv[1:]]).decode(), installed, versions)
    if not download:
        return {**result, 'decision': 'review_download_required'}
    archives = state / 'archives'
    archives.mkdir(mode=0o700, exist_ok=True)
    existing = sum(p.stat().st_size for p in archives.rglob('*') if p.is_file())
    needed = sum(int(v['Size']) for v in records.values()
                 if not (archives / Path(v['Filename']).name).is_file())
    if existing + needed > MAX_ARCHIVES:
        raise Deferred('archive_cache_capacity')
    run(['/usr/bin/env', 'LC_ALL=C', 'apt-get', '-o', 'Acquire::Retries=0',
         '-o', 'Acquire::http::Timeout=20', '-o', 'Acquire::https::Timeout=20',
         '-o', 'Dir::Cache::archives=' + str(archives), '--download-only', '-y', *argv[1:]],
        seconds=300, limit=1024 * 1024)
    manifest = {'schema': 'children-reviewed-apt-transaction/v1',
                'source': 'verified-local-debian-security', 'maintainer_reviewed': True, 'packages': {}}
    for name, row in records.items():
        archive = archives / Path(row['Filename']).name
        item = {'old_version': installed[name], 'version': versions[name], 'archive': str(archive),
                'sha256': row['SHA256'], 'bytes': int(row['Size'])}
        verify_archive(item, 0)
        inspect_control(read(['dpkg-deb', '--ctrl-tarfile', str(archive)]),
                        policy['packages'][name], name, versions[name])
        inspect_listing(read(['dpkg-deb', '--contents', str(archive)], 512 * 1024).decode(), policy['packages'][name])
        if packages==BROTLI:
            manifest['installed_files_sha256']=library_payload(read(['dpkg-deb','--fsys-tarfile',str(archive)],4*1024*1024))
            manifest['trigger_runtime']=policy['trigger_runtime']
        manifest['packages'][name] = item
    # The existing guard revalidates old/new actions and bytes under APT's lock.
    guard_path = Path(__file__).resolve().with_name('children_package_guard.py')
    hook = shlex.join(['/usr/bin/python3', '-B', '-I', str(guard_path),
                      '--manifest', str(state / 'manifest.json')])
    if any(c in hook for c in ('\\', '"', '\n')):
        raise Deferred('unreviewed_hook_location')
    scoped = ('#clear DPkg::Pre-Install-Pkgs;\nDPkg::Pre-Install-Pkgs { "' + hook +
              '"; };\nDPkg::Tools::Options::/usr/bin/python3::Version "2";\n')
    atomic(state / 'manifest.json', json.dumps(manifest, sort_keys=True).encode())
    atomic(state / 'transaction.apt.conf', scoped.encode())
    return {**result, 'decision': 'reviewed_manifest_prepared',
            'manifest_sha256': hashlib.sha256((state / 'manifest.json').read_bytes()).hexdigest(),
            'transaction_config_sha256': hashlib.sha256(scoped.encode()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy', type=Path, required=True)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--download', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    lock = None
    locked = False
    try:
        if os.geteuid() != 0:
            raise Deferred('requires_selected_guest_operator')
        policy = private_json(args.policy, 0)
        if ((policy.get('schema'),reviewed_packages(policy.get('packages',{}))) not in {
                ('children-browser-package-policy/v1',PACKAGES),('children-library-package-policy/v1',BROTLI)}):
            raise Deferred('unknown_package_policy')
        state = args.state.absolute()
        state.mkdir(mode=0o700, parents=True, exist_ok=True)
        if state.is_symlink() or state.stat().st_uid != 0 or state.stat().st_mode & 0o077:
            raise Deferred('state_custody')
        import fcntl
        lock = (state / 'lock').open('a')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        locked = True
        size = sum(p.stat().st_size for p in state.rglob('*') if p.is_file())
        if size > MAX_STATE:
            raise Deferred('state_capacity')
        result = select(policy, state, download=args.download)
    except (Deferred, OSError, ValueError, KeyError, TypeError, tarfile.TarError):
        error = sys.exception()
        result = {'schema': 'children-package-selection/v1', 'at': time.time(),
                  'decision': 'deferred', 'reason': str(error) if isinstance(error, Deferred) else type(error).__name__,
                  'package_write_performed': False}
    # No existing manifest is deleted on failure; the consumer must match current
    # selection/result, and guard old/new fields prevent reuse after installation.
    if locked:
        current = state / 'current.json'
        if current.exists():
            prior = private_json(current, 0)
            if prior.get('decision') in {'up_to_date', 'reviewed_manifest_prepared'}:
                atomic(state / 'previous.json', json.dumps(prior, sort_keys=True).encode())
        atomic(current, json.dumps(result, sort_keys=True).encode())
    if lock is not None:
        lock.close()
    print(json.dumps(result, sort_keys=True))
    return 1 if result['decision'] == 'deferred' else 0


if __name__ == '__main__':
    raise SystemExit(main())
