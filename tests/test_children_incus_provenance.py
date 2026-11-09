"""Signed index/archive selection never executes Incus package payloads."""
import hashlib
import io
import tarfile
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools import children_incus_provenance as provenance
from tools import children_application_inventory as inventory


def tar_payload(rows):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w') as archive:
        for name, raw, kind in rows:
            item = tarfile.TarInfo(name)
            item.type = kind
            item.size = len(raw)
            archive.addfile(item, io.BytesIO(raw))
    return out.getvalue()


def test_archive_manifest_comes_from_package_bytes_without_running_them():
    raw = b'raise RuntimeError("never execute")'
    result = provenance.archive_files(tar_payload([
        ('./usr/libexec/incus/incusd', raw, tarfile.REGTYPE),
        ('./usr/libexec/incus/startup', b'exit 99', tarfile.REGTYPE),
        ('./unrelated/ignored', b'not selected', tarfile.REGTYPE)]))
    assert inventory.validate_deployments(provenance.deployment_manifest(result, 'a'*64), ['incus.service'])
    assert result == {'incusd': hashlib.sha256(raw).hexdigest(),
                      'startup': hashlib.sha256(b'exit 99').hexdigest()}


@pytest.mark.parametrize('name,kind', [
    ('usr/libexec/incus/incusd', tarfile.SYMTYPE),
    ('usr/libexec/incus/../outside', tarfile.REGTYPE),
])
def test_archive_symlink_or_escape_is_not_source_provenance(name, kind):
    with pytest.raises(ValueError, match='incus_archive_file_shape'):
        provenance.archive_files(tar_payload([(name, b'bad', kind)]))


def test_index_binds_exact_installed_version_and_signed_archive_hash():
    row = ('Package: incus-base\nVersion: 6.0.4-2+deb13u12\nArchitecture: amd64\n'
           'Size: 100\nSHA256: '+ 'a'*64 +'\nFilename: pool/updates/main/i/incus/own.deb\n')
    assert provenance.package_record(row.encode(), '6.0.4-2+deb13u12')['SHA256'] == 'a'*64
    with pytest.raises(ValueError, match='incus_installed_security_package_required'):
        provenance.package_record(row.encode(), 'foreign')
    with pytest.raises(ValueError, match='incus_security_package_shape'):
        provenance.package_record(row.replace('/i/incus/', '/../escape/').encode(), '6.0.4-2+deb13u12')


def test_signed_release_digest_is_checked_before_package_selection(tmp_path, monkeypatch):
    raw = b'Package: own\n'
    index = tmp_path/'host_main_binary-amd64_Packages'
    release = tmp_path/'host_InRelease'
    release.write_text('-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nSHA256:\n '
        +hashlib.sha256(raw).hexdigest()+' '+str(len(raw))+' main/binary-amd64/Packages\n'
        +'-----BEGIN PGP SIGNATURE-----\nfixture\n')
    monkeypatch.setattr(provenance.selection, 'release_fresh', lambda target, now: index)
    target = ('Identifier: Packages\nCodename: trixie-security\nLabel: Debian-Security\n'
              'Origin: Debian\nComponent: main\nArchitecture: amd64\nTrusted: yes\n'
              'MetaKey: main/binary-amd64/Packages\n')
    calls = []
    authenticated = ('SHA256:\n '+hashlib.sha256(raw).hexdigest()+' '+str(len(raw))
                     +' main/binary-amd64/Packages\n').encode()
    def read(argv, **kwargs):
        calls.append(argv)
        if argv[0] == '/usr/bin/sqv':
            Path(argv[argv.index('--output')+1]).write_bytes(authenticated)
            return b'fixture signer'
        return raw
    assert provenance.signed_index(target, read=read, now=1) == raw
    assert calls[0][0] == '/usr/bin/sqv' and '--cleartext' in calls[0]
    def tampered(argv, **kwargs):
        return read(argv, **kwargs) if argv[0] == '/usr/bin/sqv' else b'changed'
    with pytest.raises(ValueError, match='incus_signed_index_digest_changed'):
        provenance.signed_index(target, read=tampered, now=1)
    def refused(argv, **kwargs):
        assert argv[0] == '/usr/bin/sqv'
        raise ValueError('signature refused')
    with pytest.raises(ValueError, match='signature refused'):
        provenance.signed_index(target, read=refused, now=1)


def test_retained_archive_download_resumes_with_exact_range(request):
    body = b'whole signed public archive'
    directory = tempfile.TemporaryDirectory(prefix='.incus-provenance-test-', dir=Path.home())
    request.addfinalizer(directory.cleanup)
    path = Path(directory.name)/'own.deb'
    path.with_name(path.name+'.partial').write_bytes(body[:7])
    row = dict(Size=str(len(body)), SHA256=hashlib.sha256(body).hexdigest(),
               Filename='pool/updates/main/i/incus/own.deb')
    class Response(io.BytesIO):
        status = 206
        headers = {'Content-Range': f'bytes 7-{len(body)-1}/{len(body)}'}
    def open_request(request, timeout):
        assert request.headers['Range'] == 'bytes=7-' and timeout == 20
        assert request.full_url.startswith('https://security.debian.org/debian-security/')
        return Response(body[7:])
    provenance.download_archive(path, row, opener=SimpleNamespace(open=open_request))
    assert path.read_bytes() == body
    assert not path.with_name(path.name+'.partial').exists()


@pytest.mark.parametrize('mode', ['range-refused', 'wrong-hash', 'oversized', 'zero-byte-resume'])
def test_partial_or_invalid_download_never_replaces_verified_work(request, mode):
    directory = tempfile.TemporaryDirectory(prefix='.incus-provenance-test-', dir=Path.home())
    request.addfinalizer(directory.cleanup)
    path = Path(directory.name)/'own.deb'
    body = b'known public package'
    partial = path.with_name(path.name+'.partial')
    prefix = body[:3] if mode=='range-refused' else b''
    if mode in ('range-refused', 'zero-byte-resume'):
        partial.write_bytes(prefix)
    row = dict(Size=str(len(body)), SHA256=hashlib.sha256(body).hexdigest(),
               Filename='pool/updates/main/i/incus/own.deb')
    class Response(io.BytesIO):
        status = 200
        headers = {}
    data = body+b'excess' if mode=='oversized' else body
    if mode=='wrong-hash':
        row['SHA256']='a'*64
    opener=SimpleNamespace(open=lambda request,timeout: Response(data))
    if mode=='zero-byte-resume':
        provenance.download_archive(path,row,opener=opener)
        assert path.read_bytes()==body
    else:
        with pytest.raises(ValueError):
            provenance.download_archive(path,row,opener=opener)
        assert not path.exists()
        if mode=='range-refused':
            assert partial.read_bytes()==prefix
