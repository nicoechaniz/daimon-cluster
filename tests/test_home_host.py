"""Gateway ownership, route withdrawal, and preserved guest service upgrades."""

from copy import deepcopy
import json

import pytest

from clusterctl.homes.host import ensure_proxy, guest_unit, register
from clusterctl.homes.provision import install_service, sha
from clusterctl.homes.policy import Actor


def test_signed_companion_identity_registers_once_without_keys_sessions_or_runtime(tmp_path):
    import uuid
    from clusterctl.homes.host import register_identity
    from clusterctl.homes.authority import NativeAuthority
    from tests.test_onboarding_target import receiving, files
    ceremony, plan, target = receiving(tmp_path)
    target.activate(ceremony.authorize_target(plan,target.prepare()))
    target.apply_credential(ceremony.authorize_credential(plan,target.credential_request()))
    public = ceremony.public_identity(plan)
    native_before = files(ceremony.root)
    gateway = tmp_path/'gateway'
    config = configuration(gateway)
    config_path = gateway/'config.json'
    write(config_path,json.dumps(config).encode())
    source = gateway/'identities.json'
    initial = dict(schema='dm.home-identities/v1',telegram_source=None,web=[])
    write(source,json.dumps(initial).encode())
    write(gateway/'public-proofs.json',json.dumps(target.document_bundle()).encode())
    row = dict(being_ref=public['authority']['manifest']['being_ref'], label='Companion',
        human_ref='human:local:'+str(uuid.uuid4()),human_name='Paired human',
        origin=public['origin'],enabled=True)
    original_config = config_path.read_bytes()
    with pytest.raises(ValueError,match='concurrent_home_identity'):
        register_identity(config_path,row,public['authority'],previous_source_digest='stale')
    assert json.loads(source.read_bytes())==initial
    result = register_identity(config_path,row,public['authority'],previous_source_digest=sha(source.read_bytes()))
    assert result['status']=='identity-registered'
    resolver=NativeAuthority(source,gateway/'relationships.db',config['homes'],
        authority_source=gateway/'public-proofs.json')
    assert resolver.actor(row['being_ref']).revision==result['revision']
    assert resolver.actor(row['human_ref']).kind=='human'
    retained=source.read_bytes()
    assert register_identity(config_path,row,public['authority'],previous_source_digest='lost-ack')['status']=='unchanged'
    with pytest.raises(ValueError,match='existing_home_identity_preserved'):
        register_identity(config_path,{**row,'human_ref':'human:local:'+str(uuid.uuid4())},
            public['authority'],previous_source_digest=sha(retained))
    assert source.read_bytes()==retained and config_path.read_bytes()==original_config
    assert files(ceremony.root)==native_before
    assert not (gateway/'state').exists()  # no session/owner registration yet
    assert len(list((gateway/'registered-home-identities').glob('*.json')))==1
    # Earlier supported installations keep their own proof location and byte
    # formatting. Reconciliation compares public meaning without moving it.
    legacy = gateway/'earlier-public-proof.json'
    write(legacy,json.dumps(public['authority'],indent=2).encode())
    prior = json.loads(source.read_bytes())
    prior['web'][0]['authority_file']=str(legacy)
    write(source,json.dumps(prior).encode())
    retained=source.read_bytes()
    repeated=register_identity(config_path,row,public['authority'],previous_source_digest='lost-ack')
    assert repeated['status']=='unchanged' and repeated['revision']==result['revision']
    assert source.read_bytes()==retained and json.loads(source.read_bytes())['web'][0]['authority_file']==str(legacy)
    from unittest.mock import patch
    from clusterctl.homes.host import register_companion
    from clusterctl.homes.sessions import Sessions
    from clusterctl.onboarding_conversation import prepare_intent, resolve_request
    from clusterctl.onboarding import digest
    from tests.test_onboarding_conversation import request as conversation_request
    settings=conversation_request()
    settings={key:settings[key] for key in ('human_ref','origin','label','human_id',
        'chat_id','topic_id','port','runtime','execution')}
    settings.update(human_ref=row['human_ref'],label=row['label'])
    request=resolve_request(prepare_intent(plan['name'],digest(plan),settings),row['being_ref'])
    initial_digest=sha(config_path.read_bytes())
    # Invalid/occupied origins are refused before issuing any resource keys.
    for vpn in ('http://invalid.example','https://one.example'):
        with pytest.raises(ValueError):
            register_companion(config_path,request,public,human_name=row['human_name'],
                vpn_url=vpn,previous_digest=initial_digest)
    assert not (gateway/'companion-registrations').exists()
    assert not (gateway/'keys').exists()
    # Lose the owner-registration step after Home config/keys were committed.
    # The next invocation recovers those actual effects with the same keys.
    with patch.object(Sessions,'register_owner',side_effect=RuntimeError('lost step')):
        with pytest.raises(RuntimeError,match='lost step'):
            register_companion(config_path,request,public,human_name=row['human_name'],
                vpn_url='https://private-companion.example',previous_digest=initial_digest)
    preserved=files(gateway/'keys')
    prepared=files(gateway/'companion-registrations')
    result=register_companion(config_path,request,public,human_name=row['human_name'],
        vpn_url='https://private-companion.example',previous_digest=initial_digest)
    assert result['status']=='home-configured' and result['receiving_state']=='unobserved'
    assert result['home_ref']==request['home_ref']
    assert files(gateway/'keys')==preserved
    assert files(gateway/'companion-registrations')==prepared
    assert source.read_bytes()==retained and files(ceremony.root)==native_before
    current=json.loads(config_path.read_bytes())
    assert current['homes']['one']==config['homes']['one']
    home=current['homes'][request['home_ref']]
    from pathlib import Path
    assert all(Path(home[key]).read_text().strip() not in json.dumps(result)
        for key in ('owner_token_file','gateway_token_file'))
    import subprocess
    import sys
    row_file=gateway/'operator-input.json'
    proof_file=gateway/'operator-public-identity.json'
    write(row_file,json.dumps(dict(request=request,human_name=row['human_name'],
        vpn_url='https://private-companion.example')).encode())
    write(proof_file,json.dumps(public).encode())
    cli=subprocess.run([sys.executable,'-m','clusterctl.homes.host','register-companion',
        '--config',str(config_path),'--reference',row['being_ref'],
        '--row',str(row_file),'--authority',str(proof_file),
        '--previous-digest',initial_digest],capture_output=True,text=True,timeout=15)
    assert cli.returncode==0,cli.stderr
    assert json.loads(cli.stdout)==result
    assert files(gateway/'keys')==preserved


def test_unverified_companion_identity_never_changes_selected_source(tmp_path):
    from clusterctl.homes.host import register_identity
    from tests.test_onboarding_target import receiving
    ceremony, plan, target=receiving(tmp_path)
    target.activate(ceremony.authorize_target(plan,target.prepare()))
    target.apply_credential(ceremony.authorize_credential(plan,target.credential_request()))
    public=ceremony.public_identity(plan)
    gateway=tmp_path/'gateway'
    config=configuration(gateway)
    config_path=gateway/'config.json'
    write(config_path,json.dumps(config).encode())
    source=gateway/'identities.json'
    raw=json.dumps(dict(schema='dm.home-identities/v1',telegram_source=None,web=[])).encode()
    write(source,raw)
    row=dict(being_ref=public['authority']['manifest']['being_ref'],label='Companion',
        human_ref='human:telegram:123',human_name='Human',origin=public['origin'],enabled=True)
    write(gateway/'public-proofs.json',json.dumps(target.document_bundle()).encode())
    # The public proof is real, but a new web pair cannot manufacture a
    # Telegram identity. The maintained NativeAuthority validator refuses it.
    with pytest.raises(ValueError,match='home_identity_source_invalid'):
        register_identity(config_path,row,public['authority'],previous_source_digest=sha(raw))
    assert source.read_bytes()==raw
    forged=deepcopy(public['authority'])
    forged['control_head']='forged'
    with pytest.raises(ValueError):
        register_identity(config_path,row,forged,previous_source_digest=sha(raw))
    assert source.read_bytes()==raw


def write(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(0o600)
    return str(path)


def configuration(tmp_path):
    home = {
        "name": "Existing",
        "owner_being_ref": "being-one",
        "owner_revision": "a" * 64,
        "public_url": "https://one.example",
        "vpn_url": "https://private-one.example",
        "backend": "http://127.0.0.1:8801",
        "ring": [],
        "owner_token_file": write(tmp_path / "owner.key", b"fixture-owner"),
        "gateway_token_file": write(tmp_path / "reader.key", b"fixture-reader"),
    }
    return {
        "schema": "dm.resource-access.host/v1",
        "state": str(tmp_path / "state"),
        "binding_source": str(tmp_path / "identities.json"),
        "relationship_store": str(tmp_path / "relationships.db"),
        "authority_source": str(tmp_path / "public-proofs.json"),
        "viewer_port": 8820,
        "owner_port": 8821,
        "content_public_url": "https://artifacts.example",
        "content_vpn_url": "https://private-artifacts.example",
        "homes": {"one": home},
    }


def test_shared_registration_requires_current_owner_and_preserves_other_homes(
    tmp_path, monkeypatch
):
    config = configuration(tmp_path)
    file = tmp_path / "config.json"
    raw = json.dumps(config).encode()
    write(file, raw)

    class Authority:
        def __init__(self, *a, **k):
            pass

        def actor(self, ref):
            return (
                Actor(ref, "being", "a" * 64, "Existing")
                if ref in {"being-one", "another-being"}
                else None
            )

    monkeypatch.setattr("clusterctl.homes.authority.NativeAuthority", Authority)
    new = deepcopy(config["homes"]["one"])
    new.update(public_url="https://two.example", vpn_url="https://private-two.example")
    assert (
        register(file, "two", new, previous_digest=sha(raw))["status"] == "registered"
    )
    assert json.loads(file.read_bytes())["homes"]["one"] == config["homes"]["one"]
    assert register(file, "two", new, previous_digest="old")["status"] == "unchanged"
    changed = deepcopy(new)
    changed["owner_being_ref"] = "another-being"
    with pytest.raises(ValueError, match="owner_conflict"):
        register(file, "two", changed, previous_digest=sha(file.read_bytes()))
    changed = deepcopy(new)
    changed["owner_revision"] = "b" * 64
    with pytest.raises(ValueError, match="current_home_identity"):
        register(file, "two", changed, previous_digest=sha(file.read_bytes()))
    before = file.read_bytes()
    assert (
        register(file, "two", new, previous_digest=sha(before), withdraw=True)["status"]
        == "withdrawn"
    )
    assert "two" not in json.loads(file.read_bytes())["homes"]
    changed = deepcopy(new)
    changed["owner_being_ref"] = "another-being"
    with pytest.raises(ValueError, match="owner_conflict"):
        register(file, "two", changed, previous_digest=sha(file.read_bytes()))
    assert (
        register(file, "two", new, previous_digest=sha(file.read_bytes()))["status"]
        == "registered"
    )
    assert list((tmp_path / "previous").iterdir())


def test_guest_service_upgrade_is_idempotent_and_keeps_actual_rollback(tmp_path):
    binding = {"store": "/home/agent/.local/share/daimon-home"}
    unit = guest_unit(binding)
    assert b"User=agent\n" in unit and b"NoNewPrivileges=true" in unit
    system = tmp_path / "system"
    system.mkdir(mode=0o700)
    state = tmp_path / "state"
    candidate = tmp_path / "candidate"
    write(candidate, unit)
    assert install_service(candidate, None, system_dir=system, state_dir=state)
    assert not install_service(candidate, None, system_dir=system, state_dir=state)
    successor = unit.replace(b"MemoryMax=128M", b"MemoryMax=160M")
    write(candidate, successor)
    with pytest.raises(ValueError, match="preserved"):
        install_service(candidate, "wrong", system_dir=system, state_dir=state)
    assert install_service(candidate, sha(unit), system_dir=system, state_dir=state)
    assert any(path.read_bytes() == unit for path in state.iterdir())
    with pytest.raises(ValueError):
        guest_unit({"store": "/etc"})


def test_existing_proxy_conflict_is_never_replaced():
    devices = {}
    calls = []

    def run(args):
        if args[0] == "query":
            return json.dumps({"devices": devices})
        calls.append(args)
        devices[args[4]] = {
            key: value for key, value in (v.split("=", 1) for v in args[6:])
        }
        devices[args[4]]["type"] = args[5]
        return ""

    desired = {
        "type": "proxy",
        "listen": "tcp:127.0.0.1:8802",
        "connect": "tcp:127.0.0.1:8801",
    }
    assert ensure_proxy(run, "dm-existing", "daimon-home-public", desired)
    assert not ensure_proxy(run, "dm-existing", "daimon-home-public", desired)
    with pytest.raises(ValueError, match="preserved"):
        ensure_proxy(
            run,
            "dm-existing",
            "daimon-home-public",
            {**desired, "connect": "tcp:127.0.0.1:other"},
        )
    assert len(calls) == 1
