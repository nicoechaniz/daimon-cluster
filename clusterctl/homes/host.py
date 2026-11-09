"""Shared gateway registration and body service assets, with preserved rollback.

The accepted host worker dispatches these operations; browser/reader/owner-local
publication credentials cannot register or withdraw another home.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from urllib.parse import urlsplit

from .provision import regular, replace, sha
from .service import validate_config
from .registry import Registry
from .sessions import Sessions


def guest_unit(binding):
    store = Path(binding["store"])
    if (
        not store.is_absolute()
        or not store.is_relative_to("/home/agent")
        or ".." in store.parts
        or any(c in str(store) for c in ("\n", "\r", "%", '"'))
    ):
        raise ValueError("owned_guest_artifact_store_required")
    return (
        "[Unit]\nDescription=Selected Daimon home artifact broker\nAfter=network.target\n"
        "[Service]\nUser=agent\nGroup=agent\nUMask=0077\n"
        "ExecStart=/home/agent/.local/bin/daimon-home serve\n"
        "Restart=on-failure\nRestartSec=3\nNoNewPrivileges=true\n"
        "ProtectSystem=strict\nProtectHome=read-only\nPrivateTmp=true\n"
        f"ReadWritePaths={store}\nMemoryMax=128M\nTasksMax=48\n"
        "StandardOutput=null\nStandardError=null\n[Install]\nWantedBy=multi-user.target\n"
    ).encode()


def ensure_proxy(run, instance, name, desired):
    observed = json.loads(run(["query", "/1.0/instances/" + instance]))
    current = observed.get("devices", {}).get(name)
    if current is not None:
        if current != desired:
            raise ValueError("existing_home_proxy_preserved")
        return False
    run(
        [
            "config",
            "device",
            "add",
            instance,
            name,
            "proxy",
            *[key + "=" + value for key, value in desired.items() if key != "type"],
        ]
    )
    observed = json.loads(run(["query", "/1.0/instances/" + instance]))
    if observed.get("devices", {}).get(name) != desired:
        raise ValueError("home_proxy_delivery_unconfirmed")
    return True


def register(config_path, reference, home, *, previous_digest, withdraw=False):
    """Run as the gateway owner: preserve identities and exact prior config."""
    from .authority import NativeAuthority

    original = regular(config_path)
    info = Path(config_path).stat()
    if info.st_mode & 0o077:
        raise ValueError("private_gateway_configuration_required")
    config = validate_config(json.loads(original))
    registry = Registry(Sessions(Path(config["state"])))
    for retained_ref, retained_home in config["homes"].items():
        registry.bind_home(retained_ref, retained_home["owner_being_ref"])
    old = config["homes"].get(reference)
    if withdraw:
        if old is None:
            return {"status": "unchanged", "digest": sha(original)}
        if home is None or old["owner_being_ref"] != home["owner_being_ref"]:
            raise ValueError("home_withdrawal_owner_conflict")
        del config["homes"][reference]
    else:
        if old and old["owner_being_ref"] != home["owner_being_ref"]:
            raise ValueError("home_gateway_owner_conflict")
        if old == home:
            return {"status": "unchanged", "digest": sha(original)}
        proposed = {**config["homes"], reference: home}
        # Reuse current verified identities/pairing; names do not register an
        # actor, and host placement never fabricates tribal membership.
        authority = NativeAuthority(
            Path(config["binding_source"]),
            Path(config["relationship_store"]),
            proposed,
            authority_source=Path(config["authority_source"]),
        )
        actor = authority.actor(home["owner_being_ref"])
        if (
            not actor
            or actor.kind != "being"
            or actor.revision != home["owner_revision"]
        ):
            raise ValueError("current_home_identity_binding_required")
        config["homes"] = proposed
    validate_config(config)
    if sha(original) != previous_digest:
        raise ValueError("concurrent_gateway_configuration_preserved")
    if not withdraw:
        registry.bind_home(reference, home["owner_being_ref"])
    raw = (json.dumps(config, sort_keys=True, indent=2) + "\n").encode()
    backups = Path(config_path).parent / "previous"
    backups.mkdir(mode=0o700, exist_ok=True)
    replace(
        Path(config_path),
        raw,
        previous=previous_digest,
        home=Path(config_path).parent,
        backups=backups,
    )
    return {"status": "withdrawn" if withdraw else "registered", "digest": sha(raw)}


def register_identity(config_path, row, authority, *, previous_source_digest):
    """Append one operator-selected web pair using its signed native proof.

    This is the existing gateway identity source, not a parallel login store.
    It creates no Home, session, account, key, model input or Tribe membership.
    Existing pairings and public proof revisions cannot be replaced here.
    """
    import fcntl
    import os
    import tempfile
    from daimon_matrix.operator_rebirth import authority_from_document, RebirthError
    from .authority import NativeAuthority
    from .provision import directory

    if not isinstance(row, dict) or set(row) != {
            'being_ref', 'label', 'human_ref', 'human_name', 'origin', 'enabled'}:
        raise ValueError('home_web_identity_required')
    encoded = (json.dumps(authority, sort_keys=True) + '\n').encode()
    if len(encoded) > 4*1024*1024:
        raise ValueError('home_public_identity_capacity')
    try:
        verified = authority_from_document(authority)
        verified.validate_origin(row['origin'], require_active=True)
    except (RebirthError, ValueError, KeyError, TypeError):
        raise ValueError('home_native_identity_refused') from None
    if verified.manifest.being_ref != row['being_ref'] or row['enabled'] is not True:
        raise ValueError('home_identity_source_mismatch')
    config_raw = regular(config_path)
    if Path(config_path).stat().st_mode & 0o077:
        raise ValueError('private_gateway_configuration_required')
    config = validate_config(json.loads(config_raw))
    source = Path(config['binding_source'])
    def current_source():
        original = regular(source)
        if len(original)>256*1024:
            raise ValueError('home_identity_source_capacity')
        declaration = json.loads(original)
        if (not isinstance(declaration, dict)
                or set(declaration) != {'schema', 'telegram_source', 'web'}
                or declaration['schema'] != 'dm.home-identities/v1'
                or not isinstance(declaration['web'], list)
                or any(not isinstance(item,dict) for item in declaration['web'])):
            raise ValueError('selected_web_identity_source_required')
        return original, declaration

    def retained(original, declaration):
        old = [item for item in declaration['web'] if item.get('being_ref') == row['being_ref']]
        if not old:
            return None
        if (len(old) != 1 or {k:v for k,v in old[0].items() if k != 'authority_file'} != row
                or json.loads(regular(Path(old[0]['authority_file']))) != authority):
            raise ValueError('existing_home_identity_preserved')
        resolver = NativeAuthority(source, Path(config['relationship_store']),
            config['homes'], authority_source=Path(config['authority_source']))
        actor = resolver.actor(row['being_ref'])
        if actor is None or actor.kind != 'being':
            raise ValueError('current_home_identity_binding_required')
        if regular(source) != original or regular(config_path) != config_raw:
            raise ValueError('concurrent_home_identity_source_preserved')
        return dict(status='unchanged', digest=sha(original), actor=actor.ref, revision=actor.revision)

    original, declaration = current_source()
    result = retained(original,declaration)
    if result is not None:
        return result  # Existing registrations reconcile without even a lock file.
    if sha(original) != previous_source_digest:
        raise ValueError('concurrent_home_identity_source_preserved')
    root = source.parent
    storage = root/'registered-home-identities'
    directory(storage, root)
    lock_path = storage/'registration.lock'
    fd = os.open(lock_path, os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'a+b') as lock:
        regular(lock_path)
        fcntl.flock(lock, fcntl.LOCK_EX)
        original, declaration = current_source()
        result = retained(original,declaration)
        if result is not None:
            return result
        proof = storage/(sha(encoded)+'.json')
        candidate = {**row, 'authority_file': str(proof)}
        if sha(original) != previous_source_digest:
            raise ValueError('concurrent_home_identity_source_preserved')
        if len(declaration['web']) >= 16:
            raise ValueError('home_identity_source_capacity')
        proofs = list(storage.iterdir())
        if (any(p.is_symlink() or not p.is_file() for p in proofs)
                or len(proofs) >= 18
                or sum(p.stat().st_size for p in proofs)+len(encoded) > 64*1024*1024):
            raise ValueError('home_public_identity_capacity')
        backups = root/'previous'
        directory(backups, root)
        replace(proof, encoded, previous=None, home=root, backups=backups)
        proposed = {**declaration, 'web': [*declaration['web'], candidate]}
        raw = (json.dumps(proposed, sort_keys=True, indent=2)+'\n').encode()
        if len(raw)>256*1024:
            raise ValueError('home_identity_source_capacity')
        # Reuse the maintained exact human/origin/authority validation before
        # changing the selected source. A failed proposal leaves it unchanged.
        with tempfile.TemporaryDirectory(prefix='.home-identity-', dir=root) as temporary:
            pending = Path(temporary)/'identities.json'
            pending.write_bytes(raw)
            pending.chmod(0o600)
            resolver = NativeAuthority(pending, Path(config['relationship_store']),
                config['homes'], authority_source=Path(config['authority_source']))
            actor = resolver.actor(row['being_ref'])
            if actor is None or actor.kind != 'being':
                raise ValueError('current_home_identity_binding_required')
        if regular(config_path) != config_raw:
            raise ValueError('concurrent_gateway_configuration_preserved')
        replace(source, raw, previous=previous_source_digest, home=root, backups=backups)
        return dict(status='identity-registered', digest=sha(raw),
                    actor=actor.ref, revision=actor.revision)


def accept_owner_authority(config_path, reference, *, previous_digest):
    """Explicit host operation; retain key bytes, actor, home and base revision."""
    from .authority import NativeAuthority
    from .service import private_text

    original = regular(config_path)
    if Path(config_path).stat().st_mode & 0o077 or sha(original) != previous_digest:
        raise ValueError("concurrent_gateway_configuration_preserved")
    config = validate_config(json.loads(original))
    home = config["homes"][reference]
    authority = NativeAuthority(
        Path(config["binding_source"]), Path(config["relationship_store"]),
        config["homes"], authority_source=Path(config["authority_source"]),
    )
    # Includes current signed-history validation and all consumed public pins.
    authority.authorities()
    actor = authority.actor(home["owner_being_ref"])
    if not actor or actor.kind != "being" or not actor.enabled:
        raise ValueError("current_home_identity_binding_required")
    if regular(config_path) != original:
        raise ValueError("concurrent_gateway_configuration_preserved")
    Sessions(Path(config["state"])).accept_owner_authority(
        private_text(home["owner_token_file"]), home=reference, subject=actor,
        binding_revision=home["owner_revision"],
    )
    return {"status": "authority-accepted", "home": reference,
            "actor": actor.ref, "revision": actor.revision,
            "config_digest": sha(original)}


def register_companion(config_path, request, public, *, human_name, vpn_url, previous_digest):
    """Compose the existing identity/Home/owner writers for one new companion.

    The private intent retains the same resource keys through uncertain effects.
    No guest, HTTPS route, browser session or model is started by registration.
    """
    import secrets
    from .. import being_seed
    from ..onboarding_conversation import selection
    from .authority import NativeAuthority
    from .provision import directory
    from .service import private_text

    selection(request)  # An unresolved intent cannot issue a Home credential.
    if len(json.dumps(request).encode())>65536:
        raise ValueError('companion_registration_capacity')
    if (not isinstance(public,dict) or set(public)!={'authority','origin'}
            or public['authority'].get('manifest',{}).get('being_ref')!=request['being_ref']):
        raise ValueError('home_native_identity_refused')
    config_path=Path(config_path)
    original=regular(config_path)
    config=validate_config(json.loads(original))
    reference=request['home_ref']
    home=config['homes'].get(reference)
    vpn=urlsplit(vpn_url)
    if (vpn.scheme!='https' or not vpn.hostname or vpn.username or vpn.password
            or vpn.path or vpn.query or vpn.fragment):
        raise ValueError('home_requires_exact_https_origin')
    if home is None:
        origins={urlsplit(config[key]).netloc for key in ('content_public_url','content_vpn_url')}
        origins.update(urlsplit(item[key]).netloc for item in config['homes'].values()
            for key in ('public_url','vpn_url'))
        new_origins={urlsplit(request['origin']).netloc,vpn.netloc}
        if len(new_origins)!=2 or new_origins & origins:
            raise ValueError('unique_home_content_origins_required')
    if home is None and sha(original)!=previous_digest:
        raise ValueError('concurrent_gateway_configuration_preserved')
    if home is not None and any(home[key]!=expected for key,expected in {
            'owner_being_ref':request['being_ref'],'name':request['label'],
            'public_url':request['origin'],'vpn_url':vpn_url}.items()):
        raise ValueError('existing_companion_home_preserved')
    identity_row=dict(being_ref=request['being_ref'],label=request['label'],
        human_ref=request['human_ref'],human_name=human_name,origin=public['origin'],enabled=True)
    source=Path(config['binding_source'])
    identity=register_identity(config_path,identity_row,public['authority'],
        previous_source_digest=sha(regular(source)))
    if home is None:
        root=config_path.parent
        state=root/'companion-registrations'
        directory(state,root)
        # A bounded private intent, not another account or credential service.
        lock=state/reference.removeprefix('home:')
        with being_seed._locked(state):
            size=0
            for index,path in enumerate(state.rglob('*')):
                if index>=64 or path.is_symlink() or not (path.is_file() or path.is_dir()):
                    raise ValueError('companion_registration_capacity')
                if path.is_file():
                    size+=path.stat().st_size
                if size>1024*1024:
                    raise ValueError('companion_registration_capacity')
            if not lock.exists() and len([p for p in state.iterdir() if p.is_dir()])>=16:
                raise ValueError('companion_registration_capacity')
            directory(lock,root)
        with being_seed._locked(lock):
            pins=sha(json.dumps(dict(request=request,public=public,
                human_name=human_name,vpn_url=vpn_url),sort_keys=True).encode())
            intent_path=lock/'intent.json'
            backups=root/'previous'
            directory(backups,root)
            if intent_path.exists():
                intent=json.loads(regular(intent_path))
                if (set(intent)!={'schema','pins','owner_key','gateway_key'}
                        or intent['schema']!='dm.companion-home-intent/v1' or intent['pins']!=pins
                        or any(not isinstance(intent[k],str) or len(intent[k])!=43
                            for k in ('owner_key','gateway_key'))):
                    raise ValueError('existing_companion_intent_preserved')
            else:
                intent=dict(schema='dm.companion-home-intent/v1',pins=pins,
                    owner_key=secrets.token_urlsafe(32),gateway_key=secrets.token_urlsafe(32))
                replace(intent_path,(json.dumps(intent,sort_keys=True)+'\n').encode(),
                    previous=None,home=root,backups=backups)
            keys=root/'keys'
            directory(keys,root)
            paths={}
            for field in ('owner','gateway'):
                path=keys/('companion-'+reference.removeprefix('home:')+'-'+field+'.key')
                replace(path,(intent[field+'_key']+'\n').encode(),previous=None,home=root,backups=backups)
                paths[field+'_token_file']=str(path)
            home=dict(name=request['label'],owner_being_ref=request['being_ref'],
                owner_revision=identity['revision'],public_url=request['origin'],vpn_url=vpn_url,
                backend=None,ring=[],**paths)
            register(config_path,reference,home,previous_digest=sha(original))
    resolver=NativeAuthority(source,Path(config['relationship_store']),
        {**config['homes'],reference:home},authority_source=Path(config['authority_source']))
    actor=resolver.actor(request['being_ref'])
    sessions=Sessions(Path(config['state']))
    token=private_text(home['owner_token_file'])
    # INSERT OR IGNORE retains the original credential after a lost reply.
    sessions.register_owner(home=reference,actor=request['being_ref'],
        revision=home['owner_revision'],token=token)
    if not sessions.owner(token,home=reference,subject=actor,binding_revision=home['owner_revision']):
        raise ValueError('current_home_identity_binding_required')
    return dict(status='home-configured',home_ref=reference,actor=request['being_ref'],
        human_ref=request['human_ref'],revision=actor.revision,
        config_digest=sha(regular(config_path)),receiving_state='unobserved')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("register", "withdraw", "accept-owner-authority", "register-identity", "register-companion"))
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--row", type=Path)
    parser.add_argument("--authority", type=Path)
    parser.add_argument("--previous-digest", required=True)
    args = parser.parse_args()
    try:
        if args.operation == 'register-companion':
            if args.row is None or args.authority is None:
                raise ValueError('home_web_identity_required')
            value=json.loads(regular(args.row))
            if (set(value)!={'request','human_name','vpn_url'}
                    or value['request'].get('being_ref')!=args.reference):
                raise ValueError('home_identity_source_mismatch')
            print(json.dumps(register_companion(args.config,value['request'],
                json.loads(regular(args.authority)),human_name=value['human_name'],
                vpn_url=value['vpn_url'],previous_digest=args.previous_digest)))
            return
        if args.operation == 'register-identity':
            if args.row is None or args.authority is None:
                raise ValueError('home_web_identity_required')
            row = json.loads(regular(args.row))
            if row.get('being_ref') != args.reference:
                raise ValueError('home_identity_source_mismatch')
            print(json.dumps(register_identity(args.config, row,
                json.loads(regular(args.authority)), previous_source_digest=args.previous_digest)))
            return
        if args.authority is not None:
            raise ValueError('home_identity_source_operation_required')
        if args.operation == "accept-owner-authority":
            if args.row is not None:
                raise ValueError("owner_authority_uses_existing_home")
            print(json.dumps(accept_owner_authority(
                args.config, args.reference, previous_digest=args.previous_digest,
            )))
            return
        if args.row is None:
            raise ValueError("home_row_required")
        home = json.loads(regular(args.row))
        result = register(
            args.config,
            args.reference,
            home,
            previous_digest=args.previous_digest,
            withdraw=args.operation == "withdraw",
        )
        print(json.dumps(result))
    except (ValueError, OSError, KeyError, RuntimeError, TypeError, AttributeError):
        print(
            json.dumps(
                {"status": "refused", "reason": "home_gateway_integrity_required"}
            )
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
