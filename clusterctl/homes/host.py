"""Shared gateway registration and body service assets, with preserved rollback.

The accepted host worker dispatches these operations; browser/reader/owner-local
publication credentials cannot register or withdraw another home.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("register", "withdraw", "accept-owner-authority"))
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--row", type=Path)
    parser.add_argument("--previous-digest", required=True)
    args = parser.parse_args()
    try:
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
    except (ValueError, OSError, KeyError):
        print(
            json.dumps(
                {"status": "refused", "reason": "home_gateway_integrity_required"}
            )
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
