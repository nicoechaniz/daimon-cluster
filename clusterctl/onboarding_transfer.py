"""Owner-private archive transport keys; never Matrix identity or custody.

One durable recipient per import slot survives worker/portal restarts and partial
uploads. Ciphertext and receiving writes are never replaced by recipient retry.
"""

from __future__ import annotations

import importlib.util
import os
import stat
import time
import uuid
from pathlib import Path

from . import being_seed as seeds

MAGIC = b"DM-PROTECTED-BEING\x00\x01"


def protection():
    root = seeds.verified_tools()
    spec = importlib.util.spec_from_file_location(
        "cluster_seed_protection", root / "tools/protected_being.py"
    )
    if spec is None or spec.loader is None:
        raise seeds.SeedError("qualified_transfer_tool_required", 503)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _directory(root: Path) -> Path:
    root = seeds._path(root)
    info = root.stat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
    ):
        raise seeds.SeedError("private_transfer_directory_required")
    return root


def _packet(directory: Path, record: dict) -> tuple[Path, dict, str]:
    return _packet_at(directory / "transfer", record)


def _packet_at(path: Path, record: dict) -> tuple[Path, dict, str]:
    root = _directory(path)
    if {item.name for item in root.iterdir()} != {"recipient.json", "private.key"}:
        raise seeds.SeedError("private_transfer_pair_required")
    tool = protection()
    packet = tool.validate_recipient(
        seeds._read(root / "recipient.json"), check_expiry=False
    )
    if packet["name"] != record["name"] or packet["owner"] != record["created_by"]:
        raise seeds.SeedError("transfer_owner_or_seed_mismatch")
    private = tool._owned(root / "private.key", limit=32)
    if len(private) != 32:
        raise seeds.SeedError("private_transfer_key_required")
    _, x25519, _ = tool.crypto()
    pair = x25519.X25519PrivateKey.from_private_bytes(private)
    if tool.encoded(pair.public_key().public_bytes_raw()) != packet["public_key"]:
        raise seeds.SeedError("transfer_recipient_key_mismatch")
    return root, packet, tool.fingerprint(packet)


def read(state: str | Path, name: str, *, owner: str) -> dict:
    directory, record = seeds._record(state, name, owner)
    try:
        _, packet, digest = _packet(directory, record)
    except FileNotFoundError as error:
        raise seeds.SeedError("transfer_recipient_not_found", 404) from error
    return dict(
        recipient=packet,
        recipient_sha256=digest,
        expired=packet["expires_ms"] <= int(time.time() * 1000),
        identity_authority="not granted by transport",
        protected_history="complete private content; live credentials remain separate",
    )


def request(
    state: str | Path, name: str, *, owner: str, expected_being_ref: str | None = None
) -> dict:
    directory, _ = seeds._record(state, name, owner)
    with seeds._locked(directory):
        _, record = seeds._record(state, name, owner)
        if record["mode"] != "import":
            raise seeds.SeedError("transfer_requires_existing_history_import", 409)
        if (directory / "transfer").exists():
            _, packet, _ = _packet(directory, record)
            if packet["expected_being_ref"] != expected_being_ref:
                raise seeds.SeedError("existing_transfer_recipient_preserved", 409)
            return read(state, name, owner=owner)
        if (
            record["phase"] != "awaiting-upload"
            or record.get("upload_sha256") is not None
        ):
            raise seeds.SeedError("transfer_recipient_required_before_upload", 409)
        tool = protection()
        _, x25519, _ = tool.crypto()
        pair = x25519.X25519PrivateKey.generate()
        packet = tool.validate_recipient(
            dict(
                schema=tool.RECIPIENT,
                name=name,
                owner=record["created_by"],
                request_id=str(uuid.uuid4()),
                expected_being_ref=expected_being_ref,
                public_key=tool.encoded(pair.public_key().public_bytes_raw()),
                expires_ms=int(time.time() * 1000) + 7 * 24 * 3600000,
            )
        )
        # Publish the complete pair atomically. Interrupted candidates remain
        # private evidence and can never masquerade as a published recipient.
        candidate = directory / (".transfer-" + uuid.uuid4().hex)
        candidate.mkdir(mode=0o700)
        descriptor = os.open(
            candidate / "private.key", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
        with os.fdopen(descriptor, "wb") as outgoing:
            outgoing.write(pair.private_bytes_raw())
            outgoing.flush()
            os.fsync(outgoing.fileno())
        seeds._write(candidate / "recipient.json", packet)
        os.rename(candidate, directory / "transfer")
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return read(state, name, owner=owner)


def arguments(directory: Path, record: dict) -> list[str]:
    archive = seeds._path(directory / "source.archive")
    with archive.open("rb") as incoming:
        protected = incoming.read(len(MAGIC)) == MAGIC
    if not protected:
        if record.get("transfer_recipient_sha256"):
            raise seeds.SeedError("protected_transfer_format_mismatch")
        return []
    root, _, digest = _packet(directory, record)
    if record.get("transfer_recipient_sha256") != digest:
        raise seeds.SeedError("protected_transfer_recipient_mismatch")
    return [
        "--recipient",
        str(root / "recipient.json"),
        "--recipient-key",
        str(root / "private.key"),
        "--recipient-sha256",
        digest,
    ]
