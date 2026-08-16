"""Shared, signed admission authority for embodiment launch fencing.

The authority owns the only mutable database and signing key.  Hosts connect
through an owner-only Unix socket and prove possession of an explicitly
enrolled holder key.  The exclusion key is exactly ``(being_ref,
embodiment_id)``: two legitimate embodiments of one being do not contend,
while two copies of one embodiment do.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import socketserver
import stat
import threading
import uuid
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from .fences import Ed25519Signer, FenceError
from .production_fences import (
    MAX_FENCE_TTL_S,
    ProductionFenceStore,
    _verify_ed25519,
    create_holder_authorization,
    ed25519_fingerprint,
)

REQUEST_SCHEMA = "dm.cluster.admission-request/v1"
RESPONSE_SCHEMA = "dm.cluster.admission-response/v1"
RECEIPT_SCHEMA = "dm.cluster.admission-receipt/v1"
MAX_MESSAGE_BYTES = 1024 * 1024
DEFAULT_LEASE_TTL_S = 15


class AdmissionError(RuntimeError):
    """Stable failure at the shared admission boundary."""


class AdmissionConflict(AdmissionError):
    """Another live holder owns the exact embodiment coordinate."""


class AdmissionUnavailable(AdmissionError):
    """The authority could not be reached or returned an invalid response."""


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        {key: item for key, item in value.items() if key != "signature"},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def admission_resource_ref(being_ref: str, embodiment_id: str) -> str:
    """Return a collision-resistant resource name for the exact logical key."""

    if not isinstance(being_ref, str) or not being_ref:
        raise AdmissionError("admission being reference is invalid")
    if not isinstance(embodiment_id, str) or not embodiment_id:
        raise AdmissionError("admission embodiment id is invalid")
    encoded = json.dumps(
        [being_ref, embodiment_id], ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return "embodiment-admission:sha256:" + hashlib.sha256(encoded).hexdigest()


def _lease_expiry(evidence: Mapping[str, Any]) -> int:
    created = evidence.get("created_ms")
    ttl_s = evidence.get("ttl_s")
    if (
        isinstance(created, bool)
        or not isinstance(created, int)
        or isinstance(ttl_s, bool)
        or not isinstance(ttl_s, int)
        or ttl_s < 0
    ):
        raise AdmissionError("admission evidence time is invalid")
    return created + ttl_s * 1000


class AdmissionAuthority:
    """Key-owning dispatcher.  Keep this object inside the authority process."""

    def __init__(
        self,
        state_dir: str | Path,
        *,
        signer: Ed25519Signer,
        holder_registrars: Mapping[str, str],
        database_path: str | Path | None = None,
        clock: Callable[[], int] | None = None,
    ):
        self._signer = signer
        arguments: dict[str, Any] = {
            "signer": signer,
            "key_id": signer.key_id,
            "database_path": database_path,
            "holder_registrars": holder_registrars,
        }
        if clock is not None:
            arguments["clock"] = clock
        self._store = ProductionFenceStore(state_dir, **arguments)

    @property
    def authority_key_id(self) -> str:
        return self._signer.key_id

    @property
    def authority_public_key(self) -> str:
        return self._signer.public_key

    def _binding(self, request: Mapping[str, Any]) -> dict[str, Any]:
        holder_key_id = request.get("holder_key_id")
        if not isinstance(holder_key_id, str) or not holder_key_id:
            raise AdmissionError("admission holder key id is invalid")
        binding = self._store.holder_binding(holder_key_id)
        expected = {
            key: request.get(key)
            for key in (
                "being_ref",
                "body_ref",
                "embodiment_id",
                "incarnation_id",
                "activation_id",
                "credential_id",
                "manifest_hash",
            )
        }
        if any(binding.get(key) != value for key, value in expected.items()):
            raise AdmissionError("admission holder binding mismatch")
        if binding["holder_pubkey"] != request.get("holder_pubkey"):
            raise AdmissionError("admission holder public key mismatch")
        return binding

    def _receipt(
        self,
        action: str,
        binding: Mapping[str, Any],
        evidence: Mapping[str, Any],
        session_id: str,
    ) -> dict[str, Any]:
        resource_ref = admission_resource_ref(
            str(binding["being_ref"]), str(binding["embodiment_id"])
        )
        if evidence.get("resource_ref") != resource_ref:
            raise AdmissionError("admission evidence resource mismatch")
        if any(
            evidence.get(field) != binding[binding_field]
            for field, binding_field in (
                ("body_ref", "body_ref"),
                ("holder_embodiment_id", "embodiment_id"),
                ("holder_incarnation_id", "incarnation_id"),
                ("holder_key_id", "holder_key_id"),
            )
        ):
            raise AdmissionError("admission evidence holder mismatch")
        if evidence.get("renewer") != f"admission-session:{session_id}":
            raise AdmissionError("admission evidence session mismatch")
        value: dict[str, Any] = {
            "schema": RECEIPT_SCHEMA,
            "action": action,
            "being_ref": binding["being_ref"],
            "body_ref": binding["body_ref"],
            "embodiment_id": binding["embodiment_id"],
            "incarnation_id": binding["incarnation_id"],
            "activation_id": binding["activation_id"],
            "credential_id": binding["credential_id"],
            "manifest_hash": binding["manifest_hash"],
            "holder_key_id": binding["holder_key_id"],
            "session_id": session_id,
            "resource_ref": resource_ref,
            "fencing_token": evidence["epoch"],
            "proof_ref": self._store.proof_ref(dict(evidence)),
            "lease_expires_at_ms": _lease_expiry(evidence),
            "evidence": dict(evidence),
            "authority_key_id": self._signer.key_id,
        }
        value["signature"] = self._signer.sign(_canonical(value))
        return value

    def dispatch(self, request: Mapping[str, Any]) -> dict[str, Any]:
        if request.get("schema") != REQUEST_SCHEMA:
            raise AdmissionError("admission request schema is unsupported")
        action = request.get("action")
        if action == "enroll":
            enrollment = request.get("enrollment")
            if not isinstance(enrollment, dict):
                raise AdmissionError("admission enrollment is missing")
            return self._store.admit_holder(enrollment)
        if action == "position":
            resource_ref = admission_resource_ref(
                str(request.get("being_ref", "")),
                str(request.get("embodiment_id", "")),
            )
            return self._store.position(resource_ref)
        if action == "current":
            binding = self._binding(request)
            session_id = request.get("session_id")
            if not isinstance(session_id, str) or not session_id:
                raise AdmissionError("admission session id is invalid")
            resource_ref = admission_resource_ref(
                str(binding["being_ref"]), str(binding["embodiment_id"])
            )
            evidence = self._store.verify_current(resource_ref)
            if evidence is None:
                return {"current": False, "resource_ref": resource_ref}
            if evidence.get("renewer") != f"admission-session:{session_id}":
                return {"current": False, "resource_ref": resource_ref}
            return {
                "current": True,
                "receipt": self._receipt("current", binding, evidence, session_id),
            }
        if action not in {"acquire", "renew", "release"}:
            raise AdmissionError("admission action is unsupported")
        binding = self._binding(request)
        session_id = request.get("session_id")
        if not isinstance(session_id, str) or not session_id:
            raise AdmissionError("admission session id is invalid")
        resource_ref = admission_resource_ref(
            str(binding["being_ref"]), str(binding["embodiment_id"])
        )
        authorization = request.get("authorization")
        expected_epoch = request.get("expected_epoch")
        expected_proof = request.get("expected_proof")
        if action == "acquire":
            evidence = self._store.acquire(
                resource_ref,
                str(binding["holder_pubkey"]),
                ed25519_fingerprint(str(binding["holder_pubkey"])),
                ttl_s=request.get("ttl_s", DEFAULT_LEASE_TTL_S),
                renewer=f"admission-session:{session_id}",
                holder_embodiment_id=str(binding["embodiment_id"]),
                body_ref=str(binding["body_ref"]),
                holder_incarnation_id=str(binding["incarnation_id"]),
                holder_key_id=str(binding["holder_key_id"]),
                expected_epoch=expected_epoch,
                expected_proof=expected_proof,
                authorization=authorization if isinstance(authorization, dict) else None,
            )
        elif action == "renew":
            current = self._store.get(resource_ref)
            if (
                current is None
                or current.get("renewer") != f"admission-session:{session_id}"
            ):
                raise AdmissionConflict("admission session does not own the lease")
            evidence = self._store.renew(
                resource_ref,
                new_ttl_s=request.get("ttl_s", DEFAULT_LEASE_TTL_S),
                expected_epoch=expected_epoch,
                expected_proof=expected_proof,
                authorization=authorization if isinstance(authorization, dict) else None,
            )
        else:
            current = self._store.get(resource_ref)
            if (
                current is None
                or current.get("renewer") != f"admission-session:{session_id}"
            ):
                raise AdmissionConflict("admission session does not own the lease")
            evidence = self._store.release(
                resource_ref,
                expected_epoch=expected_epoch,
                expected_proof=expected_proof,
                authorization=authorization if isinstance(authorization, dict) else None,
            )
        if evidence is None:
            raise AdmissionError("admission mutation returned no evidence")
        return self._receipt(str(action), binding, evidence, session_id)


class _AdmissionRequestHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        raw = self.rfile.readline(MAX_MESSAGE_BYTES + 1)
        if not raw or len(raw) > MAX_MESSAGE_BYTES or not raw.endswith(b"\n"):
            return
        request_id: str | None = None
        try:
            request = json.loads(raw)
            if not isinstance(request, dict):
                raise AdmissionError("admission request is malformed")
            candidate = request.get("request_id")
            request_id = candidate if isinstance(candidate, str) else None
            result = self.server.authority.dispatch(request)  # type: ignore[attr-defined]
            response = {
                "schema": RESPONSE_SCHEMA,
                "request_id": request_id,
                "ok": True,
                "result": result,
            }
        except (AdmissionError, FenceError, KeyError, TypeError, ValueError) as exception:
            name = type(exception).__name__
            response = {
                "schema": RESPONSE_SCHEMA,
                "request_id": request_id,
                "ok": False,
                "error": name,
                "message": str(exception),
            }
        self.wfile.write(
            json.dumps(response, sort_keys=True, separators=(",", ":")).encode("utf-8")
            + b"\n"
        )


class AdmissionServer(socketserver.ThreadingUnixStreamServer):
    """Owner-only Unix service around one shared admission authority."""

    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, socket_path: str | Path, authority: AdmissionAuthority):
        self.socket_path = Path(os.path.abspath(socket_path))
        parent = self.socket_path.parent
        parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        info = parent.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise AdmissionError("admission socket directory is not owner-only")
        if self.socket_path.exists() or self.socket_path.is_symlink():
            raise AdmissionError("admission socket path already exists")
        self.authority = authority
        super().__init__(str(self.socket_path), _AdmissionRequestHandler)
        self.socket_path.chmod(0o600)

    def get_request(self) -> tuple[socket.socket, Any]:
        connection, address = super().get_request()
        if hasattr(socket, "SO_PEERCRED"):
            import struct

            credentials = connection.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
            )
            _pid, uid, _gid = struct.unpack("3i", credentials)
            if uid != os.geteuid():
                connection.close()
                raise AdmissionError("admission peer uid is unauthorized")
        return connection, address

    def server_close(self) -> None:
        super().server_close()
        try:
            self.socket_path.unlink()
        except FileNotFoundError:
            pass


class AdmissionClient:
    """Holder-only client; contains neither authority signing key nor database."""

    def __init__(
        self,
        socket_path: str | Path,
        *,
        holder_signer: Ed25519Signer,
        authority_key_id: str,
        authority_public_key: str,
        being_ref: str,
        body_ref: str,
        embodiment_id: str,
        incarnation_id: str,
        activation_id: str,
        credential_id: str,
        manifest_hash: str,
        timeout_s: float = 2.0,
        lease_ttl_s: int = DEFAULT_LEASE_TTL_S,
        session_id: str | None = None,
    ):
        if timeout_s <= 0 or timeout_s > 30:
            raise AdmissionError("admission client timeout is invalid")
        if (
            isinstance(lease_ttl_s, bool)
            or not isinstance(lease_ttl_s, int)
            or not 3 <= lease_ttl_s <= 300
        ):
            raise AdmissionError("admission client lease TTL is invalid")
        self.socket_path = Path(os.path.abspath(socket_path))
        self.holder_signer = holder_signer
        self.authority_key_id = authority_key_id
        self.authority_public_key = authority_public_key
        self.being_ref = being_ref
        self.body_ref = body_ref
        self.embodiment_id = embodiment_id
        self.incarnation_id = incarnation_id
        self.activation_id = activation_id
        self.credential_id = credential_id
        self.manifest_hash = manifest_hash
        self.timeout_s = timeout_s
        self.lease_ttl_s = lease_ttl_s
        self.session_id = str(uuid.uuid4()) if session_id is None else session_id
        if not self.session_id or any(character.isspace() for character in self.session_id):
            raise AdmissionError("admission client session id is invalid")

    def _coordinates(self) -> dict[str, Any]:
        return {
            "holder_key_id": self.holder_signer.key_id,
            "holder_pubkey": self.holder_signer.public_key,
            "being_ref": self.being_ref,
            "body_ref": self.body_ref,
            "embodiment_id": self.embodiment_id,
            "incarnation_id": self.incarnation_id,
            "activation_id": self.activation_id,
            "credential_id": self.credential_id,
            "manifest_hash": self.manifest_hash,
            "session_id": self.session_id,
        }

    def _call(self, action: str, **values: Any) -> Any:
        request_id = str(uuid.uuid4())
        request = {
            "schema": REQUEST_SCHEMA,
            "request_id": request_id,
            "action": action,
            **values,
        }
        encoded = json.dumps(request, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        ) + b"\n"
        if len(encoded) > MAX_MESSAGE_BYTES:
            raise AdmissionError("admission request is too large")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self.timeout_s)
                connection.connect(str(self.socket_path))
                connection.sendall(encoded)
                chunks = bytearray()
                while not chunks.endswith(b"\n"):
                    chunk = connection.recv(65536)
                    if not chunk:
                        break
                    chunks.extend(chunk)
                    if len(chunks) > MAX_MESSAGE_BYTES:
                        raise AdmissionUnavailable("admission response is too large")
        except (OSError, TimeoutError) as exception:
            raise AdmissionUnavailable("admission authority is unavailable") from exception
        try:
            response = json.loads(chunks)
        except (json.JSONDecodeError, UnicodeDecodeError) as exception:
            raise AdmissionUnavailable("admission response is malformed") from exception
        if (
            not isinstance(response, dict)
            or response.get("schema") != RESPONSE_SCHEMA
            or response.get("request_id") != request_id
        ):
            raise AdmissionUnavailable("admission response binding mismatch")
        if response.get("ok") is not True:
            if response.get("error") in {"AdmissionConflict", "FenceConflict"}:
                raise AdmissionConflict(str(response.get("message")))
            raise AdmissionError(str(response.get("message", "admission refused")))
        return response.get("result")

    def enroll(self, enrollment: dict[str, Any]) -> dict[str, Any]:
        result = self._call("enroll", enrollment=enrollment)
        if not isinstance(result, dict) or result.get("admitted") is not True:
            raise AdmissionUnavailable("admission enrollment response is invalid")
        return result

    def _position(self) -> dict[str, Any]:
        result = self._call(
            "position", being_ref=self.being_ref, embodiment_id=self.embodiment_id
        )
        if (
            not isinstance(result, dict)
            or not isinstance(result.get("epoch"), int)
            or result.get("resource_ref")
            != admission_resource_ref(self.being_ref, self.embodiment_id)
        ):
            raise AdmissionUnavailable("admission position response is invalid")
        return result

    def _mutation(self, action: str, *, ttl_s: int | None = None) -> dict[str, Any]:
        position = self._position()
        resource_ref = str(position["resource_ref"])
        authorization = create_holder_authorization(
            self.holder_signer,
            operation=action,
            body_ref=self.body_ref,
            embodiment_id=self.embodiment_id,
            incarnation_id=self.incarnation_id,
            resource_ref=resource_ref,
            expected_epoch=position["epoch"],
            expected_proof=position.get("proof"),
            nonce=str(uuid.uuid4()),
        )
        values = {
            **self._coordinates(),
            "expected_epoch": position["epoch"],
            "expected_proof": position.get("proof"),
            "authorization": authorization,
        }
        if ttl_s is not None:
            if not 1 <= ttl_s <= MAX_FENCE_TTL_S:
                raise AdmissionError("admission lease TTL is out of bounds")
            values["ttl_s"] = ttl_s
        result = self._call(action, **values)
        return self.verify_receipt(result, expected_action=action)

    def acquire(self, *, ttl_s: int = DEFAULT_LEASE_TTL_S) -> dict[str, Any]:
        return self._mutation("acquire", ttl_s=ttl_s)

    def renew(self, *, ttl_s: int = DEFAULT_LEASE_TTL_S) -> dict[str, Any]:
        return self._mutation("renew", ttl_s=ttl_s)

    def release(self) -> dict[str, Any]:
        return self._mutation("release")

    def current(self) -> dict[str, Any] | None:
        result = self._call("current", **self._coordinates())
        if not isinstance(result, dict) or not isinstance(result.get("current"), bool):
            raise AdmissionUnavailable("admission current response is invalid")
        if result["current"] is False:
            return None
        return self.verify_receipt(result.get("receipt"), expected_action="current")

    def verify_receipt(
        self, receipt: Any, *, expected_action: str | None = None
    ) -> dict[str, Any]:
        if not isinstance(receipt, dict) or receipt.get("schema") != RECEIPT_SCHEMA:
            raise AdmissionUnavailable("admission receipt is malformed")
        expected = {
            **{
                key: value
                for key, value in self._coordinates().items()
                if key != "holder_pubkey"
            },
            "resource_ref": admission_resource_ref(self.being_ref, self.embodiment_id),
            "authority_key_id": self.authority_key_id,
        }
        if any(receipt.get(key) != value for key, value in expected.items()):
            raise AdmissionUnavailable("admission receipt binding mismatch")
        if expected_action is not None and receipt.get("action") != expected_action:
            raise AdmissionUnavailable("admission receipt action mismatch")
        signature = receipt.get("signature")
        if not isinstance(signature, str) or not _verify_ed25519(
            _canonical(receipt), signature, self.authority_public_key
        ):
            raise AdmissionUnavailable("admission receipt signature is invalid")
        evidence = receipt.get("evidence")
        if (
            not isinstance(evidence, dict)
            or evidence.get("resource_ref") != expected["resource_ref"]
            or evidence.get("epoch") != receipt.get("fencing_token")
            or ProductionFenceStore.proof_ref(evidence) != receipt.get("proof_ref")
            or _lease_expiry(evidence) != receipt.get("lease_expires_at_ms")
        ):
            raise AdmissionUnavailable("admission receipt evidence is inconsistent")
        return dict(receipt)


def serve_in_thread(server: AdmissionServer) -> threading.Thread:
    """Start a disposable authority server; primarily useful to local harnesses."""

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--authority-key", type=Path, required=True)
    parser.add_argument("--authority-key-id", required=True)
    parser.add_argument("--registrar-key-id", required=True)
    parser.add_argument("--registrar-public-key-file", type=Path, required=True)
    args = parser.parse_args(argv)
    registrar_public_key = args.registrar_public_key_file.read_text(
        encoding="ascii"
    ).strip()
    authority = AdmissionAuthority(
        args.state_dir,
        signer=Ed25519Signer(args.authority_key, args.authority_key_id),
        holder_registrars={args.registrar_key_id: registrar_public_key},
    )
    server = AdmissionServer(args.socket, authority)
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "DEFAULT_LEASE_TTL_S",
    "RECEIPT_SCHEMA",
    "AdmissionAuthority",
    "AdmissionClient",
    "AdmissionConflict",
    "AdmissionError",
    "AdmissionServer",
    "AdmissionUnavailable",
    "admission_resource_ref",
    "main",
    "serve_in_thread",
]
