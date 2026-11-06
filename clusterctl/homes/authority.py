"""Credential-free identity bindings and current native tribe authority.

Reads public catalogs and the existing operator-selected contact bindings. It
never calls participants(), reads its bearer tokens or loads a Matrix runtime.
Human tribe readers require a separately accepted, shared founder reader roster;
that projection is not a Matrix human membership event.
"""

from __future__ import annotations

from collections import OrderedDict
from contextlib import contextmanager
from contextvars import ContextVar
import copy
import hashlib
import json
from pathlib import Path
import threading
import time

from .policy import Actor


def digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


class NativeAuthority:
    def __init__(
        self,
        binding_source: Path,
        relationship_store: Path,
        homes,
        *,
        authority_source: Path | None = None,
        human_rosters=lambda: {},
        clock=lambda: int(time.time() * 1000),
    ):
        self.binding_source = Path(binding_source)
        self.relationship_store = Path(relationship_store)
        self.homes = homes
        self.authority_source = authority_source
        self.human_rosters = human_rosters
        self.clock = clock
        self._read_snapshot = ContextVar("home_public_proofs", default=None)
        # Successful public constructors only; never cache grants/file reads.
        self._proof_cache = OrderedDict()
        self._proof_cache_bytes = 0
        self._proof_cache_lock = threading.RLock()
        self._proof_cache_entries = 16
        self._proof_cache_limit = 16 * 1024 * 1024

    def _constructed(self, kind, value, construct):
        # The exact complete input, including unknown fields, distinguishes hits.
        # 64x canonical bytes +64KiB is conservative retention accounting, not a
        # process peak-memory guarantee; oversize inputs bypass retention.
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                             allow_nan=False).encode()
        charge = 64 * len(encoded) + 65536
        if charge > self._proof_cache_limit:
            return construct(value)
        key = (kind, encoded)
        with self._proof_cache_lock:
            if key in self._proof_cache:
                cached, _ = self._proof_cache[key]
                result = copy.deepcopy(cached)
                self._proof_cache.move_to_end(key)
                return result
            result = construct(value)  # Failure never admits an entry.
            private = copy.deepcopy(result)
            while self._proof_cache and (
                    len(self._proof_cache) >= self._proof_cache_entries or
                    self._proof_cache_bytes + charge > self._proof_cache_limit):
                _, (_, removed) = self._proof_cache.popitem(last=False)
                self._proof_cache_bytes -= removed
            self._proof_cache[key] = (private, charge)
            self._proof_cache_bytes += charge
            return result


    @contextmanager
    def read_snapshot(self):
        """Reuse successful public-proof reads within one read-only request.

        Lazy, per-instance and context-local: public reads incur no proof work.
        Sessions, registry, relationship views, rosters and clocks stay fresh.
        Nested scopes get independent snapshots; failure always restores scope.
        """
        token = self._read_snapshot.set({})
        try:
            yield
        finally:
            self._read_snapshot.reset(token)

    def _read_once(self, name, read):
        snapshot = self._read_snapshot.get()
        if snapshot is None:
            return read()
        if name not in snapshot:
            snapshot[name] = read()  # Exceptions never populate a success entry.
        return snapshot[name]

    def bindings(self):
        return self._read_once("bindings", self._bindings)

    def _bindings(self):
        from daimon_matrix.human_tribu_process import host_config
        from daimon_matrix.messaging_config import protected_read
        from daimon_matrix.operator_rebirth import authority_from_document

        # host_config validates its protected source but never reads token values.
        source = host_config(self.binding_source)
        results = []
        for row in source["participants"]:
            authority = self._constructed("authority",
                json.loads(protected_read(Path(row["authority_file"]))),
                authority_from_document,
            )
            if authority.manifest.being_ref != row["being_ref"]:
                raise ValueError("home_identity_source_mismatch")
            authority.validate_origin(row["origin"], require_active=True)
            if (
                type(row["human_id"]) is not int
                or row["human_id"] <= 0
                or type(row["bot_id"]) is not int
                or row["bot_id"] <= 0
                or type(row["enabled"]) is not bool
            ):
                raise ValueError("home_identity_source_invalid")
            results.append(
                {
                    k: row[k]
                    for k in (
                        "being_ref",
                        "label",
                        "human_id",
                        "human_name",
                        "bot_id",
                        "username",
                        "origin",
                        "enabled",
                    )
                }
                | {"authority": authority}
            )
        if len({r["being_ref"] for r in results}) != len(results):
            raise ValueError("home_identity_source_conflict")
        return results

    def actors(self):
        return self._read_once("actors", self._actors)

    def _actors(self):
        # An actor pin alone can be a valid historical Root. Actor-based owner
        # and browser checks must also agree with the selected current source.
        self.authorities()
        result = {}
        for row in self.bindings():
            if not row["enabled"]:
                continue
            ref = row["being_ref"]
            revision = digest(
                {
                    "ref": ref,
                    "origin": row["origin"],
                    "manifest": row["authority"].manifest.digest,
                }
            )
            result[ref] = Actor(ref, "being", revision, row["label"])
            human = "human:telegram:" + str(row["human_id"])
            result[human] = Actor(
                human,
                "human",
                digest({"provider": "telegram", "subject": row["human_id"]}),
                row["human_name"],
            )
        return result

    def actor(self, reference):
        return self.actors().get(reference)

    def paired_human(self, home):
        selected = self.homes[home]["owner_being_ref"]
        row = next(
            (r for r in self.bindings() if r["being_ref"] == selected and r["enabled"]),
            None,
        )
        return "human:telegram:" + str(row["human_id"]) if row else None

    def bot(self, home):
        selected = self.homes[home]["owner_being_ref"]
        row = next(
            (r for r in self.bindings() if r["being_ref"] == selected and r["enabled"]),
            None,
        )
        return {"id": row["bot_id"], "username": row["username"]} if row else None

    @contextmanager
    def view(self):
        from daimon_matrix.relationship_store import RelationshipStore
        from daimon_matrix.runtime import verify_relationship_card_authority

        authorities = self.authorities()
        store = RelationshipStore(
            self.relationship_store, authority_resolver=authorities.__getitem__
        )

        def verifier(card, at):
            return verify_relationship_card_authority(
                card, authorities[card["being_ref"]], at_ms=at
            )

        # Existing initialized authority only. No initialize(), ingest or runtime.
        with store.authorization_view(
            at_ms=self.clock(), card_verifier=verifier
        ) as view:
            yield view

    def authorities(self):
        return self._read_once("authorities", self._authorities)

    def _authorities(self):
        rows = self.bindings()
        selected = {r["being_ref"]: r["authority"] for r in rows}
        if self.authority_source is None:
            return selected
        from daimon_matrix.messaging_config import protected_read

        source = json.loads(protected_read(self.authority_source))
        # Read only public proof fields; never load/open a runtime or its custody.
        candidates = [source, *source.get("sources", {}).get("known_beings", [])]
        histories = {}
        for candidate in candidates:
            # Only the public fields consumed by public_history are retained.
            # Epoch dictionaries remain complete so invalid extra fields refuse.
            document = {k: candidate[k] for k in (
                "control_artifacts", "control_head", "manifest", "credentials",
                "incarnations")}
            document["authority_history"] = candidate.get("authority_history", [])
            authority = self._constructed("history", document, public_history)
            reference = authority.manifest.being_ref
            if (
                reference in histories
                and histories[reference].manifest.digest != authority.manifest.digest
            ):
                raise ValueError("home_authority_source_fork")
            histories[reference] = authority
        for reference, authority in selected.items():
            if (
                reference not in histories
                or histories[reference].manifest.digest != authority.manifest.digest
            ):
                raise ValueError("home_actor_authority_source_stale")
        return histories

    def tribes(self):
        with self.view() as view:
            return {
                reference: view.snapshot(reference).value
                for reference, row in view.tribes.items()
                if row["state"] == "active"
            }

    def tribe_member(self, home, tribe, actor):
        try:
            with self.view() as view:
                snapshot = view.snapshot(tribe).value
                if actor.kind == "being":
                    return any(
                        r["principal_id"] == actor.ref and r["state"] == "active"
                        for r in snapshot["members"]
                    )
                # Shared explicit human readers, separate from native being membership.
                roster = self.human_rosters().get(tribe)
                if (
                    not isinstance(roster, dict)
                    or type(roster.get("revision")) is not int
                    or roster["revision"] < 1
                    or roster.get("revoked") is not False
                    or roster.get("founder_principal_id")
                    != snapshot["founder_principal_id"]
                ):
                    return False
                expires = roster.get("expires_at_ms")
                if expires is not None and (
                    type(expires) is not int or expires <= self.clock()
                ):
                    return False
                return actor.ref in roster.get("readers", [])
        except (KeyError, ValueError, RuntimeError):
            return False


def public_history(value):
    """Bridge existing public proof fields to SDK constructors/epoch verifiers.

    Old enrollment epochs may contain only manifest+successor and share the next
    authority's public controls/credentials. This preserves actual historical
    signatures without importing custody or treating old roots as current.
    """
    from daimon_matrix.authority_epochs import RootHistoryAuthority
    from daimon_matrix.operator_rebirth import authority_from_document
    from daimon_matrix.weave import BeingManifest, RootAuthority

    fields = (
        "control_artifacts",
        "control_head",
        "manifest",
        "credentials",
        "incarnations",
    )
    active = authority_from_document(
        {"schema": "dm.operator.authority/v1", **{k: value[k] for k in fields}}
    )
    epochs = value.get("authority_history", [])
    if not isinstance(epochs, list) or len(epochs) > 256:
        raise ValueError("invalid_home_authority_history")
    previous = active
    backwards = []
    for epoch in reversed(epochs):
        if set(epoch) == {"manifest", "successor"}:
            previous = RootAuthority(
                BeingManifest.from_value(epoch["manifest"]),
                previous.state,
                previous.credentials,
                previous.incarnations,
            )
        elif set(epoch) == set(fields) | {"successor"}:
            previous = authority_from_document(
                {"schema": "dm.operator.authority/v1", **{k: epoch[k] for k in fields}}
            )
        else:
            raise ValueError("invalid_home_authority_history")
        backwards.append(previous)
    return (
        RootHistoryAuthority(
            active, list(reversed(backwards)), [e["successor"] for e in epochs]
        )
        if epochs
        else active
    )
