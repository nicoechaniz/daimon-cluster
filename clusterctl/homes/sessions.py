"""Home read sessions and browser-proof pairing, separate from Cluster tokens.

Reuses the existing auth digest/write-lock helpers but never their fleet or seed
scopes. Public request codes are correlation; only the browser proof redeems an
approved identity. Credential values are hashed, never logged or returned by CLI.
"""

from __future__ import annotations

from contextlib import closing
import base64
import hashlib
import hmac
import os
from pathlib import Path
import re
import secrets
import sqlite3
import time

from clusterd.auth import hash_token

from .policy import Actor


class Sessions:
    def __init__(self, directory: Path, *, clock=lambda: int(time.time())):
        self.directory = Path(directory)
        self.clock = clock
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path = self.directory / "home-sessions.sqlite"
        if not self.path.exists():
            descriptor = os.open(
                self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600
            )
            os.close(descriptor)
        if (
            self.directory.is_symlink()
            or self.directory.stat().st_uid != os.geteuid()
            or self.directory.stat().st_mode & 0o077
            or self.path.is_symlink()
            or self.path.stat().st_uid != os.geteuid()
            or self.path.stat().st_nlink != 1
            or self.path.stat().st_mode & 0o077
        ):
            raise ValueError("private_home_session_store_required")
        with closing(self.connect()) as db:
            db.executescript("""
            PRAGMA journal_mode=DELETE;
            CREATE TABLE IF NOT EXISTS clock(id INTEGER PRIMARY KEY, highwater INTEGER NOT NULL);
            INSERT OR IGNORE INTO clock VALUES(1,0);
            CREATE TABLE IF NOT EXISTS sessions(
              digest TEXT PRIMARY KEY, home TEXT NOT NULL, origin TEXT NOT NULL,
              actor TEXT NOT NULL, revision TEXT NOT NULL, created INTEGER NOT NULL,
              expires INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS requests(
              code TEXT PRIMARY KEY, proof TEXT NOT NULL, home TEXT NOT NULL,
              origin TEXT NOT NULL, expires INTEGER NOT NULL, actor TEXT,
              revision TEXT, claimed INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS content_reads(
              digest TEXT PRIMARY KEY, home TEXT NOT NULL, content_origin TEXT NOT NULL,
              resource TEXT NOT NULL, version TEXT NOT NULL, parent TEXT,
              actor TEXT, revision TEXT, created INTEGER NOT NULL, expires INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS owner_credentials(
              digest TEXT PRIMARY KEY, home TEXT NOT NULL, actor TEXT NOT NULL,
              revision TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS session_parents(
              child TEXT PRIMARY KEY, parent TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS owner_authority_acceptance(
              digest TEXT PRIMARY KEY, revision TEXT NOT NULL);
            """)

    def connect(self):
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA synchronous=FULL")
        return db

    def now(self, db):
        previous = db.execute("SELECT highwater FROM clock WHERE id=1").fetchone()[0]
        current = max(previous, int(self.clock()))
        if current != previous:
            db.execute("UPDATE clock SET highwater=? WHERE id=1", (current,))
        return current

    @staticmethod
    def secret():
        return secrets.token_urlsafe(32)

    def _issue(self, db, home, origin, subject, ttl, token=None):
        now = self.now(db)
        token = token or self.secret()
        db.execute(
            "INSERT INTO sessions VALUES(?,?,?,?,?,?,?,0)",
            (
                hash_token(token),
                home,
                origin,
                subject.ref,
                subject.revision,
                now,
                now + ttl,
            ),
        )
        return token

    def issue(self, *, home: str, origin: str, subject: Actor, ttl=7 * 86400):
        if not subject.enabled or not 1 <= ttl <= 366 * 86400:
            raise ValueError("invalid_home_session_grant")
        with closing(self.connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                token = self._issue(db, home, origin, subject, ttl)
                db.commit()
                return token
            except BaseException:
                db.rollback()
                raise

    def active(self, db, row, now, *, max_age=None):
        """Check session ancestry inside the caller's existing transaction."""
        seen = set()
        for _ in range(8):
            if (not row or row['revoked'] or not row['created'] <= now < row['expires']
                    or row['digest'] in seen or (max_age is not None and now-row['created'] > max_age)):
                return False
            seen.add(row['digest'])
            parent = db.execute('SELECT parent FROM session_parents WHERE child=?',
                                (row['digest'],)).fetchone()
            if not parent:
                return True
            source = db.execute('SELECT * FROM sessions WHERE digest=?',
                                (parent['parent'],)).fetchone()
            if not source or (source['actor'], source['revision']) != (row['actor'], row['revision']):
                return False
            row = source
        return False

    def resolve(self, token, *, home, origin):
        if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
            return None
        with closing(self.connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute(
                    "SELECT * FROM sessions WHERE digest=?", (hash_token(token),)
                ).fetchone()
                now = self.now(db)
                valid = (
                    row
                    and row["home"] == home
                    and row["origin"] == origin
                    and self.active(db, row, now)
                )
                db.commit()
                return dict(row) if valid else None
            except BaseException:
                db.rollback()
                raise

    def register_owner(self, *, home, actor, revision, token):
        """Trusted provisioning may register a new key, never rebind an old one."""
        with closing(self.connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                digest = hash_token(token)
                old = db.execute(
                    "SELECT * FROM owner_credentials WHERE digest=?", (digest,)
                ).fetchone()
                if old and (old["home"], old["actor"], old["revision"]) != (
                    home,
                    actor,
                    revision,
                ):
                    raise ValueError("home_owner_key_binding_immutable")
                db.execute(
                    "INSERT OR IGNORE INTO owner_credentials VALUES(?,?,?,?,0)",
                    (digest, home, actor, revision),
                )
                db.commit()
            except BaseException:
                db.rollback()
                raise

    def accept_owner_authority(self, token, *, home, subject, binding_revision):
        """Trusted host accepts current authority for the same immutable owner key.

        The caller verifies the currently selected native authority and config.
        This is not a browser/owner API. One current row per credential bounds
        growth; the original credential/home/actor/revision remains unchanged.
        """
        if not subject.enabled or subject.kind != "being":
            raise ValueError("current_home_identity_binding_required")
        with closing(self.connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                digest = hash_token(token)
                row = db.execute(
                    "SELECT * FROM owner_credentials WHERE digest=?", (digest,)
                ).fetchone()
                if (
                    not row or row["revoked"] or row["home"] != home
                    or row["actor"] != subject.ref
                    or row["revision"] != binding_revision
                ):
                    raise ValueError("home_owner_binding_unavailable")
                db.execute(
                    "INSERT INTO owner_authority_acceptance VALUES(?,?) "
                    "ON CONFLICT(digest) DO UPDATE SET revision=excluded.revision",
                    (digest, subject.revision),
                )
                db.commit()
            except BaseException:
                db.rollback()
                raise

    def owner(self, token, *, home, subject, binding_revision=None):
        with closing(self.connect()) as db:
            digest = hash_token(token)
            row = db.execute(
                "SELECT * FROM owner_credentials WHERE digest=?", (digest,)
            ).fetchone()
            revision = subject.revision if binding_revision is None else binding_revision
            accepted = False
            if binding_revision is not None and binding_revision != subject.revision:
                accepted = db.execute(
                    "SELECT 1 FROM owner_authority_acceptance WHERE digest=? AND revision=?",
                    (digest, subject.revision),
                ).fetchone() is not None
            return bool(
                row
                and not row["revoked"]
                and row["home"] == home
                and (row["actor"], row["revision"]) == (subject.ref, revision)
                and (revision == subject.revision or accepted)
            )

    def revoke(self, *, home, actor=None, token=None):
        if (actor is None) == (token is None):
            raise ValueError("select_one_session_revocation")
        with closing(self.connect()) as db:
            cursor = db.execute(
                "UPDATE sessions SET revoked=1 WHERE home=? AND "
                + ("actor=?" if actor is not None else "digest=?"),
                (home, actor if actor is not None else hash_token(token)),
            )
            return cursor.rowcount

    def request(self, *, home, origin):
        with closing(self.connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                now = self.now(db)
                db.execute("DELETE FROM requests WHERE expires<?", (now - 86400,))
                count = db.execute(
                    "SELECT count(*) FROM requests WHERE home=? AND expires>?",
                    (home, now),
                ).fetchone()[0]
                if count >= 100:
                    raise ValueError("home_pairing_busy")
                code, proof = secrets.token_hex(5).upper(), self.secret()
                db.execute(
                    "INSERT INTO requests VALUES(?,?,?,?,?,NULL,NULL,0)",
                    (code, hash_token(proof), home, origin, now + 900),
                )
                db.commit()
                return {"code": code, "expires_at": now + 900}, proof
            except BaseException:
                db.rollback()
                raise

    def approve(self, *, home, code, subject):
        if not subject.enabled:
            raise ValueError("home_actor_disabled")
        with closing(self.connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute(
                    "SELECT * FROM requests WHERE home=? AND code=?", (home, code)
                ).fetchone()
                if not row or row["claimed"] or row["expires"] <= self.now(db):
                    raise ValueError("home_pairing_unavailable")
                if row["actor"] and (row["actor"], row["revision"]) != (
                    subject.ref,
                    subject.revision,
                ):
                    raise ValueError("home_pairing_identity_conflict")
                db.execute(
                    "UPDATE requests SET actor=?,revision=? WHERE code=?",
                    (subject.ref, subject.revision, code),
                )
                db.commit()
            except BaseException:
                db.rollback()
                raise

    def claim(self, *, home, origin, code, proof, current_actor):
        with closing(self.connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute(
                    "SELECT * FROM requests WHERE code=?", (code,)
                ).fetchone()
                if (
                    not row
                    or row["home"] != home
                    or row["origin"] != origin
                    or row["expires"] <= self.now(db)
                    or not hmac.compare_digest(row["proof"], hash_token(proof))
                ):
                    raise ValueError("home_pairing_unavailable")
                if not row["actor"]:
                    db.commit()
                    return {"status": "pending"}, None
                subject = current_actor(row["actor"], row["revision"])
                if not subject:
                    raise ValueError("home_pairing_identity_changed")
                # One grant, retryable receipt to the same exact browser proof.
                # No raw token is retained; the proof has 256 bits of entropy.
                material = (
                    b"dm.home-browser-session/v1\0"
                    + home.encode()
                    + b"\0"
                    + origin.encode()
                    + b"\0"
                    + code.encode()
                    + b"\0"
                    + proof.encode()
                )
                token = (
                    base64.urlsafe_b64encode(hashlib.sha256(material).digest())
                    .decode()
                    .rstrip("=")
                )
                if row["claimed"]:
                    old = db.execute(
                        "SELECT * FROM sessions WHERE digest=?", (hash_token(token),)
                    ).fetchone()
                    if (
                        not old
                        or old["revoked"]
                        or old["expires"] <= self.now(db)
                        or (old["actor"], old["revision"])
                        != (subject.ref, subject.revision)
                    ):
                        raise ValueError("home_pairing_unavailable")
                    db.commit()
                    return {"status": "approved"}, token
                token = self._issue(db, home, origin, subject, 7 * 86400, token)
                db.execute("UPDATE requests SET claimed=1 WHERE code=?", (code,))
                db.commit()
                return {"status": "approved"}, token
            except BaseException:
                db.rollback()
                raise

    def content_read(
        self,
        *,
        home,
        origin,
        content_origin,
        resource,
        version,
        subject,
        parent_token,
        ttl=900,
    ):
        """Cookie-free child read, bound to one artifact and its parent session."""
        if not 1 <= ttl <= 3600:
            raise ValueError("invalid_content_read_expiry")
        parent = (
            self.resolve(parent_token, home=home, origin=origin) if subject else None
        )
        if subject and (
            not parent
            or (parent["actor"], parent["revision"]) != (subject.ref, subject.revision)
        ):
            raise ValueError("content_read_parent_required")
        with closing(self.connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                now = self.now(db)
                db.execute("DELETE FROM content_reads WHERE expires<?", (now - 86400,))
                token = self.secret()
                db.execute(
                    "INSERT INTO content_reads VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (
                        hash_token(token),
                        home,
                        content_origin,
                        resource,
                        version,
                        hash_token(parent_token) if subject else None,
                        subject.ref if subject else None,
                        subject.revision if subject else None,
                        now,
                        min(now + ttl, parent["expires"]) if parent else now + ttl,
                    ),
                )
                db.commit()
                return token
            except BaseException:
                db.rollback()
                raise

    def resolve_content(self, token, *, content_origin):
        if not isinstance(token, str) or not re.fullmatch("[A-Za-z0-9_-]{43}", token):
            return None
        with closing(self.connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute(
                    "SELECT * FROM content_reads WHERE digest=?", (hash_token(token),)
                ).fetchone()
                now = self.now(db)
                valid = (
                    row
                    and row["content_origin"] == content_origin
                    and row["created"] <= now < row["expires"]
                )
                if valid and row["parent"]:
                    parent = db.execute(
                        "SELECT * FROM sessions WHERE digest=?", (row["parent"],)
                    ).fetchone()
                    valid = (
                        parent
                        and parent["home"] == row["home"]
                        and self.active(db, parent, now)
                        and (parent["actor"], parent["revision"])
                        == (row["actor"], row["revision"])
                    )
                db.commit()
                return dict(row) if valid else None
            except BaseException:
                db.rollback()
                raise
