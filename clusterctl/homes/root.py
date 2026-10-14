"""A selected immutable home landing, distinct from artifact publication.

This stores a delivery pointer, not another design catalog/default authority.
Every reader still passes current and original resource audience enforcement.
"""

from contextlib import closing
import json
import re


def valid_path(path):
    return isinstance(path, str) and bool(
        re.fullmatch(
            r"/(?:index\.html|blog/?|(?:journal|blog)/[a-z0-9][a-z0-9_-]{0,79}(?:/index\.html|\.html))?",
            path,
        )
    )


class HomeRoot:
    def __init__(self, app):
        self.app = app
        with closing(app.sessions.connect()) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS home_roots(home TEXT PRIMARY KEY, revision INTEGER NOT NULL, selection TEXT);
                CREATE TABLE IF NOT EXISTS home_root_history(home TEXT NOT NULL, revision INTEGER NOT NULL,
                    actor TEXT NOT NULL, selection TEXT, PRIMARY KEY(home,revision));
            """)

    def read(self, home):
        with closing(self.app.sessions.connect()) as db:
            row = db.execute(
                "SELECT revision,selection FROM home_roots WHERE home=?", (home,)
            ).fetchone()
        return {
            "schema": "dm.home.root/v1",
            "home": home,
            "revision": row["revision"] if row else 0,
            "selection": json.loads(row["selection"])
            if row and row["selection"]
            else None,
        }

    def select(self, home, owner, payload):
        if (
            owner.kind != "being"
            or owner.ref != self.app.homes[home]["owner_being_ref"]
            or set(payload) != {"expected_revision", "resource", "version", "routes"}
            or type(payload["expected_revision"]) is not int
            or payload["expected_revision"] < 0
        ):
            raise ValueError("invalid_home_root_selection")
        reference, version, routes = (
            payload["resource"],
            payload["version"],
            payload["routes"],
        )
        if reference is None and version is None and routes == {}:
            selection = None
        else:
            if (
                not isinstance(reference, str)
                or not re.fullmatch("[a-f0-9]{32}", reference)
                or not isinstance(version, str)
                or not re.fullmatch("[a-f0-9]{64}", version)
                or not isinstance(routes, dict)
                or len(routes) > 2048
            ):
                raise ValueError("invalid_home_root_selection")
            current = next(
                (
                    e
                    for e in self.app.publication(home)["entries"]
                    if e["artifact_ref"] == reference
                ),
                None,
            )
            selected = self.app.registry.version(
                home=home, resource=reference, version=version
            )
            if (
                not current
                or not selected
                or selected["kind"] != "artifact"
                or selected["entrypoint"] != "index.html"
            ):
                raise ValueError("home_root_requires_accepted_home_bundle")
            defaults = {"/": "index.html", "/index.html": "index.html"}
            defaults.update(
                {
                    "/" + f: f
                    for f in selected["files"]
                    if re.fullmatch(r"journal/[a-z0-9][a-z0-9-]{0,79}/index\.html", f)
                }
            )
            for route, file in routes.items():
                if (
                    not valid_path(route)
                    or not isinstance(file, str)
                    or file not in selected["files"]
                    or not file.endswith(".html")
                    or (route in defaults and defaults[route] != file)
                ):
                    raise ValueError("invalid_home_root_route")
            selection = {
                "resource": reference,
                "version": version,
                "routes": {**defaults, **routes},
            }
        serialized = (
            json.dumps(selection, sort_keys=True, separators=(",", ":"))
            if selection
            else None
        )
        with closing(self.app.sessions.connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute(
                    "SELECT revision,selection FROM home_roots WHERE home=?", (home,)
                ).fetchone()
                revision = row["revision"] if row else 0
                if (row["selection"] if row else None) == serialized:
                    db.commit()
                    return {**self.read(home), "status": "unchanged"}
                if revision != payload["expected_revision"]:
                    raise ValueError("home_root_revision_conflict")
                revision += 1
                db.execute(
                    "INSERT INTO home_root_history VALUES(?,?,?,?)",
                    (home, revision, owner.ref, serialized),
                )
                db.execute(
                    "INSERT OR REPLACE INTO home_roots VALUES(?,?,?)",
                    (home, revision, serialized),
                )
                db.commit()
            except BaseException:
                db.rollback()
                raise
        return {**self.read(home), "status": "selected" if selection else "cleared"}

    def entry(self, home, path, subject, vpn):
        root = self.read(home)["selection"]
        if not root or path not in root["routes"]:
            return None
        selected = self.app.selected(
            home, root["resource"], root["version"], subject, vpn
        )
        if not selected or root["routes"][path] not in selected["files"]:
            return None
        return root, root["routes"][path]
