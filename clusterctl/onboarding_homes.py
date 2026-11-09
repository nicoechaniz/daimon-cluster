"""Accepted-body home hook; reuse worker progress, not a new watcher or stage.

The hook never activates a body or replays its onboarding. Host-approved home
placements bind to the existing owner and complete plan digest. Installation is
delivered by a typed host provider under that placement's existing resource
grant; the hook itself cannot run arbitrary source-supplied commands.
"""

from __future__ import annotations

from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import uuid

from .onboarding import OnboardingError, Observation, digest, CONVERSATION_JOB_SCHEMA, CONVERSATION_PLAN_SCHEMA
from .onboarding_progress import Progress


def selected_bundle(repository, commit, destination):
    """Bundle an approved commit without changing the development checkout."""
    import subprocess

    reference = "refs/daimon-home/bundle-" + uuid.uuid4().hex
    subprocess.run(
        ["git", "-C", str(repository), "update-ref", reference, commit, "0" * 40],
        check=True,
        capture_output=True,
    )
    try:
        subprocess.run(
            [
                "git",
                "-C",
                str(repository),
                "bundle",
                "create",
                str(destination),
                reference,
            ],
            check=True,
            capture_output=True,
            timeout=60,
        )
        Path(destination).chmod(0o600)
    finally:
        # A concurrent change is preserved, never force-deleted.
        subprocess.run(
            ["git", "-C", str(repository), "update-ref", "-d", reference, commit],
            check=True,
            capture_output=True,
        )


def verify_conversation_access(request, *, owner_url, owner_token, journal=None):
    """Use the existing owner entry/claim with an isolated technical browser.

    The owner proves only its already registered human. No child input, family
    bearer invitation, alternate pairing store or provider request is involved.
    """
    import http.cookiejar
    import time
    import urllib.error
    import urllib.parse
    import urllib.request

    origin = request['origin']
    end = time.monotonic()+25
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, message, headers, newurl):
            return None
    jar = http.cookiejar.CookieJar()
    browser = urllib.request.build_opener(urllib.request.ProxyHandler({}),
        urllib.request.HTTPCookieProcessor(jar), NoRedirect())
    owner = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    result = dict(own_human=False, conversation=False, anonymous_denied=False,
                  admin_denied=False, signed_out=False)
    pins = digest({key: request[key] for key in ('origin', 'home_ref', 'human_ref')})
    operation = {'schema': 'cluster-conversation-browser-check/v1', 'pins': pins,
                 'phase': 'prepared', 'entry': None, 'cookies': [], 'checks': result}
    if journal is not None:
        from .onboarding import private_directory
        from .onboarding_custody import document
        journal = Path(journal)
        private_directory(journal.parent)
        if journal.exists():
            if journal.stat().st_size > 65536:
                raise OnboardingError('conversation_browser_checkpoint_capacity')
            operation = document(journal)
            if (operation.get('schema') != 'cluster-conversation-browser-check/v1'
                    or operation.get('pins') != pins
                    or set(operation.get('checks', {})) != set(result)
                    or any(type(value) is not bool for value in operation['checks'].values())
                    or not isinstance(operation.get('cookies'), list) or len(operation['cookies']) > 8):
                raise OnboardingError('conversation_browser_checkpoint_changed')
            result = operation['checks']
            for cookie in operation['cookies']:
                if (cookie['domain'].lstrip('.') != urllib.parse.urlsplit(origin).hostname
                        or cookie['secure'] is not True):
                    raise OnboardingError('conversation_browser_checkpoint_changed')
                jar.set_cookie(http.cookiejar.Cookie(0, cookie['name'], cookie['value'], None, False,
                    cookie['domain'], cookie['domain_specified'], cookie['domain'].startswith('.'),
                    cookie['path'], True, True, cookie['expires'], True, None, None, {}))

    def save(phase):
        # The same private, bounded operator checkpoint survives deadline
        # teardown. No cookie/proof enters logs, result receipts or model text.
        operation.update(phase=phase, checks=result, cookies=[dict(name=c.name, value=c.value,
            domain=c.domain, domain_specified=c.domain_specified, path=c.path,
            secure=c.secure, expires=c.expires) for c in jar])
        if len(operation['cookies']) > 8 or len(json.dumps(operation).encode()) > 65536:
            raise OnboardingError('conversation_browser_checkpoint_capacity')
        if journal is not None:
            from . import being_seed
            being_seed._write(journal, operation)

    def call(client, path, *, data=None, headers=None, local=False):
        remaining = end-time.monotonic()
        if remaining <= 0:
            raise OnboardingError('conversation_access_deadline_expired')
        target = (owner_url if local else origin)+path
        with client.open(urllib.request.Request(target, data=data, headers=headers or {}),
                         timeout=min(5, remaining)) as response:
            raw = response.read(262145)
            if response.status != 200 or len(raw) > 262144 or response.geturl() != target:
                raise OnboardingError('conversation_access_unconfirmed')
            return raw

    def claim():
        value = json.loads(call(browser, '/access/entry',
            data=json.dumps(operation['entry']).encode(), headers={
                'Content-Type': 'application/json', 'Origin': origin, 'Accept': 'application/json'}))
        if (value.get('status') != 'approved'
                or not any(c.name == '__Host-home' and c.value for c in jar)):
            raise OnboardingError('conversation_browser_claim_unconfirmed')
        save('claimed')

    if operation['phase'] == 'signed-out':
        if all(result.values()):
            return result
        operation.update(phase='prepared', entry=None)
        jar.clear()
        result = dict.fromkeys(result, False)
    if operation['phase'] == 'logout-intent':
        call(browser, '/access/logout', data=b'', headers={'Origin': origin, 'Accept': 'application/json'})
        result['signed_out'] = True
        save('signed-out')
        if all(result.values()):
            return result
        operation.update(phase='prepared', entry=None)
        jar.clear()
        result = dict.fromkeys(result, False)

    attempted_claim = operation['phase'] in {'claim-intent', 'claimed'}
    try:
        if operation['phase'] == 'prepared':
            # This separate private technical request does not consume or
            # replace a family's delivered links. Its retained proof spans the
            # supported seven-day window, not a fifteen-minute UI exchange.
            value = json.loads(call(owner, '/owner/'+request['home_ref']+'/entry-link', local=True,
                data=json.dumps({'return': '/interaction/?view=conversation&client=standalone',
                                 'ttl': 7*86400}).encode(),
                headers={'Authorization': 'Bearer '+owner_token, 'Content-Type': 'application/json'}))
            url = urllib.parse.urlsplit(value.get('url', ''))
            fields = urllib.parse.parse_qs(url.fragment, strict_parsing=True)
            if (value.get('schema') != 'dm.home-entry-link/v1'
                    or urllib.parse.urlunsplit((url.scheme, url.netloc, '', '', '')) != origin
                    or url.path != '/access/entry' or url.query or set(fields) != {'code', 'proof', 'return'}
                    or any(len(v) != 1 for v in fields.values())
                    or fields['return'][0] != '/interaction/?view=conversation&client=standalone'):
                raise OnboardingError('conversation_browser_request_unconfirmed')
            operation['entry'] = {k: v[0] for k, v in fields.items()}
            save('claim-intent')
        if operation['phase'] == 'claim-intent':
            attempted_claim = True
            # Home returns the same receipt to this exact retained code/proof,
            # including after a lost response. Never mint a replacement claim.
            claim()
        if operation['phase'] != 'claimed':
            raise OnboardingError('conversation_browser_checkpoint_changed')
        identity = json.loads(call(browser, '/access/identity'))
        if identity.get('actor', {}).get('ref') != request['human_ref']:
            raise OnboardingError('conversation_actual_home_pairing_required')
        result['own_human'] = True
        presentation = json.loads(call(browser, '/interaction/api/interaction'))
        if presentation.get('schema') != 'telecodex.presentation-list/v1':
            raise OnboardingError('conversation_public_read_unconfirmed')
        result['conversation'] = True
        for key, client, path in (('anonymous_denied', owner, '/interaction/api/interaction'),
                                  ('admin_denied', browser, '/interaction/api/state')):
            try:
                call(client, path)
            except urllib.error.HTTPError as error:
                if error.code in (401, 403):
                    result[key] = True
            if not result[key]:
                raise OnboardingError('conversation_private_access_not_denied')
    except (OSError, ValueError, KeyError, TypeError):
        raise OnboardingError('conversation_access_unconfirmed') from None
    finally:
        if attempted_claim:
            # Revocation is confined to this temporary cookie jar. Family
            # sessions, passkeys and their untouched invitation links remain.
            if operation['phase'] == 'claim-intent':
                # A lost response may already have created the same session.
                # Recover its exact supported receipt before revoking it; an
                # anonymous logout would not prove that session was closed.
                claim()
            save('logout-intent')
            call(browser, '/access/logout', data=b'', headers={
                'Origin': origin, 'Accept': 'application/json'})
            result['signed_out'] = True
            save('signed-out')
    return result


class AcceptedHomes:
    def __init__(self, *, progress, worker_uid, placements, state, provider):
        self.progress = Path(progress)
        self.worker_uid = worker_uid
        self.placements = placements
        self.provider = provider
        self.state = Path(state)
        from .onboarding import private_directory

        private_directory(self.state, create=True)
        self.path = self.state / "home-jobs.sqlite"
        if not self.path.exists():
            descriptor = os.open(
                self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600
            )
            os.close(descriptor)
        if (
            self.path.is_symlink()
            or self.path.stat().st_uid != worker_uid
            or self.path.stat().st_mode & 0o077
        ):
            raise OnboardingError("trusted_home_job_store_required")
        with closing(sqlite3.connect(self.path)) as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS homes(name TEXT PRIMARY KEY, owner TEXT NOT NULL, "
                "plan TEXT NOT NULL, selection TEXT NOT NULL, state TEXT NOT NULL)"
            )

    def reconcile_committed(self, name):
        """Home admission is independent of still-pending human acceptance."""
        placement = self.placements.get(name)
        if placement is None:
            return {"state": "not-selected"}
        try:
            value = Progress(self.progress, worker_uid=self.worker_uid).read(
                name, owner=placement['owner'])
        except FileNotFoundError:
            return {"state": "waiting", "reason": "home_admission_unconfirmed"}
        return self(value)

    def conversation_access(self, plan, request, apply):
        """Check only the delivered own Home, never a family invitation link."""
        from .onboarding_custody import document
        placement = self.placements.get(plan['name'])
        if (placement is None or placement['owner'] != plan['owner']
                or placement['plan_digest'] != digest(plan)):
            return Observation('waiting', reason='connection_data_required')
        selected = digest(placement)
        with closing(sqlite3.connect(self.path)) as db:
            row = db.execute('SELECT owner,plan,selection,state FROM homes WHERE name=?',
                             (plan['name'],)).fetchone()
        if row != (plan['owner'], digest(plan), selected, 'complete'):
            return Observation('waiting', reason='connection_data_required')
        receipt = self.state/(plan['name']+'.conversation-access.json')
        browser_journal = self.state/(plan['name']+'.technical-browser.json')
        pins = {'plan_digest': digest(plan), 'placement_digest': selected,
                'request_digest': digest(request)}
        if receipt.exists():
            value = document(receipt)
            if (value.get('schema') != 'cluster-conversation-access/v1'
                    or value.get('pins') != pins):
                raise OnboardingError('conversation_access_receipt_changed')
            if value.get('verified') is True:
                if browser_journal.exists():
                    current = document(browser_journal)
                    if current.get('phase') != 'signed-out' or current.get('checks') != value['checks']:
                        raise OnboardingError('conversation_browser_checkpoint_changed')
                    browser_journal.unlink()
                return Observation('complete', {'conversation_verified': True, 'shared_login_verified': True})
        if not apply:
            return Observation('absent', safe_to_execute=True)
        result = self.provider.conversation_access(placement, request, journal=browser_journal)
        if result != {'own_human': True, 'conversation': True,
                      'anonymous_denied': True, 'admin_denied': True, 'signed_out': True}:
            raise OnboardingError('conversation_access_unconfirmed')
        from . import being_seed
        being_seed._write(receipt, dict(schema='cluster-conversation-access/v1',
            pins=pins, verified=True, checks=result))
        # Byte/proof work is finished and the logout ACK is retained. Retire
        # only this operation's temporary cookie checkpoint, never a session DB.
        if browser_journal.exists():
            current = document(browser_journal)
            if current.get('phase') != 'signed-out' or current.get('checks') != result:
                raise OnboardingError('conversation_browser_checkpoint_changed')
            browser_journal.unlink()
        return Observation('complete', {'conversation_verified': True, 'shared_login_verified': True})

    def __call__(self, value):
        value = Progress.validate(value)
        placement = self.placements.get(value["name"])
        prerequisite = 'identity' if value['schema'] == CONVERSATION_JOB_SCHEMA else 'matrix'
        if not placement or prerequisite not in value['completed_steps']:
            return {"state": "not-selected"}
        if placement['owner'] != value['owner'] or placement['plan_digest'] != value['plan_digest']:
            raise OnboardingError('accepted_home_placement_required')
        committed = Progress(self.progress, worker_uid=self.worker_uid).read(
            value['name'], owner=placement['owner'])
        if (
            os.geteuid() != self.worker_uid
            or placement["owner"] != value["owner"]
            or placement["plan_digest"] != value["plan_digest"]
            or committed['plan_digest'] != value['plan_digest']
            or committed['schema'] != value['schema']
            or prerequisite not in committed['completed_steps']
        ):
            raise OnboardingError("accepted_home_placement_required")
        selected = hashlib.sha256(
            json.dumps(placement, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        with closing(sqlite3.connect(self.path, timeout=30)) as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute(
                "SELECT owner,plan,selection,state FROM homes WHERE name=?",
                (value["name"],),
            ).fetchone()
            if old and old[:2] != (value["owner"], value["plan_digest"]):
                raise OnboardingError("existing_home_job_preserved")
            if old and old[2] == selected and old[3] == "complete":
                return {"state": "complete", "retried": True}
            db.execute(
                "INSERT OR REPLACE INTO homes VALUES(?,?,?,?,?)",
                (
                    value["name"],
                    value["owner"],
                    value["plan_digest"],
                    selected,
                    "dispatching",
                ),
            )
            db.commit()
        # Provider owns exact incarnation/resource checks and idempotent guest
        # writes. A lost receipt repeats the same bounded placement, not a new
        # body, grant, public artifact or native model turn.
        receipt = self.provider.reconcile(placement)
        if (
            not isinstance(receipt, dict)
            or receipt.get("state") != "complete"
            or receipt.get("selection_digest") != selected
        ):
            return {"state": "waiting", "reason": "home_delivery_unconfirmed"}
        with closing(sqlite3.connect(self.path)) as db:
            db.execute(
                "UPDATE homes SET state=? WHERE name=? AND owner=? AND plan=? AND selection=?",
                (
                    "complete",
                    value["name"],
                    value["owner"],
                    value["plan_digest"],
                    selected,
                ),
            )
            db.commit()
        return {"state": "complete", "retried": False}


class IncusProvider:
    """Typed delivery into the already accepted, plan-owned agent namespace."""

    def __init__(self, store, backend):
        self.store, self.backend = store, backend

    def reconcile(self, placement):
        from . import being_seed
        from .onboarding import private_directory
        # Home callbacks run independently of acceptance. Their receiving calls
        # must nevertheless own the same job lock and resolve the current
        # runtime after acquiring it, just like the ordinary worker tick.
        directory = private_directory(self.store.directory(placement['name']))
        with being_seed._locked(directory):
            backend = self.backend() if callable(self.backend) else self.backend
            return IncusProvider(self.store, backend)._reconcile(placement)

    def conversation_access(self, placement, request, *, journal=None):
        from .homes.service import validate_config
        from .onboarding_release import regular
        delivery = validate_delivery(placement['delivery'])
        if (delivery['home_ref'] != request['home_ref']
                or delivery['owner_being_ref'] != request['being_ref']
                or delivery['home']['public_url'] != request['origin']):
            raise OnboardingError('matching_home_receiving_binding_required')
        config = validate_config(json.loads(regular(Path(delivery['gateway_config']),
            uid=delivery['gateway_uid'])), credential_uid=delivery['gateway_uid'])
        token = regular(Path(delivery['home']['owner_token_file']), uid=delivery['gateway_uid'], limit=4096)
        return verify_conversation_access(request, owner_url='http://127.0.0.1:'+str(config['owner_port']),
            owner_token=token.decode().strip(), journal=journal)

    def _reconcile(self, placement):
        from .homes.provision import regular, sha
        from .onboarding import digest, validate_plan
        import tempfile

        record = self.store._load(placement["name"])
        plan = validate_plan(record["plan"])
        fingerprint = digest(plan)
        if (
            fingerprint != placement["plan_digest"]
            or not self.backend.authorize(plan, fingerprint)
            or self.backend._environment(plan).state != "complete"
        ):
            raise OnboardingError("accepted_home_environment_required")
        if plan['schema'] == CONVERSATION_PLAN_SCHEMA:
            if self.backend._identity(plan, apply=False).state != 'complete':
                raise OnboardingError('home_admission_unconfirmed')
            expected = self.backend._ceremony(plan).admission_coordinates(plan)
        else:
            from .onboarding_managed import ManagedRuntime
            managed = ManagedRuntime(self.backend)
            if managed.observe(plan).state != 'complete':
                raise OnboardingError('home_admission_unconfirmed')
            expected = managed._expected(plan)
        delivery = validate_delivery(placement['delivery'])
        if (expected['being_ref'] != delivery['owner_being_ref']
                or expected['being_ref'] != delivery['home']['owner_being_ref']):
            raise OnboardingError('home_admission_owner_conflict')
        source = Path(placement["provider_file"])
        if sha(regular(source)) != placement["provider_sha256"]:
            raise OnboardingError("qualified_home_provider_required")
        declaration = Path(placement["declaration_file"])
        raw = regular(declaration)
        if sha(raw) != placement["declaration_sha256"]:
            raise OnboardingError("qualified_home_placement_required")
        value = json.loads(raw)
        if value["skills_commit"] != placement["skills_commit"]:
            raise OnboardingError("qualified_home_skill_required")
        instance = self.backend.instance(plan)
        run = self.backend.run
        destination = "/opt/daimon-home-provider"
        run(["exec", instance, "--", "mkdir", "-p", destination])
        run(
            [
                "file",
                "push",
                str(source),
                instance + destination + "/provision.py",
                "--uid",
                "0",
                "--gid",
                "0",
                "--mode",
                "0644",
            ]
        )
        run(
            [
                "file",
                "push",
                str(declaration),
                instance + destination + "/declaration.json",
                "--uid",
                "1000",
                "--gid",
                "1000",
                "--mode",
                "0600",
            ]
        )
        repository = Path(placement["repository"])
        with tempfile.TemporaryDirectory(
            prefix="home-skill-bundle-", dir=self.store.root
        ) as temporary:
            bundle = Path(temporary) / "skills.bundle"
            selected_bundle(repository, placement["skills_commit"], bundle)
            run(
                [
                    "file",
                    "push",
                    str(bundle),
                    instance + destination + "/skills.bundle",
                    "--uid",
                    "1000",
                    "--gid",
                    "1000",
                    "--mode",
                    "0600",
                ]
            )
        run(
            [
                "exec",
                instance,
                "--user",
                "1000",
                "--group",
                "1000",
                "--",
                "python3",
                destination + "/provision.py",
                "--home",
                "/home/agent",
                "--repository",
                "/home/agent/.local/state/daimon-home/skills-source",
                "--source-bundle",
                destination + "/skills.bundle",
            ]
        )
        run(
            [
                "exec",
                instance,
                "--user",
                "1000",
                "--group",
                "1000",
                "--",
                "python3",
                destination + "/provision.py",
                "--home",
                "/home/agent",
                "--declaration",
                destination + "/declaration.json",
                "--repository",
                "/home/agent/.local/state/daimon-home/skills-source",
            ]
        )
        self.deliver(placement, value, instance)
        selected = hashlib.sha256(
            json.dumps(placement, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return {"state": "complete", "selection_digest": selected}

    def deliver(self, placement, declaration, instance):
        """Only verified service/routing/grant delivery yields completion."""
        from .homes.host import ensure_proxy, guest_unit
        from .homes.provision import sha
        from .onboarding_release import regular
        import tempfile
        import subprocess
        import pwd
        from urllib.parse import urlsplit

        from .homes.service import validate_config

        details = validate_delivery(placement["delivery"])
        home = details["home"]
        config_path = Path(details["gateway_config"])
        uid, gid = details["gateway_uid"], details["gateway_gid"]
        original = regular(config_path, uid=uid)
        config = validate_config(json.loads(original), credential_uid=uid)
        if home["owner_being_ref"] != details["owner_being_ref"]:
            raise OnboardingError("home_delivery_owner_conflict")
        binding = declaration["binding"]
        access = binding.get("access", {})
        if (
            access.get("home_ref") != details["home_ref"]
            or access.get("owner_url") != f"http://127.0.0.1:{config['owner_port']}"
            or binding.get("public_url") != home["public_url"]
            or binding.get("vpn_url") != home["vpn_url"]
        ):
            raise OnboardingError("matching_home_receiving_binding_required")
        validate_config(
            {**config, "homes": {**config["homes"], details["home_ref"]: home}},
            credential_uid=uid,
        )
        # Transport only the two resource-scoped home credentials, not any
        # Matrix, account, bot, SSH or custody material.
        destinations = access
        for field in ("gateway_token_file", "owner_token_file"):
            destination = Path(destinations[field])
            if (
                destination.parent != Path("/home/agent/.config/daimon-home")
                or destination.name
                != {
                    "gateway_token_file": "gateway.key",
                    "owner_token_file": "owner.key",
                }[field]
            ):
                raise OnboardingError("dedicated_home_key_destination_required")
            source = Path(home[field])
            if source.parent != config_path.parent / "keys":
                raise OnboardingError("dedicated_home_key_source_required")
            regular(source, uid=uid)
            if source.stat().st_mode & 0o077:
                raise OnboardingError("private_home_key_required")
            self.backend.run(
                [
                    "file",
                    "push",
                    str(source),
                    instance + str(destination),
                    "--uid",
                    "1000",
                    "--gid",
                    "1000",
                    "--mode",
                    "0600",
                ]
            )
        with tempfile.TemporaryDirectory(
            prefix="home-service-", dir=self.store.root
        ) as temporary:
            unit = Path(temporary) / "daimon-home.service"
            unit.write_bytes(guest_unit(declaration["binding"]))
            unit.chmod(0o600)
            self.backend.run(
                [
                    "file",
                    "push",
                    str(unit),
                    instance + "/opt/daimon-home-provider/daimon-home.service",
                    "--uid",
                    "0",
                    "--gid",
                    "0",
                    "--mode",
                    "0600",
                ]
            )
        args = [
            "exec",
            instance,
            "--",
            "python3",
            "/opt/daimon-home-provider/provision.py",
            "--unit-file",
            "/opt/daimon-home-provider/daimon-home.service",
        ]
        if details["previous_unit_sha256"]:
            args += ["--previous-unit-sha256", details["previous_unit_sha256"]]
        self.backend.run(args)
        self.backend.run(["exec", instance, "--", "systemctl", "daemon-reload"])
        self.backend.run(
            [
                "exec",
                instance,
                "--",
                "systemctl",
                "enable",
                "--now",
                "daimon-home.service",
            ]
        )
        self.backend.run(
            ["exec", instance, "--", "systemctl", "restart", "daimon-home.service"]
        )
        self.backend.run(
            [
                "exec",
                instance,
                "--",
                "systemctl",
                "is-active",
                "--quiet",
                "daimon-home.service",
            ]
        )
        port = urlsplit(home["backend"]).port
        ensure_proxy(
            self.backend.run,
            instance,
            "daimon-home-public",
            {
                "type": "proxy",
                "bind": "host",
                "listen": f"tcp:127.0.0.1:{port}",
                "connect": "tcp:127.0.0.1:"
                + str(declaration["binding"]["public_port"]),
            },
        )
        owner_port = config["owner_port"]
        ensure_proxy(
            self.backend.run,
            instance,
            "daimon-home-owner",
            {
                "type": "proxy",
                "bind": "instance",
                "listen": f"tcp:127.0.0.1:{owner_port}",
                "connect": f"tcp:127.0.0.1:{owner_port}",
            },
        )
        # Gateway registration runs under its existing owner, retaining epoch
        # bindings and exact config CAS. The worker has no reader token shortcut.
        row = config_path.parent / (
            "home-row-" + sha(json.dumps(home, sort_keys=True).encode()) + ".json"
        )
        if not row.exists():
            fd = os.open(
                row, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600
            )
            with os.fdopen(fd, "wb") as stream:
                os.fchown(stream.fileno(), uid, gid)
                stream.write(json.dumps(home).encode())
        if json.loads(regular(row, uid=uid)) != home:
            raise OnboardingError("existing_home_registration_row_preserved")
        argv = [
            "/usr/sbin/runuser",
            "-u",
            pwd.getpwuid(uid).pw_name,
            "--",
            details["gateway_python"],
            "-m",
            "clusterctl.homes.host",
            "register",
            "--config",
            str(config_path),
            "--reference",
            details["home_ref"],
            "--row",
            str(row),
            "--previous-digest",
            sha(original),
        ]
        registered = json.loads(
            subprocess.run(
                argv,
                cwd=details["gateway_code"],
                capture_output=True,
                check=True,
                timeout=60,
            ).stdout
        )
        if registered["status"] != "unchanged":
            subprocess.run(
                ["systemctl", "restart", "daimon-home-access.service"],
                capture_output=True,
                check=True,
                timeout=40,
            )
        self.backend.run(
            [
                "exec",
                instance,
                "--user",
                "1000",
                "--group",
                "1000",
                "--",
                "/home/agent/.local/bin/daimon-home",
                "sync",
            ]
        )
        # An actual external projection, not only a running process/file, proves
        # the selected home is routed to the common authority and usable.
        import urllib.request

        with urllib.request.urlopen(
            home["public_url"] + "/catalog.json", timeout=20
        ) as response:
            value = json.load(response)
            if (
                response.status != 200
                or value.get("home_ref") != details["home_ref"]
                or value.get("access_contract") != "dm.resource-access/v1"
                or not isinstance(value.get("entries"), list)
            ):
                raise OnboardingError("home_frontend_delivery_unconfirmed")


def configure(path, *, progress, store, backend, worker_uid):
    from . import being_seed
    import re

    value = being_seed._read(Path(path))
    if (
        set(value) != {"schema", "state", "placements"}
        or value["schema"] != "dm.home-onboarding.host/v1"
        or not isinstance(value["placements"], dict)
        or not Path(value["state"]).is_absolute()
    ):
        raise OnboardingError("invalid_home_onboarding_configuration")
    required = {
        "name",
        "owner",
        "plan_digest",
        "provider_file",
        "provider_sha256",
        "declaration_file",
        "declaration_sha256",
        "repository",
        "skills_commit",
        "delivery",
    }
    for name, placement in value["placements"].items():
        if (
            not being_seed.NAME.fullmatch(name)
            or set(placement) != required
            or placement["name"] != name
            or not being_seed.NAME.fullmatch(placement["owner"])
            or any(
                not isinstance(placement[key], str)
                or not Path(placement[key]).is_absolute()
                for key in ("provider_file", "declaration_file", "repository")
            )
            or any(
                not isinstance(placement[key], str)
                or not re.fullmatch("[a-f0-9]{64}", placement[key])
                for key in ("plan_digest", "provider_sha256", "declaration_sha256")
            )
            or not isinstance(placement["skills_commit"], str)
            or not re.fullmatch("[a-f0-9]{40}", placement["skills_commit"])
        ):
            raise OnboardingError("invalid_home_onboarding_placement")
        validate_delivery(placement["delivery"])
    return AcceptedHomes(
        progress=progress,
        worker_uid=worker_uid,
        placements=value["placements"],
        state=Path(value["state"]),
        provider=IncusProvider(store, backend),
    )


def validate_delivery(value):
    import re

    fields = {
        "home",
        "home_ref",
        "owner_being_ref",
        "gateway_config",
        "gateway_uid",
        "gateway_gid",
        "gateway_python",
        "gateway_code",
        "previous_unit_sha256",
    }
    if (
        not isinstance(value, dict)
        or set(value) != fields
        or not isinstance(value["home"], dict)
        or not isinstance(value["home_ref"], str)
        or not re.fullmatch("[A-Za-z0-9:_-]{1,128}", value["home_ref"])
        or any(
            type(value[key]) is not int or value[key] < 0
            for key in ("gateway_uid", "gateway_gid")
        )
        or any(
            not isinstance(value[key], str)
            or not Path(value[key]).is_absolute()
            or ".." in Path(value[key]).parts
            for key in ("gateway_config", "gateway_python", "gateway_code")
        )
        or not isinstance(value["owner_being_ref"], str)
        or value["home"].get("owner_being_ref") != value["owner_being_ref"]
        or value["previous_unit_sha256"] is not None
        and not re.fullmatch("[a-f0-9]{64}", value["previous_unit_sha256"])
    ):
        raise OnboardingError("invalid_home_delivery_placement")
    return value
