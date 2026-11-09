"""Finite web-only Conversation bootstrap in an existing, paired guest.

This is the guest adapter for companion delivery, not another enrollment or
scheduler. The host supplies qualified public runtime components and the actual
Home pairing. Existing differing configuration/services are preserved. A retry
observes a recorded start; it never restarts a receiver to manufacture readiness.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.request
from urllib.parse import urlsplit
import uuid


class ConversationError(ValueError):
    """Closed bootstrap refusal; never includes private command output."""


SCHEMA = "cluster-conversation-bootstrap/v1"
INTENT_SCHEMA = "cluster-conversation-intent/v1"
# Resource identifiers, never credentials or native identity authorities.
RESOURCE_NAMESPACE = uuid.UUID('9d2123d3-9af7-43a7-973c-3cdfe48f4f21')
HOME = Path("/home/agent")
STATE = HOME / ".local/state/daimon-conversation"
SYSTEMD = Path("/etc/systemd/system")
JOURNAL = Path("/var/lib/daimon-conversation-bootstrap")
NATIVE_UNIT = "children-conversation-native.service"
WEB_UNIT = "children-conversation-web.service"
# A cold browser requests the complete deferred module graph concurrently.
# Sixteen rejects startup assets before the application can become usable.
WEB_HTTP_CONCURRENCY = 64
SHA = re.compile(r"[a-f0-9]{64}\Z")
SAFE_PATH = re.compile(r"/[A-Za-z0-9_./-]+\Z")


def fail(reason):
    raise ConversationError(reason)


def read(path, *, uid, limit=65536, allow_hardlinks=False):
    """Private inputs are single-link; pinned public runtime bytes may be shared."""
    path = Path(path)
    if any(p.is_symlink() for p in (path, *path.parents)):
        fail("conversation_regular_file_required")
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != uid
            or info.st_mode & 0o022
            or info.st_nlink < 1
            or (not allow_hardlinks and info.st_nlink != 1)
            or info.st_size > limit
        ):
            fail("conversation_owned_file_required")
        value = stream.read(limit + 1)
    if len(value) > limit:
        fail("conversation_input_capacity")
    return value


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def selection(value, *, unresolved=False):
    keys = {
        "schema",
        "name",
        "plan_digest",
        "being_ref",
        "home_ref",
        "human_ref",
        "application_id",
        "origin",
        "label",
        "human_id",
        "chat_id",
        "topic_id",
        "port",
        "runtime",
        "execution",
    }
    if unresolved:
        keys.remove('being_ref')
    if (
        not isinstance(value, dict)
        or set(value) - {"listen_host"} != keys
        or value.get("schema") != (INTENT_SCHEMA if unresolved else SCHEMA)
        or not isinstance(value["name"], str)
        or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,30}", value["name"])
        or not isinstance(value["plan_digest"], str)
        or not SHA.fullmatch(value["plan_digest"])
        or (not unresolved and (not isinstance(value["being_ref"], str)
            or not re.fullmatch(r"dm:being:v1:[A-Za-z0-9_-]{43}", value["being_ref"])))
        or not isinstance(value["home_ref"], str)
        or not re.fullmatch(r"home:[a-f0-9]{32}", value["home_ref"])
        or not isinstance(value["human_ref"], str)
        or not re.fullmatch(r"human:[A-Za-z0-9:._/-]{1,240}", value["human_ref"])
        or not isinstance(value["label"], str)
        or not 1 <= len(value["label"]) <= 80
        or any(ord(c) < 32 for c in value["label"])
        or any(
            type(value[k]) is not int or not 1 <= value[k] <= 2**63 - 1
            for k in ("human_id", "chat_id", "topic_id")
        )
        or type(value["port"]) is not int
        or not 1024 <= value["port"] <= 65535
    ):
        fail("conversation_selection_required")
    if 'listen_host' in value:
        listen_host(value)
    try:
        if str(uuid.UUID(value["application_id"])) != value["application_id"]:
            raise ValueError
        origin = urlsplit(value["origin"])
        if (
            origin.scheme != "https"
            or not origin.hostname
            or origin.port not in (None, 443)
            or origin.username
            or origin.password
            or origin.path
            or origin.query
            or origin.fragment
            or origin.netloc != origin.hostname
            or any(ord(c) < 33 for c in value["origin"])
        ):
            raise ValueError
    except (ValueError, TypeError, AttributeError):
        fail("conversation_registered_entry_required")
    execution = value["execution"]
    if (
        not isinstance(execution, dict)
        or set(execution) != {"sandbox", "approval"}
        or not isinstance(execution["sandbox"], str)
        or not isinstance(execution["approval"], str)
        or execution["sandbox"]
        not in {"read-only", "workspace-write", "danger-full-access"}
        or execution["approval"] not in {"never", "on-request"}
    ):
        fail("conversation_selected_profile_required")
    runtime = value["runtime"]
    if not isinstance(runtime, dict) or set(runtime) != {
        "binary",
        "binary_sha256",
        "python",
        "python_sha256",
        "web",
        "pythonpath",
        "components",
        "node_required",
    }:
        fail("conversation_runtime_selection_required")
    for field in ("binary", "python", "web"):
        if (
            not isinstance(runtime[field], str)
            or not SAFE_PATH.fullmatch(runtime[field])
            or ".." in Path(runtime[field]).parts
            or not Path(runtime[field]).is_relative_to("/opt/daimon-app")
        ):
            fail("conversation_qualified_runtime_required")
    if (
        any(
            not isinstance(runtime[k], str) or not SHA.fullmatch(runtime[k])
            for k in ("binary_sha256", "python_sha256")
        )
        or type(runtime["node_required"]) is not bool
        or not isinstance(runtime["pythonpath"], list)
        or not 1 <= len(runtime["pythonpath"]) <= 4
        or any(not isinstance(p, str) for p in runtime["pythonpath"])
        or len(set(runtime["pythonpath"])) != len(runtime["pythonpath"])
        or runtime["web"] not in runtime["pythonpath"]
        or not isinstance(runtime["components"], list)
        or not 1 <= len(runtime["components"]) <= 4
    ):
        fail("conversation_qualified_runtime_required")
    roots = set()
    for component in runtime["components"]:
        if not isinstance(component, dict) or set(component) != {
            "root",
            "manifest",
            "manifest_sha256",
        }:
            fail("conversation_component_required")
        for k in ("root", "manifest"):
            if (
                not isinstance(component[k], str)
                or not SAFE_PATH.fullmatch(component[k])
                or ".." in Path(component[k]).parts
                or not Path(component[k]).is_relative_to("/opt/daimon-app")
            ):
                fail("conversation_component_required")
        if (
            component["root"] in roots
            or not isinstance(component["manifest_sha256"], str)
            or not SHA.fullmatch(component["manifest_sha256"])
        ):
            fail("conversation_component_required")
        roots.add(component["root"])
    if set(runtime["pythonpath"]) != roots:
        fail("conversation_component_roots_required")
    return value


def listen_host(value):
    """Explicit private VM listener; absent field preserves loopback unit bytes."""
    host = value.get('listen_host', '127.0.0.1')
    try:
        address = ipaddress.ip_address(host)
        if (not isinstance(host, str) or str(address) != host or address.version != 4
                or host != '127.0.0.1' and (not address.is_private or address.is_loopback
                    or address.is_unspecified or address.is_multicast or address.is_link_local)):
            raise ValueError
    except (ValueError, TypeError):
        fail('conversation_selection_required')
    return host


def prepare_intent(name, plan_digest, settings):
    """Derive stable app/Home references before the native identity exists.

    Only the explicit own pair/runtime/profile settings enter this intent.
    There is no native identity placeholder, credential, account or publication.
    """
    static = {'human_ref', 'origin', 'label', 'human_id', 'chat_id', 'topic_id',
              'port', 'runtime', 'execution'}
    if not isinstance(settings, dict) or set(settings) - {'listen_host'} != static:
        fail('conversation_selection_required')
    value = dict(settings, schema=INTENT_SCHEMA, name=name, plan_digest=plan_digest,
        home_ref='home:'+uuid.uuid5(RESOURCE_NAMESPACE, 'home:'+str(plan_digest)).hex,
        application_id=str(uuid.uuid5(RESOURCE_NAMESPACE, 'application:'+str(plan_digest))))
    return selection(value, unresolved=True)


def resolve_request(value, being_ref):
    """Bind the exact approved intent to the actual admitted native identity."""
    if isinstance(value, dict) and value.get('schema') == INTENT_SCHEMA:
        selection(value, unresolved=True)
        return selection({**value, 'schema': SCHEMA, 'being_ref': being_ref})
    selection(value)
    if value['being_ref'] != being_ref:
        fail('conversation_actual_identity_required')
    return value


def trusted(path, *, resolve=False):
    path = Path(path)
    if resolve:
        for parent in path.parents:
            trusted(parent)
        path = path.resolve(strict=True)
    for item in (path, *path.parents):
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            fail("conversation_root_runtime_required")
    return path


def verify_runtime(value):
    runtime = value["runtime"]
    for file, pin in (("binary", "binary_sha256"), ("python", "python_sha256")):
        # A venv interpreter may be a symlink to the root-owned system image.
        path = trusted(runtime[file], resolve=file == "python")
        if sha(read(path, uid=0, limit=64 * 1024**2, allow_hardlinks=True)) != runtime[pin]:
            fail("conversation_runtime_changed")
    total = count = 0
    for component in runtime["components"]:
        root = trusted(component["root"])
        raw = read(trusted(component["manifest"]), uid=0, limit=1024**2)
        if sha(raw) != component["manifest_sha256"]:
            fail("conversation_component_changed")
        manifest = json.loads(raw)
        if (
            set(manifest) != {"schema", "files"}
            or manifest["schema"] != "cluster-conversation-component/v1"
            or not isinstance(manifest["files"], dict)
            or not manifest["files"]
        ):
            fail("conversation_component_manifest_required")
        if len(manifest["files"]) > 4096:
            fail("conversation_component_capacity")
        actual = set()
        for index, item in enumerate(root.rglob("*")):
            if index >= 8192:
                fail("conversation_component_capacity")
            if item.is_symlink():
                fail("conversation_component_inventory_changed")
            if not item.is_dir():
                actual.add(str(item.relative_to(root)))
        if actual != set(manifest["files"]):
            fail("conversation_component_inventory_changed")
        for name, pin in manifest["files"].items():
            relative = Path(name)
            if (
                relative.is_absolute()
                or ".." in relative.parts
                or str(relative) != name
                or not isinstance(pin, str)
                or not SHA.fullmatch(pin)
            ):
                fail("conversation_component_manifest_required")
            path = trusted(root / relative)
            size = path.stat().st_size
            total += size
            count += 1
            if total > 96 * 1024**2 or count > 4096:
                fail("conversation_component_capacity")
            if sha(read(path, uid=0, limit=16 * 1024**2, allow_hardlinks=True)) != pin:
                fail("conversation_component_changed")
    return {"files": count, "bytes": total}


def configurations(value):
    def quote(text):
        return json.dumps(text, ensure_ascii=False)

    native = f'''db_path = "{STATE}/native.sqlite3"
startup_admin_ids = [{value["human_id"]}]
background_maintenance = false
tmp_dir = "{STATE}/tmp"
[goal_recovery]
enabled = false
[telegram]
enabled = false
[codex]
shared_app_server = true
binary = "/usr/local/bin/codex"
default_cwd = "{HOME}/Projects/being"
default_sandbox = "{value["execution"]["sandbox"]}"
default_approval = "{value["execution"]["approval"]}"
import_cli_history = true
import_desktop_history = false
[session_control]
socket_path = "{STATE}/control.sock"
human_id = {value["human_id"]}
[interaction]
human_id = {value["human_id"]}
chat_id = {value["chat_id"]}
topic_id = {value["topic_id"]}
[interaction.artifact_store]
directory = "{HOME}/.local/share/daimon-conversation/generated-files"
retention_hours = 24
max_file_bytes = 67108864
max_total_bytes = 536870912
'''
    web = f'''receiver_config = "{STATE}/receiver.toml"
native_home = "{HOME}/.codex"
state_dir = "{STATE}/web"
origin = {quote(value["origin"])}
prefix = "/sessions"
application_id = {quote(value["application_id"])}
label = {quote(value["label"])}
daimon_name = {quote(value["label"])}
additional_origins = [{quote(value["origin"])}]
[storage]
Workspace = "{HOME}/Projects/being"
[shared_auth]
enabled = true
home_origin = {quote(value["origin"])}
human_ref = {quote(value["human_ref"])}
entry_path = "/interaction/"
artifact_access = true
workspace_access = false
'''
    return {
        STATE / "receiver.toml": native.encode(),
        STATE / "dashboard.toml": web.encode(),
    }


def unit_files(value):
    runtime = value["runtime"]
    common = (
        f"User=agent\nGroup=agent\nEnvironment=HOME={HOME}\nEnvironment=CODEX_HOME={HOME}/.codex\n"
        f"Environment=PATH={HOME}/.local/bin:/usr/local/bin:/usr/bin:/bin\n"
        "Restart=on-failure\nRestartSec=10\nUMask=0077\n"
    )
    native = (
        "[Unit]\nDescription=Own general Conversation native backend\nStartLimitIntervalSec=300\n"
        f"StartLimitBurst=3\nWants={WEB_UNIT}\n[Service]\nType=simple\n"
        + common
        + f"WorkingDirectory={HOME}/Projects/being\nExecStart={runtime['binary']} {STATE}/receiver.toml\n"
        "TimeoutStopSec=30\nMemoryMax=2G\nCPUQuota=200%\nTasksMax=512\n"
        "[Install]\nWantedBy=multi-user.target\n"
    )
    web = (
        f"[Unit]\nDescription=Own private general Conversation web\nAfter={NATIVE_UNIT}\n"
        f"Requires={NATIVE_UNIT}\nPartOf={NATIVE_UNIT}\nStartLimitIntervalSec=300\nStartLimitBurst=3\n"
        "[Service]\nType=simple\n"
        + common
        + "Environment=PYTHONDONTWRITEBYTECODE=1\n"
        + "Environment=PYTHONPATH="
        + ":".join(runtime["pythonpath"])
        + "\n"
        + f"Environment=TELECODEX_DASHBOARD_CONFIG={STATE}/dashboard.toml\n"
        f"WorkingDirectory={runtime['web']}\nExecStart={runtime['python']} -B -m uvicorn "
        f"dashboard.app:create_app --factory --host {listen_host(value)} --port {value['port']} "
        f"--no-access-log --limit-concurrency {WEB_HTTP_CONCURRENCY} --timeout-graceful-shutdown 3\n"
        "TimeoutStopSec=15\nMemoryMax=384M\nCPUQuota=100%\nTasksMax=64\n"
        "[Install]\nWantedBy=multi-user.target\n"
    )
    return {NATIVE_UNIT: native.encode(), WEB_UNIT: web.encode()}


def contains(actual, required):
    """Preserve existing extra settings, while rejecting a different own entry."""
    return all(
        k in actual
        and (
            isinstance(v, dict)
            and isinstance(actual[k], dict)
            and contains(actual[k], v)
            or not isinstance(v, dict)
            and type(actual[k]) is type(v)
            and actual[k] == v
        )
        for k, v in required.items()
    )


class Bootstrap:
    def __init__(self, value, *, seconds=120):
        self.value = selection(value)
        if (
            type(seconds) not in (int, float)
            or not math.isfinite(seconds)
            or not 1 <= seconds <= 180
        ):
            fail("conversation_deadline_required")
        self.deadline = time.monotonic() + seconds
        self.phase = "selection"

    def remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            fail("conversation_deadline_expired")
        return remaining

    def command(self, argv, *, agent=False, input_data=None):
        options = {}
        if agent:
            options.update(user=1000, group=1000, extra_groups=[])
        return bounded_command(
            argv,
            seconds=min(15, self.remaining()),
            input_data=input_data,
            env={
                "HOME": str(HOME),
                "CODEX_HOME": str(HOME / ".codex"),
                "LANG": "C.UTF-8",
                "PATH": f"{HOME}/.local/bin:/usr/local/bin:/usr/bin:/bin"
                if agent
                else "/usr/sbin:/usr/bin:/sbin:/bin",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            **options,
        )

    def preflight(self):
        self.phase = "context"
        self.remaining()
        marker = json.loads(
            read(
                HOME
                / f".local/state/daimon-onboarding/{self.value['name']}/context.json",
                uid=1000,
            )
        )
        if marker.get("plan_digest") != self.value["plan_digest"]:
            fail("conversation_existing_context_required")
        for path in (HOME / ".codex", HOME / "Projects/being"):
            if path.is_symlink() or not path.is_dir() or path.stat().st_uid != 1000:
                fail("conversation_existing_own_workspace_required")
        profile = tomllib.loads(read(HOME / ".codex/config.toml", uid=1000).decode())
        if (
            profile.get("sandbox_mode") != self.value["execution"]["sandbox"]
            or profile.get("approval_policy") != self.value["execution"]["approval"]
        ):
            fail("conversation_existing_profile_preserved")
        self.phase = "runtime"
        runtime = verify_runtime(self.value)
        self.phase = "native-engine"
        version = self.command(
            ["/usr/local/bin/codex", "app-server", "daemon", "version"], agent=True
        )
        if not version.strip() or len(version) > 8192:
            fail("conversation_native_engine_unconfirmed")
        # Reuse the selected App reader's initialize-only path. Do not create a
        # thread, request thread/loaded/list, submit input or prime Conversation.
        initialized = json.loads(
            self.command(
                [
                    self.value["runtime"]["python"],
                    "-B",
                    "-I",
                    "-c",
                    "import sys,json;sys.path.insert(0,sys.argv[1]);"
                    "from activity_indicator import Native;"
                    "n=Native('/usr/local/bin/codex');n.close();"
                    "print(json.dumps({'initialized':True}))",
                    str(Path(self.value["runtime"]["web"]) / "scripts"),
                ],
                agent=True,
            )
        )
        if initialized != {"initialized": True}:
            fail("conversation_native_engine_unconfirmed")
        self.phase = "pairing"
        pairing = json.loads(
            self.command([str(HOME / ".local/bin/daimon-home"), "human"], agent=True)
        )
        if (
            pairing.get("schema") != "dm.human-endpoint/v1"
            or pairing.get("home_ref") != self.value["home_ref"]
            or pairing.get("owner_being_ref") != self.value["being_ref"]
            or pairing.get("human", {}).get("ref") != self.value["human_ref"]
        ):
            fail("conversation_actual_home_pairing_required")
        self.phase = "node"
        if self.value["runtime"]["node_required"]:
            version = (
                self.command(["/usr/bin/node", "--version"], agent=True)
                .decode()
                .strip()
            )
            match = re.fullmatch(r"v([0-9]+)\.[0-9]+\.[0-9]+", version)
            if match is None or int(match[1]) < 20:
                fail("conversation_node20_required")
        self.phase = "configuration"
        for path, raw in configurations(self.value).items():
            if path.exists() and not contains(
                tomllib.loads(read(path, uid=1000).decode()),
                tomllib.loads(raw.decode()),
            ):
                fail("conversation_existing_configuration_preserved")
        self.remaining()
        self._verified_runtime = runtime
        return runtime

    def ready(self, *, native_only=False):
        self.phase = "native-readiness"
        native = json.loads(
            self.command(
                [
                    self.value["runtime"]["binary"],
                    "--control",
                    str(STATE / "receiver.toml"),
                    "presentation",
                    "list",
                    "0",
                    "0",
                ],
                agent=True,
            )
        )
        if (
            native.get("ok") is not True
            or not isinstance(native.get("result"), dict)
            or native["result"].get("schema") != "telecodex.presentation-list/v1"
        ):
            fail("conversation_native_readiness_unconfirmed")
        if native_only:
            return {"native_control": True}

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, request, fp, code, message, headers, new_url):
                return None

        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

        def get(path):
            request = urllib.request.Request(
                f"http://{listen_host(self.value)}:{self.value['port']}" + path,
                headers={"Host": urlsplit(self.value["origin"]).netloc},
            )
            return opener.open(request, timeout=min(3, self.remaining()))

        self.phase = "web-readiness"
        with get("/health") as response:
            if response.status != 200 or json.loads(response.read(8193)) != {
                "ok": True
            }:
                fail("conversation_web_readiness_unconfirmed")
        self.phase = "anonymous-access"
        for path in ("/api/interaction/access", "/api/state"):
            try:
                with get(path):
                    fail("conversation_anonymous_access_not_denied")
            except urllib.error.HTTPError as error:
                if error.code not in (401, 403):
                    fail("conversation_anonymous_access_not_denied")
        return {
            "native_control": True,
            "web_health": True,
            "anonymous_private_api_denied": True,
            "model_calls": 0,
            "public_entry": self.value["origin"]
            + "/interaction/?view=conversation&client=standalone",
            "shared_browser_sign_in": "not-verified-by-guest",
            "family_device": "unobserved",
        }

    def services(self):
        self.phase = "selected-services"
        result = {}
        for unit in (NATIVE_UNIT, WEB_UNIT):
            raw = self.command(
                [
                    "/usr/bin/systemctl",
                    "show",
                    unit,
                    "-p",
                    "ActiveState",
                    "-p",
                    "MainPID",
                    "-p",
                    "InvocationID",
                    "-p",
                    "User",
                    "-p",
                    "Group",
                    "-p",
                    "WorkingDirectory",
                    "-p",
                    "ExecStart",
                    "-p",
                    "Environment",
                ]
            ).decode()
            result[unit] = dict(
                line.split("=", 1) for line in raw.splitlines() if "=" in line
            )
        return result

    def observe(self):
        runtime = self.preflight()
        services = self.services()
        missing = [path for path in (*configurations(self.value),
                    *(SYSTEMD / unit for unit in (NATIVE_UNIT, WEB_UNIT)))
                   if not path.exists()]
        if missing:
            # This is the same adapter's absent-file bootstrap, not authority
            # to restart an existing inactive selection or replace a service.
            # apply() rechecks all preimages and its retained effect journal.
            return {
                'schema': 'cluster-conversation-observation/v1',
                'state': 'absent', 'safe_to_execute': True,
                'missing_files': len(missing), 'runtime': runtime,
                'model_calls': 0,
            }
        expected = {
            NATIVE_UNIT: (
                self.value["runtime"]["binary"] + " " + str(STATE / "receiver.toml"),
                str(HOME / "Projects/being"),
            ),
            WEB_UNIT: (
                self.value["runtime"]["python"] + " -B -m uvicorn "
                f"dashboard.app:create_app --factory --host {listen_host(self.value)} --port "
                + str(self.value["port"])
                + f" --no-access-log --limit-concurrency {WEB_HTTP_CONCURRENCY} --timeout-graceful-shutdown 3",
                self.value["runtime"]["web"],
            ),
        }
        import shlex

        for unit, (argv, cwd) in expected.items():
            observed = services[unit]
            # systemctl's presentation includes timestamps and PIDs. Compare
            # only the actual command and selected execution configuration.
            match = re.search(r"argv\[\]=(.*?) ;", observed.get("ExecStart", ""))
            env = dict(
                item.split("=", 1)
                for item in shlex.split(observed.get("Environment", ""))
                if "=" in item
            )
            if (
                observed.get("ActiveState") != "active"
                or int(observed.get("MainPID", "0")) <= 0
                or observed.get("User") != "agent"
                or observed.get("Group") != "agent"
                or observed.get("WorkingDirectory") != cwd
                or match is None
                or match[1] != argv
                or env.get("HOME") != str(HOME)
                or env.get("CODEX_HOME") != str(HOME / ".codex")
            ):
                fail("conversation_selected_service_unconfirmed")
            if unit == WEB_UNIT and (
                env.get("PYTHONPATH") != ":".join(self.value["runtime"]["pythonpath"])
                or env.get("TELECODEX_DASHBOARD_CONFIG")
                != str(STATE / "dashboard.toml")
                or env.get("PYTHONDONTWRITEBYTECODE") != "1"
            ):
                fail("conversation_selected_service_unconfirmed")
        return {
            "schema": "cluster-conversation-observation/v1",
            "state": "ready",
            "runtime": runtime,
            **self.ready(),
            "service_pids": {
                unit: int(row["MainPID"]) for unit, row in services.items()
            },
        }

    def wait_ready(self, *, native_only):
        while True:
            try:
                return self.ready(native_only=native_only)
            except (ConversationError, OSError, ValueError, subprocess.SubprocessError):
                current = self.services()
                required = (NATIVE_UNIT,) if native_only else (NATIVE_UNIT, WEB_UNIT)
                if any(
                    current[unit].get("ActiveState") not in ("active", "activating")
                    for unit in required
                ):
                    fail("conversation_started_service_exited")
                time.sleep(min(0.2, self.remaining()))

    def apply(self):
        try:
            return {**self.observe(), "bootstrap": "already-ready"}
        except (ConversationError, OSError, ValueError, subprocess.SubprocessError):
            # A live, matching receiver needs no bootstrap journal, config write,
            # daemon reload or lifecycle request. Missing/failed readiness alone
            # never authorizes replacing a differing existing selection.
            if not hasattr(self, "_verified_runtime"):
                self.preflight()
        state = JOURNAL
        if not state.exists():
            state.mkdir(mode=0o700)
        trusted(state)
        if state.stat().st_mode & 0o077:
            fail("conversation_private_operation_required")
        lock_fd = os.open(
            state / "writer.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
        )
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return self._apply_locked(state)
        finally:
            os.close(lock_fd)

    def _apply_locked(self, state):
        receipt = state / "current.json"
        fingerprint = sha(
            json.dumps(self.value, sort_keys=True, separators=(",", ":")).encode()
        )
        units = unit_files(self.value)
        directory = trusted(SYSTEMD)
        # Refuse all differing existing files before the first write. Software
        # updates use the existing maintenance path, not this initial bootstrap.
        for unit, raw in units.items():
            path = directory / unit
            if (path.exists() or path.is_symlink()) and read(path, uid=0) != raw:
                fail("conversation_existing_unit_preserved")
        if receipt.exists():
            operation = json.loads(read(receipt, uid=0))
            if operation.get("request_sha256") != fingerprint:
                fail("conversation_existing_operation_preserved")
        else:
            operation = {
                "schema": "cluster-conversation-bootstrap-result/v1",
                "request_sha256": fingerprint,
                "phase": "prepared",
                "started": time.time(),
                "initial_units_absent": {
                    name: not (directory / name).exists() for name in units
                },
                "start_intents": {},
                "models": 0,
            }

        def save():
            atomic(receipt, json.dumps(operation, sort_keys=True).encode(), mode=0o600)

        save()
        self.command(
            ["/usr/bin/python3", "-B", "-I", "-c", AGENT_PREPARE],
            agent=True,
            input_data=json.dumps(
                {p.name: raw.decode() for p, raw in configurations(self.value).items()}
            ).encode(),
        )
        for unit, raw in units.items():
            path = directory / unit
            if not path.exists():
                atomic(path, raw, mode=0o644, absent=True)
        self.command(["/usr/bin/systemctl", "daemon-reload"])
        operation["phase"] = "files-ready"
        save()
        for unit in (NATIVE_UNIT, WEB_UNIT):
            current = self.services()[unit]
            if (
                current.get("ActiveState") == "active"
                and int(current.get("MainPID", "0")) > 0
            ):
                pass  # Exact retained live process; no start or restart.
            elif unit in operation["start_intents"]:
                fail("conversation_retained_start_unconfirmed")
            elif not operation["initial_units_absent"][unit]:
                fail("conversation_existing_inactive_unit_preserved")
            else:
                operation["phase"] = "starting"
                operation["start_intents"][unit] = {"requested": time.time()}
                save()  # Write-ahead intent survives a lost systemctl ACK.
                self.command(["/usr/bin/systemctl", "enable", "--now", unit])
            self.wait_ready(native_only=unit == NATIVE_UNIT)
        result = self.observe()
        operation.update(phase="ready", finished=time.time(), observation=result)
        save()
        return {**result, "bootstrap_request_sha256": fingerprint}


def bounded_command(argv, *, seconds, input_data=None, env=None, **options):
    """Cap both pipes while reading, not after a possibly unbounded communicate.

    Killing an expired control CLI is not cancellation of its systemd job. Its
    caller's write-ahead start intent remains authoritative for recovery.
    """
    if input_data is not None and (
        not isinstance(input_data, bytes) or len(input_data) > 16384
    ):
        fail("conversation_input_capacity")
    deadline = time.monotonic() + seconds
    process = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        **options,
    )
    stdout = bytearray()
    size = offset = 0
    try:
        with selectors.DefaultSelector() as selector:
            for stream in (process.stdout, process.stderr):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            if input_data is not None:
                os.set_blocking(process.stdin.fileno(), False)
                selector.register(process.stdin, selectors.EVENT_WRITE)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(argv, seconds)
                for key, _ in selector.select(remaining):
                    stream = key.fileobj
                    if stream is process.stdin:
                        try:
                            offset += os.write(stream.fileno(), input_data[offset:])
                        except BrokenPipeError:
                            offset = len(input_data)
                        if offset == len(input_data):
                            selector.unregister(stream)
                            stream.close()
                    else:
                        chunk = os.read(stream.fileno(), min(65536, 262145 - size))
                        if not chunk:
                            selector.unregister(stream)
                        else:
                            size += len(chunk)
                            if size > 262144:
                                fail("conversation_output_capacity")
                            if stream is process.stdout:
                                stdout.extend(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(argv, seconds)
        if process.wait(timeout=remaining):
            fail("conversation_operation_unconfirmed")
        return bytes(stdout)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=2)
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                stream.close()


def atomic(path, raw, *, mode, absent=False):
    if len(raw) > 65536:
        fail("conversation_operation_capacity")
    temporary = path.with_name(".conversation-" + uuid.uuid4().hex)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        if absent:
            os.link(temporary, path)  # A racing installed file is preserved.
        else:
            if path.is_symlink():
                fail("conversation_existing_operation_preserved")
            os.replace(temporary, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        temporary.unlink(missing_ok=True)


AGENT_PREPARE = r"""
import json,os,sys,tomllib
from pathlib import Path
assert os.geteuid()==1000
os.umask(0o077)
root=Path('/home/agent/.local/state/daimon-conversation')
selected=json.loads(sys.stdin.read(16385))
assert set(selected)=={'receiver.toml','dashboard.toml'}
for path in (root,root/'tmp',root/'web'):
    current=Path('/home/agent')
    for part in path.relative_to(current).parts:
        current/=part
        if not current.exists():current.mkdir(mode=0o700)
        assert current.is_dir() and not current.is_symlink() and current.stat().st_uid==1000
for name,raw in selected.items():
    path=root/name
    if path.exists():
        # The root preflight compared required semantics. Do not replace later
        # private settings or original media/database/history on reconciliation.
        assert not path.is_symlink() and path.stat().st_uid==1000 and not path.stat().st_mode&0o077
        actual=tomllib.loads(path.read_text());required=tomllib.loads(raw)
        def contains(a,r):return all(k in a and (contains(a[k],v) if isinstance(v,dict) and isinstance(a[k],dict) else type(a[k]) is type(v) and a[k]==v) for k,v in r.items())
        assert contains(actual,required)
    else:
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as stream:
            stream.write(raw);stream.flush();os.fsync(stream.fileno())
print(json.dumps({'own_configs_ready':True,'telegram':False}))
"""


PUBLIC_CODES = frozenset(
    [
        "conversation_selected_profile_required",
        "conversation_existing_profile_preserved",
        "conversation_native_engine_unconfirmed",
        "conversation_anonymous_access_not_denied",
        "conversation_actual_home_pairing_required",
        "conversation_actual_identity_required",
        "conversation_component_capacity",
        "conversation_component_changed",
        "conversation_component_inventory_changed",
        "conversation_component_manifest_required",
        "conversation_component_required",
        "conversation_component_roots_required",
        "conversation_deadline_expired",
        "conversation_deadline_required",
        "conversation_existing_configuration_preserved",
        "conversation_existing_context_required",
        "conversation_existing_inactive_unit_preserved",
        "conversation_existing_operation_preserved",
        "conversation_existing_own_workspace_required",
        "conversation_existing_unit_preserved",
        "conversation_guest_operator_required",
        "conversation_input_capacity",
        "conversation_native_readiness_unconfirmed",
        "conversation_node20_required",
        "conversation_operation_capacity",
        "conversation_operation_unconfirmed",
        "conversation_output_capacity",
        "conversation_owned_file_required",
        "conversation_private_operation_required",
        "conversation_private_selection_required",
        "conversation_qualified_runtime_required",
        "conversation_registered_entry_required",
        "conversation_regular_file_required",
        "conversation_retained_start_unconfirmed",
        "conversation_root_runtime_required",
        "conversation_runtime_changed",
        "conversation_runtime_selection_required",
        "conversation_selected_service_unconfirmed",
        "conversation_selection_required",
        "conversation_started_service_exited",
        "conversation_web_readiness_unconfirmed",
    ]
)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--request", type=Path)
    source.add_argument("--request-stdin", action="store_true",
                        help="Read the bounded selection from the host-owned execution pipe")
    parser.add_argument("--timeout-seconds", type=float, default=120)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Bootstrap absent services; otherwise observe only",
    )
    args = parser.parse_args(argv)
    bootstrap = None
    started = time.monotonic()
    try:
        if os.geteuid() != 0:
            fail("conversation_guest_operator_required")
        if args.request_stdin:
            raw = sys.stdin.buffer.read(65537)
            if len(raw) > 65536:
                fail("conversation_input_capacity")
            value = json.loads(raw)
        else:
            if args.request.stat().st_mode & 0o077:
                fail("conversation_private_selection_required")
            value = json.loads(read(args.request, uid=0))
        bootstrap = Bootstrap(value, seconds=args.timeout_seconds)
        result = bootstrap.apply() if args.apply else bootstrap.observe()
        print(json.dumps(result))
        return 0
    except (
        ConversationError,
        OSError,
        ValueError,
        KeyError,
        TypeError,
        subprocess.SubprocessError,
    ) as error:
        code = (
            str(error)
            if isinstance(error, ConversationError) and str(error) in PUBLIC_CODES
            else (
                "conversation_deadline_expired"
                if isinstance(error, subprocess.TimeoutExpired)
                else "conversation_operation_refused"
            )
        )
        # Effect receipts precede starts. A timeout/lost ACK leaves those exact
        # intents for reconciliation; do not hide it behind an 'effect:none'.
        if args.apply and bootstrap is not None:
            receipt = JOURNAL / "current.json"
            try:
                current = json.loads(read(receipt, uid=0))
                fingerprint = sha(
                    json.dumps(
                        bootstrap.value, sort_keys=True, separators=(",", ":")
                    ).encode()
                )
                if current.get("request_sha256") == fingerprint:
                    current.update(phase="refused", reason=code, finished=time.time())
                    atomic(
                        receipt,
                        json.dumps(current, sort_keys=True).encode(),
                        mode=0o600,
                    )
            except (OSError, ValueError):
                pass  # CLI still reports failure; never replace foreign intent.
        print(
            json.dumps(
                {
                    "schema": "cluster-conversation-observation/v1",
                    "state": "refused",
                    "reason": code,
                    "elapsed_seconds": time.monotonic() - started,
                    "effect": "inspect-retained-bootstrap" if args.apply else "none",
                }
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
