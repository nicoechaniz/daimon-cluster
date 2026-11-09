"""Web-only cold entry, retained effects, pairing and bounded-control regressions."""

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import patch

from clusterctl import onboarding_conversation as conversation


def request():
    return {
        "schema": conversation.SCHEMA,
        "name": "fixture",
        "plan_digest": "a" * 64,
        "being_ref": "dm:being:v1:" + "b" * 43,
        "home_ref": "home:" + "c" * 32,
        "human_ref": "human:local:11111111-1111-4111-8111-111111111111",
        "application_id": "22222222-2222-4222-8222-222222222222",
        "origin": "https://fixture.example.org",
        "label": "Fixture",
        "human_id": 9,
        "chat_id": 11,
        "topic_id": 17,
        "port": 8800,
        "execution": {"sandbox": "workspace-write", "approval": "on-request"},
        "runtime": {
            "binary": "/opt/daimon-app/native/telecodex",
            "binary_sha256": "d" * 64,
            "python": "/opt/daimon-app/base/venv/bin/python",
            "python_sha256": "e" * 64,
            "web": "/opt/daimon-app/web",
            "pythonpath": ["/opt/daimon-app/web"],
            "node_required": True,
            "components": [
                {
                    "root": "/opt/daimon-app/web",
                    "manifest": "/opt/daimon-app/web-manifest.json",
                    "manifest_sha256": "f" * 64,
                }
            ],
        },
    }


def test_preidentity_intent_has_stable_resource_ids_without_placeholder_identity():
    value=request()
    settings={key:value[key] for key in ('human_ref','origin','label','human_id',
        'chat_id','topic_id','port','runtime','execution')}
    intent=conversation.prepare_intent(value['name'],value['plan_digest'],settings)
    assert 'being_ref' not in intent
    assert intent==conversation.prepare_intent(value['name'],value['plan_digest'],settings)
    other=conversation.prepare_intent(value['name'],'d'*64,settings)
    assert other['home_ref']!=intent['home_ref']
    assert other['application_id']!=intent['application_id']
    resolved=conversation.resolve_request(intent,value['being_ref'])
    assert resolved['schema']==conversation.SCHEMA
    assert resolved['being_ref']==value['being_ref']
    assert resolved['home_ref']==intent['home_ref']
    assert resolved['human_ref']==value['human_ref']
    assert 'being_ref' not in intent  # Resolving never rewrites the original intent.
    with unittest.TestCase().assertRaises(conversation.ConversationError):
        conversation.Bootstrap(intent)  # A guest never accepts an unresolved intent.
    for invalid in ({**settings,'being_ref':value['being_ref']},
                    {**settings,'origin':'http://private.invalid'},
                    {**settings,'human_id':0}):
        with unittest.TestCase().assertRaises(conversation.ConversationError):
            conversation.prepare_intent(value['name'],value['plan_digest'],invalid)
    with unittest.TestCase().assertRaises(conversation.ConversationError):
        conversation.resolve_request(value,'dm:being:v1:'+'c'*43)


class Fixture(conversation.Bootstrap):
    def __init__(self, *, lost_ack=False, effect=True):
        super().__init__(request())
        self.running = {
            unit: False for unit in (conversation.NATIVE_UNIT, conversation.WEB_UNIT)
        }
        self.starts = []
        self.commands = []
        self.lost_ack, self.effect = lost_ack, effect

    def preflight(self):
        return {"files": 1, "bytes": 1}

    def services(self):
        return {
            unit: {
                "ActiveState": "active" if active else "inactive",
                "MainPID": "99" if active else "0",
            }
            for unit, active in self.running.items()
        }

    def command(self, argv, **options):
        self.commands.append(argv)
        if argv[:3] == ["/usr/bin/systemctl", "enable", "--now"]:
            unit = argv[3]
            self.starts.append(unit)
            self.running[unit] = self.effect
            if self.lost_ack:
                self.lost_ack = False
                raise subprocess.TimeoutExpired(argv, 1)
        return b"{}"

    def wait_ready(self, *, native_only):
        selected = [conversation.NATIVE_UNIT] if native_only else list(self.running)
        if not all(self.running[unit] for unit in selected):
            raise conversation.ConversationError("conversation_started_service_exited")
        return {"native_control": True}

    def observe(self):
        if not all(self.running.values()):
            raise conversation.ConversationError(
                "conversation_selected_service_unconfirmed"
            )
        return {"state": "ready", "model_calls": 0}


class ConversationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.units = self.root / "units"
        self.units.mkdir()
        self.journal = self.root / "journal"
        self.journal.mkdir(mode=0o700)
        original_read = conversation.read
        for name, replacement in [
            ("SYSTEMD", self.units),
            ("JOURNAL", self.journal),
            ("trusted", lambda path, **kw: Path(path)),
            (
                "read",
                lambda path, uid, limit=65536, allow_hardlinks=False: original_read(
                    path, uid=os.getuid(), limit=limit, allow_hardlinks=allow_hardlinks
                ),
            ),
        ]:
            started = patch.object(conversation, name, replacement)
            started.start()
            self.addCleanup(started.stop)

    def test_actual_pair_ids_private_files_and_no_telegram_are_rendered(self):
        value = request()
        files = conversation.configurations(value)
        native = tomllib.loads(files[conversation.STATE / "receiver.toml"].decode())
        web = tomllib.loads(files[conversation.STATE / "dashboard.toml"].decode())
        self.assertEqual(native["startup_admin_ids"], [9])
        self.assertEqual(
            native["interaction"], {"human_id": 9, "chat_id": 11, "topic_id": 17,
                "artifact_store": {
                    "directory": "/home/agent/.local/share/daimon-conversation/generated-files",
                    "retention_hours": 24, "max_file_bytes": 67108864,
                    "max_total_bytes": 536870912}}
        )
        self.assertEqual(native["telegram"], {"enabled": False})
        self.assertTrue(native["codex"]["shared_app_server"])
        self.assertEqual(native["codex"]["default_sandbox"], "workspace-write")
        self.assertEqual(native["codex"]["default_approval"], "on-request")
        self.assertEqual(web["shared_auth"]["human_ref"], value["human_ref"])
        self.assertEqual(web["application_id"], value["application_id"])
        self.assertTrue(web["shared_auth"]["artifact_access"])
        self.assertFalse(web["shared_auth"]["workspace_access"])
        self.assertNotIn("bot_id", web)
        self.assertNotIn("targets", native)
        self.assertIn(
            b"PATH=/home/agent/.local/bin:",
            conversation.unit_files(value)[conversation.NATIVE_UNIT],
        )

    def test_invalid_origin_foreign_paths_and_injected_configuration_are_refused(self):
        changes = [
            {"origin": "https://fixture.example.org/path"},
            {"origin": "https://user@fixture.example.org"},
            {"origin": "https://fixture.example.org?x=1"},
            {"human_id": True},
            {"label": "Other\n[telegram]\nenabled=true"},
            {"application_id": "not-uuid"},
        ]
        for change in changes:
            with (
                self.subTest(change=change),
                self.assertRaises(conversation.ConversationError),
            ):
                conversation.selection({**request(), **change})
        value = request()
        value["runtime"]["web"] = "/home/agent/unreviewed-code"
        with self.assertRaises(conversation.ConversationError):
            conversation.selection(value)
        value = request()
        value["runtime"]["components"].append(
            copy.deepcopy(value["runtime"]["components"][0])
        )
        with self.assertRaises(conversation.ConversationError):
            conversation.selection(value)

    def test_lost_start_ack_reconciles_live_native_then_starts_only_missing_web(self):
        fixture = Fixture(lost_ack=True)
        with self.assertRaises(subprocess.TimeoutExpired):
            fixture._apply_locked(self.journal)
        retained = json.loads((self.journal / "current.json").read_text())
        self.assertIn(conversation.NATIVE_UNIT, retained["start_intents"])
        self.assertEqual(fixture._apply_locked(self.journal)["state"], "ready")
        self.assertEqual(
            fixture.starts, [conversation.NATIVE_UNIT, conversation.WEB_UNIT]
        )
        self.assertEqual(
            json.loads((self.journal / "current.json").read_text())["phase"], "ready"
        )

    def test_unknown_start_outcome_is_not_replayed_when_process_is_absent(self):
        fixture = Fixture(lost_ack=True, effect=False)
        with self.assertRaises(subprocess.TimeoutExpired):
            fixture._apply_locked(self.journal)
        with self.assertRaisesRegex(
            conversation.ConversationError, "retained_start_unconfirmed"
        ):
            fixture._apply_locked(self.journal)
        self.assertEqual(fixture.starts, [conversation.NATIVE_UNIT])

    def test_foreign_existing_unit_refuses_before_config_or_lifecycle_effect(self):
        original = b"[Service]\nExecStart=/some/other/receiver\n"
        path = self.units / conversation.WEB_UNIT
        path.write_bytes(original)
        fixture = Fixture()
        with self.assertRaisesRegex(
            conversation.ConversationError, "existing_unit_preserved"
        ):
            fixture._apply_locked(self.journal)
        self.assertEqual(path.read_bytes(), original)
        self.assertFalse((self.journal / "current.json").exists())
        self.assertEqual(fixture.commands, [])

    def test_existing_inactive_identical_unit_is_not_an_implicit_resume(self):
        for name, raw in conversation.unit_files(request()).items():
            (self.units / name).write_bytes(raw)
        fixture = Fixture()
        with self.assertRaisesRegex(
            conversation.ConversationError, "existing_inactive_unit_preserved"
        ):
            fixture._apply_locked(self.journal)
        self.assertEqual(fixture.starts, [])

    def test_already_ready_apply_performs_no_install_reload_or_start(self):
        fixture = Fixture()
        fixture.running = {name: True for name in fixture.running}
        self.assertEqual(fixture.apply()["bootstrap"], "already-ready")
        self.assertEqual(fixture.commands, [])
        self.assertFalse((self.journal / "current.json").exists())

    def test_changed_operation_cannot_replace_original_start_intent(self):
        fixture = Fixture(lost_ack=True)
        with self.assertRaises(subprocess.TimeoutExpired):
            fixture._apply_locked(self.journal)
        original = (self.journal / "current.json").read_bytes()
        fixture.value["human_id"] = 100
        with self.assertRaisesRegex(
            conversation.ConversationError, "existing_operation_preserved"
        ):
            fixture._apply_locked(self.journal)
        self.assertEqual((self.journal / "current.json").read_bytes(), original)
        self.assertEqual(fixture.starts, [conversation.NATIVE_UNIT])

    def test_required_config_preserves_extra_voice_and_private_settings(self):
        expected = tomllib.loads(
            conversation.configurations(request())[
                conversation.STATE / "dashboard.toml"
            ].decode()
        )
        actual = copy.deepcopy(expected)
        actual["voice"] = {"selected": "existing-own-voice"}
        self.assertTrue(conversation.contains(actual, expected))
        actual["shared_auth"]["human_ref"] = "human:local:foreign"
        self.assertFalse(conversation.contains(actual, expected))

    def test_atomic_absent_publication_preserves_concurrent_file(self):
        target = self.root / "retained"
        target.write_bytes(b"original")
        with self.assertRaises(FileExistsError):
            conversation.atomic(target, b"new", mode=0o600, absent=True)
        self.assertEqual(target.read_bytes(), b"original")
        self.assertEqual(list(self.root.glob(".conversation-*")), [])

    def test_control_output_is_bounded_before_buffering_and_timeout_exits(self):
        with self.assertRaisesRegex(conversation.ConversationError, "output_capacity"):
            conversation.bounded_command(
                [sys.executable, "-c", 'import sys;sys.stderr.write("x"*400000)'],
                seconds=3,
            )
        with self.assertRaises(subprocess.TimeoutExpired):
            conversation.bounded_command(
                [sys.executable, "-c", "import time;time.sleep(10)"], seconds=0.05
            )
        reply = conversation.bounded_command(
            [
                sys.executable,
                "-c",
                "import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())",
            ],
            seconds=3,
            input_data=b"private selected input",
        )
        self.assertEqual(reply, b"private selected input")

    def test_root_control_never_searches_agent_writable_path(self):
        with patch.object(conversation, "bounded_command", return_value=b"") as execute:
            fixture = conversation.Bootstrap(request())
            fixture.command(["/usr/bin/systemctl", "show", conversation.NATIVE_UNIT])
        self.assertNotIn("/home/agent", execute.call_args.kwargs["env"]["PATH"])
        self.assertEqual(execute.call_args.args[0][0], "/usr/bin/systemctl")


if __name__ == "__main__":
    unittest.main()


class RuntimeEvidenceTests(unittest.TestCase):
    def test_manifest_binds_consumed_bytes_and_rejects_extra_or_symlink_files(self):
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp)
            root = parent / "component"
            root.mkdir()
            source = root / "app.py"
            source.write_bytes(b"qualified public source")
            alias = parent / 'other-retained-release.py'
            alias.hardlink_to(source)
            binary = parent / "binary"
            binary.write_bytes(b"qualified executable fixture")
            manifest = parent / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema": "cluster-conversation-component/v1",
                        "files": {"app.py": conversation.sha(source.read_bytes())},
                    }
                )
            )
            value = request()
            value["runtime"].update(
                binary=str(binary),
                python=str(binary),
                binary_sha256=conversation.sha(binary.read_bytes()),
                python_sha256=conversation.sha(binary.read_bytes()),
                components=[
                    {
                        "root": str(root),
                        "manifest": str(manifest),
                        "manifest_sha256": conversation.sha(manifest.read_bytes()),
                    }
                ],
            )
            original_read = conversation.read
            with (
                patch.object(
                    conversation, "trusted", side_effect=lambda path, **kw: Path(path)
                ),
                patch.object(
                    conversation,
                    "read",
                    side_effect=lambda path, uid, limit=65536, allow_hardlinks=False: original_read(
                        path, uid=os.getuid(), limit=limit, allow_hardlinks=allow_hardlinks
                    ),
                ),
            ):
                self.assertEqual(conversation.verify_runtime(value)["files"], 1)
                alias.write_bytes(b"different source")
                with self.assertRaisesRegex(
                    conversation.ConversationError, "component_changed"
                ):
                    conversation.verify_runtime(value)
                source.write_bytes(b"qualified public source")
                extra = root / "extra.py"
                extra.write_bytes(b"unselected extra code")
                with self.assertRaisesRegex(
                    conversation.ConversationError, "inventory_changed"
                ):
                    conversation.verify_runtime(value)
                extra.unlink()
                extra.symlink_to(parent)
                with self.assertRaisesRegex(
                    conversation.ConversationError, "inventory_changed"
                ):
                    conversation.verify_runtime(value)

    def test_private_inputs_still_refuse_aliases_and_public_files_keep_other_checks(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/'input.json'
            path.write_bytes(b'private input fixture')
            path.chmod(0o600)
            alias = Path(temp)/'alias.json'
            alias.hardlink_to(path)
            with self.assertRaisesRegex(conversation.ConversationError,'owned_file_required'):
                conversation.read(path,uid=os.getuid())
            self.assertEqual(conversation.read(path,uid=os.getuid(),allow_hardlinks=True),b'private input fixture')
            path.chmod(0o666)
            with self.assertRaisesRegex(conversation.ConversationError,'owned_file_required'):
                conversation.read(path,uid=os.getuid(),allow_hardlinks=True)

    def test_live_readiness_requires_both_private_routes_to_deny_anonymous(self):
        import urllib.error
        from unittest.mock import MagicMock

        fixture = conversation.Bootstrap(request())
        health = MagicMock()
        health.__enter__.return_value.status = 200
        health.__enter__.return_value.read.return_value = b'{"ok":true}'
        opener = MagicMock()
        opener.open.side_effect = [
            health,
            urllib.error.HTTPError("local", 401, "denied", {}, None),
            urllib.error.HTTPError("local", 403, "denied", {}, None),
        ]
        with (
            patch.object(
                fixture,
                "command",
                return_value=b'{"ok":true,"result":{"schema":"telecodex.presentation-list/v1"}}',
            ) as call,
            patch.object(
                conversation.urllib.request, "build_opener", return_value=opener
            ),
        ):
            self.assertTrue(fixture.ready()["anonymous_private_api_denied"])
            self.assertEqual(
                call.call_args.args[0][-4:], ["presentation", "list", "0", "0"]
            )
        opener.open.side_effect = [health, health]
        with (
            patch.object(
                fixture,
                "command",
                return_value=b'{"ok":true,"result":{"schema":"telecodex.presentation-list/v1"}}',
            ),
            patch.object(
                conversation.urllib.request, "build_opener", return_value=opener
            ),
            self.assertRaisesRegex(
                conversation.ConversationError, "anonymous_access_not_denied"
            ),
        ):
            fixture.ready()


def test_private_vm_listener_binds_units_and_preserves_resolved_intent():
    value=request()
    value['listen_host']='10.100.0.10'
    assert conversation.selection(value)==value
    units=conversation.unit_files(value)
    assert b'--host 10.100.0.10 --port 8800' in units[conversation.WEB_UNIT]
    settings={k:v for k,v in value.items() if k not in
        ('schema','name','plan_digest','being_ref','home_ref','application_id')}
    intent=conversation.prepare_intent(value['name'],value['plan_digest'],settings)
    resolved=conversation.resolve_request(intent,value['being_ref'])
    assert resolved['listen_host']==value['listen_host']
    assert resolved['being_ref']==value['being_ref']
    for host in ['0.0.0.0','8.8.8.8','::','::1','localhost','127.0.0.2','169.254.1.1',False]:
        with unittest.TestCase().assertRaises(conversation.ConversationError):
            conversation.selection({**value,'listen_host':host})
    assert conversation.listen_host(request())=='127.0.0.1'
