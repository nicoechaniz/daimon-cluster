from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from tools import preventive_sysops as s


class Sysops(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = {
            "schema": "cluster.preventive-sysops/v1",
            "state": str(Path(self.temp.name) / "state"),
            "paused": False,
            "targets": [
                {
                    "id": "own",
                    "transport": {"kind": "local", "prefix": []},
                    "jobs": [
                        {
                            "id": "audit",
                            "unit": "audit.service",
                            "scope": "system",
                            "interval_seconds": 3600,
                            "unit_sha256": "a" * 64,
                            "action": "start-if-due",
                        }
                    ],
                }
            ],
        }
        self.row = {
            "id": "audit",
            "Type": "oneshot",
            "ActiveState": "inactive",
            "Result": "success",
            "ExecMainStatus": "0",
            "InvocationID": "original",
            "ExecMainStartTimestampMonotonic": "1",
            "unit_sha256": "a" * 64,
            "read_ok": True,
            "age_seconds": 9000,
        }
        self.calls = []

    def command(self, argv, **kw):
        self.calls.append(argv)
        if "start" in argv:
            return b""
        return json.dumps(
            {
                "schema": "cluster.sysops-observation/v1",
                "jobs": [self.row],
                "dpkg_audit": {"requires_recovery": False, "exit": 0},
            }
        ).encode()

    def test_due_job_acts_without_alert_or_model_and_never_repeats_uncertain(self):
        a = s.run_pass(self.config, run=self.command)
        self.assertEqual(len(a["pending"]), 1)
        self.assertEqual(a["models_started"], 0)
        s.run_pass(self.config, run=self.command)
        self.assertEqual(sum("start" in x for x in self.calls), 1)
        self.row.update(
            InvocationID="actual-new",
            ExecMainStartTimestampMonotonic="2",
            age_seconds=1,
        )
        a = s.run_pass(self.config, run=self.command)
        self.assertFalse(a["pending"])

    def test_busy_and_changed_unit_are_not_started(self):
        self.row["ActiveState"] = "active"
        s.run_pass(self.config, run=self.command)
        self.row.update(ActiveState="inactive", unit_sha256="b" * 64)
        s.run_pass(self.config, run=self.command)
        self.assertFalse(any("start" in x for x in self.calls))

    def test_pause_preserves_pending_and_does_not_touch_target(self):
        s.run_pass(self.config, run=self.command)
        self.calls.clear()
        self.config["paused"] = True
        a = s.run_pass(self.config, run=self.command)
        self.assertTrue(a["pending"])
        self.assertFalse(self.calls)

    def test_unknown_dispatch_keeps_intent_and_no_retry(self):
        def failed(argv, **kw):
            if "start" in argv:
                raise TimeoutError()
            return self.command(argv, **kw)

        a = s.run_pass(self.config, run=failed)
        self.assertEqual(a["pending"]["own:audit"]["state"], "uncertain")
        s.run_pass(self.config, run=self.command)
        self.assertFalse(any("start" in x for x in self.calls))

    def test_failed_completed_job_gets_finite_backoff(self):
        s.run_pass(self.config, run=self.command)
        self.row.update(
            InvocationID="after",
            ExecMainStartTimestampMonotonic="2",
            Result="exit-code",
            ExecMainStatus="1",
        )
        a = s.run_pass(self.config, run=self.command)
        self.assertEqual(a["failures"]["own:audit"]["count"], 1)
        self.calls.clear()
        a = s.run_pass(self.config, run=self.command)
        self.assertIn("audit:retry-deferred", a["targets"][0]["attention"])
        self.assertFalse(any("start" in x for x in self.calls))

    def test_no_arbitrary_command_or_ssh_proxy(self):
        for prefix, kind in [
            (["/bin/sh", "-c", "incus"], "local"),
            (["ssh", "-oProxyCommand=evil", "agent@host"], "ssh"),
        ]:
            c = deepcopy(self.config)
            c["targets"][0]["transport"] = {"kind": kind, "prefix": prefix}
            with self.assertRaises(ValueError):
                s.validate(c)

    def test_remote_payload_is_quoted_as_one_fixed_command(self):
        t = {
            "transport": {
                "kind": "ssh",
                "prefix": [
                    "ssh",
                    "-T",
                    "agent@host",
                    "sudo",
                    "-n",
                    "incus",
                    "exec",
                    "dm-pixin",
                    "--",
                ],
            }
        }
        argv = s.target_command(t, ["python3", "-c", 'print("literal $()")'])
        self.assertEqual(argv[:3], ["ssh", "-T", "agent@host"])
        import shlex

        self.assertEqual(shlex.split(argv[-1])[-1], 'print("literal $()")')

    def test_retained_pending_does_not_follow_new_binding(self):
        s.run_pass(self.config, run=self.command)
        self.config["targets"][0]["jobs"][0]["unit_sha256"] = "b" * 64
        a = s.run_pass(self.config, run=self.command)
        self.assertEqual(a["pending"]["own:audit"]["unit_sha256"], "a" * 64)
        self.assertIn(
            "audit:pending-original-binding-preserved", a["targets"][0]["attention"]
        )


if __name__ == "__main__":
    unittest.main()
