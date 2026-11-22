from copy import deepcopy
import json
from pathlib import Path
import tempfile
import time
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

    def test_model_family_observation_does_not_dispatch(self):
        now = int(time.time())
        fixed = dict(target="own", route="native-review", family="sol", contract="a" * 64)
        proof = dict(previous_model="gpt-6.1-sol", previous_revision="b" * 64, observed_at=now)
        candidate = dict(**fixed, model="gpt-6.2-sol", version=[6, 2, 0],
                         available=True, qualification=proof, observed_at=now)
        workload = dict(**fixed, id="review", current="gpt-6.1-sol",
                        current_version=[6, 1, 0], current_revision="b" * 64, follow=True, candidates=[
                            candidate,
                            dict(candidate, model="gpt-6.3-sol", version=[6, 3, 0], observed_at=now - 90000),
                            dict(candidate, model="gpt-6.4-sol", version=[6, 4, 0], route="other-account"),
                            dict(candidate, model="gpt-6.5-astra", version=[6, 5, 0], family="astra"),
                            dict(candidate, model="gpt-6.6-sol", version=[6, 6, 0], available=False),
                        ])
        evidence = Path(self.temp.name) / "models.json"
        evidence.touch(mode=0o600)
        self.config["model_evidence"] = str(evidence)
        self.row["age_seconds"] = 1
        for changes, expected in (
            ({}, "qualified-for-owner-apply"),
            ({"follow": False}, "pinned"),
            ({"current_revision": "c" * 64}, "qualification-required"),
            ({"candidates": [dict(candidate, qualification=dict(proof, observed_at=now - 90000))]},
             "qualification-required"),
            ({"current": "gpt-6-sol", "current_version": [6, 0, 0]}, "qualification-required"),
            ({"candidates": [candidate, dict(candidate, model="gpt-6.2-sol-alias")]}, "ambiguous-release"),
        ):
            with self.subTest(changes=changes):
                evidence.write_text(json.dumps({"schema": "cluster.model-family-evidence/v1",
                                                "workloads": [dict(workload, **changes)]}))
                result = s.run_pass(self.config, run=self.command)
                self.assertEqual(result["model_upgrades"]["own:review"]["state"], expected)
                self.assertEqual(result["models_started"], 0)
                self.assertNotIn("current_revision", result["semantic"]["model:own:review"])
        self.assertFalse(any("start" in argv for argv in self.calls))
        evidence.chmod(0o644)
        result = s.run_pass(self.config, run=self.command)
        self.assertEqual(result["semantic"]["model_upgrades"], "evidence-unavailable")
        self.assertNotIn("model_upgrades", result)

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
