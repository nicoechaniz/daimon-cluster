from copy import deepcopy
import json
import os
from pathlib import Path
import tempfile
import unittest

from tools.renew_shared_native_auth import validate, install


class SharedRenewal(unittest.TestCase):
    def setUp(self):
        self.source = json.dumps(
            {"auth_mode": "chatgpt", "tokens": {"account_id": "selected"}}
        ).encode()
        self.profile = {
            "schema": "cluster-onboarding-account/v1",
            "name": "shared",
            "account_id": "selected",
        }
        self.grant = {
            "schema": "cluster-onboarding-shared-login/v1",
            "name": "shared",
            "account_id": "selected",
            "revoked": False,
            "human_instruction_digest": "a" * 64,
            "pairs": {"child": "human"},
        }
        self.plan = {"name": "child", "owner": "human", "account_profile": "shared"}

    def test_native_identity_not_missing_file_authorizes_existing_account(self):
        self.assertEqual(
            validate(self.source, self.profile, self.grant, self.plan, "selected"),
            "selected",
        )

    def test_foreign_source_native_identity_revocation_and_mixed_pair_refuse(self):
        for field in ["native", "source", "revoked", "pair", "profile"]:
            grant = deepcopy(self.grant)
            plan = dict(self.plan)
            source = self.source
            native = "selected"
            if field == "native":
                native = "other"
            if field == "source":
                source = json.dumps(
                    {"auth_mode": "chatgpt", "tokens": {"account_id": "other"}}
                ).encode()
            if field == "revoked":
                grant["revoked"] = True
            if field == "pair":
                plan["owner"] = "different-human"
            if field == "profile":
                plan["account_profile"] = "different-profile"
            with self.assertRaises(ValueError):
                validate(source, self.profile, grant, plan, native)

    def test_missing_authority_fields_are_not_inferred(self):
        with self.assertRaises(ValueError):
            validate(self.source, {}, self.grant, self.plan, None)
        grant = dict(self.grant)
        grant.pop("human_instruction_digest")
        with self.assertRaises(ValueError):
            validate(self.source, self.profile, grant, self.plan, "selected")

    def test_real_installer_missing_cache_and_existing_file_preservation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            source = root / "source"
            source.write_bytes(self.source)
            source.chmod(0o600)
            dest = root / "auth.json"
            install(
                source,
                dest,
                self.profile,
                self.grant,
                self.plan,
                "selected",
                uid=os.geteuid(),
                gid=os.getegid(),
            )
            self.assertEqual(dest.read_bytes(), self.source)
            self.assertEqual(dest.stat().st_mode & 0o777, 0o600)
            dest.write_bytes(b"newer-private-file")
            with self.assertRaises(ValueError):
                install(
                    source,
                    dest,
                    self.profile,
                    self.grant,
                    self.plan,
                    "selected",
                    uid=os.geteuid(),
                    gid=os.getegid(),
                )
            self.assertEqual(dest.read_bytes(), b"newer-private-file")


if __name__ == "__main__":
    unittest.main()
