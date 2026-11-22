"""Validate held shared-account authority before existing empty-cache installation.

No account selection, key creation, service restart, prompt or goal operation.
The receiving operator supplies observed native workspace identity separately.
"""

from pathlib import Path
import json
import re
from clusterctl.onboarding_accounts import install_shared_cache


def validate(source, profile, grant, plan, observed_account):
    value = json.loads(source)
    if (
        profile.get("schema") != "cluster-onboarding-account/v1"
        or not isinstance(profile.get("account_id"), str)
        or not profile["account_id"]
        or not isinstance(profile.get("name"), str)
        or not profile["name"]
        or not isinstance(plan.get("name"), str)
        or not plan["name"]
        or not isinstance(plan.get("owner"), str)
        or not plan["owner"]
        or not isinstance(grant.get("pairs"), dict)
        or not isinstance(grant.get("human_instruction_digest"), str)
        or not re.fullmatch("[a-f0-9]{64}", grant["human_instruction_digest"])
    ):
        raise ValueError("held_shared_account_records_required")
    if (
        value.get("auth_mode") != "chatgpt"
        or not isinstance(value.get("tokens"), dict)
        or value["tokens"].get("account_id") != profile.get("account_id")
        or grant.get("schema") != "cluster-onboarding-shared-login/v1"
        or grant.get("revoked") is not False
        or grant.get("name") != profile.get("name")
        or grant.get("account_id") != profile.get("account_id")
        or grant.get("pairs", {}).get(plan.get("name")) != plan.get("owner")
        or plan.get("account_profile") != profile.get("name")
        or observed_account != profile.get("account_id")
    ):
        raise ValueError("same_existing_authorized_account_required")
    return profile["account_id"]


def install(
    source_path, destination, profile, grant, plan, observed_account, *, uid, gid
):
    """Retain any different receiving file. Missing legacy file is not missing identity."""
    account = validate(
        Path(source_path).read_bytes(), profile, grant, plan, observed_account
    )
    install_shared_cache(source_path, destination, uid=uid, gid=gid, account=account)
    return {"installed": True, "same_account": True, "service_restarts": 0}
