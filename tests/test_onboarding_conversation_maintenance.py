import fcntl
import hashlib
import os
from pathlib import Path
import sys

import pytest

from clusterctl.onboarding import OnboardingError
from clusterctl.onboarding_conversation_maintenance import guard


def target(tmp_path):
    script = tmp_path / "scripts/interaction_web_maintenance.py"
    script.parent.mkdir()
    script.write_text("""import os,sys,fcntl,argparse
p=argparse.ArgumentParser();p.add_argument('--config');p.add_argument('--owner-uid');p.add_argument('--health-url');p.add_argument('--seconds');p.add_argument('command',nargs=argparse.REMAINDER);a=p.parse_args()
fd=os.open(a.config,os.O_RDWR)
try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
except BlockingIOError:sys.exit(75)
os.set_inheritable(fd,True)
os.execv(a.command[1],a.command[1:])
""")
    config = tmp_path / "existing.lock"
    config.write_bytes(b"")
    return dict(
        name="fixture",
        upstream="127.0.0.1:8800",
        command=[sys.executable, "-B", "-I", "-c", "{program}"],
        python=sys.executable,
        script=str(script),
        script_sha256=hashlib.sha256(script.read_bytes()).hexdigest(),
        config=str(config),
        owner_uid=os.getuid(),
        health_url="http://127.0.0.1:8800/health",
    )


def test_finite_transport_retains_kernel_exclusion_and_releases_on_context_exit(
    tmp_path,
):
    row = target(tmp_path)
    with open(row["config"], "r+b") as stream:
        with guard([row]) as check:
            check()
            with pytest.raises(BlockingIOError):
                fcntl.flock(stream, fcntl.LOCK_SH | fcntl.LOCK_NB)
        fcntl.flock(stream, fcntl.LOCK_SH | fcntl.LOCK_NB)
        fcntl.flock(stream, fcntl.LOCK_UN)


def test_actual_busy_holder_is_not_interrupted(tmp_path):
    row = target(tmp_path)
    with open(row["config"], "r+b") as stream:
        fcntl.flock(stream, fcntl.LOCK_SH)
        with pytest.raises(OnboardingError, match="conversation_route_voice_active"):
            with guard([row]):
                raise AssertionError("Busy capture lock was bypassed")
        # The original holder continues to own its lock and file.
        assert Path(row["config"]).exists()
        fcntl.flock(stream, fcntl.LOCK_UN)


def test_source_change_refuses_before_running_target_code(tmp_path):
    row = target(tmp_path)
    Path(row["script"]).write_text('raise AssertionError("not selected")')
    with pytest.raises(
        OnboardingError, match="conversation_route_maintenance_unavailable"
    ):
        with guard([row]):
            raise AssertionError("Changed source admitted")


def test_second_busy_target_releases_the_first_owned_lease(tmp_path):
    first = tmp_path / "one"
    second = tmp_path / "two"
    first.mkdir()
    second.mkdir()
    one = target(first)
    two = target(second)
    two["name"] = "second"
    two["upstream"] = one["upstream"]  # Distinct readers behind the same Host-routed proxy.
    with open(two["config"], "r+b") as busy:
        fcntl.flock(busy, fcntl.LOCK_SH)
        with pytest.raises(OnboardingError, match="conversation_route_voice_active"):
            with guard([one, two]):
                raise AssertionError("Busy target admitted")
        with open(one["config"], "r+b") as released:
            fcntl.flock(released, fcntl.LOCK_EX | fcntl.LOCK_NB)
