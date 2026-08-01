"""Digest parity guard: steward_tools' local action_digest MUST stay
byte-identical to clusterd.confirm.action_digest (the daemon recomputes
digests when validating confirmations). If this test fails, the two
implementations drifted — fix the copy, never relax this test."""
import hashlib
import json

from clusterd.confirm import action_digest as daemon_digest
from steward_tools.mutations import action_digest as tool_digest

CASES = [
    ("stop", "iso-b", "steward@daimonmatrix", None),
    ("destroy", "eko", "steward@daimonmatrix", {"reason": "offboard"}),
    ("snapshot", "steward", "nico", {}),
    ("park", "a-very-long-daimon-name-123", "steward@daimonmatrix",
     {"nested": {"x": [1, 2]}, "unicode": "☯"}),
]


def test_digest_parity():
    for op, target, actor, args in CASES:
        assert tool_digest(op, target, actor, args) == \
            daemon_digest(op, target, actor, args)


def test_digest_matches_reference_vector():
    canonical = json.dumps(
        {"operation": "stop", "target": "iso-b",
         "actor": "steward@daimonmatrix", "args": {}},
        sort_keys=True, separators=(",", ":"))
    expected = hashlib.sha256(canonical.encode()).hexdigest()
    assert tool_digest("stop", "iso-b", "steward@daimonmatrix") == expected
