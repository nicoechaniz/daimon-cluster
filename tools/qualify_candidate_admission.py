"""Test explicit candidate owner APIs with the unchanged default identity producer.

This test-process-only selection changes no installed SDK, runtime or source pin.
The candidate must have real VCS provenance; wheel metadata is never fabricated.
"""
from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
ADMISSION_MATRIX_COMMIT = 'b53fa220d0917a5522773b7fb9711ab67e634b42'
TESTS = {'tests/test_onboarding_group_admission.py', 'tests/test_onboarding_group_authorities.py',
         'tests/test_onboarding_group_publication.py'}
OWNER_TEST = 'tests/test_guest_owner_bootstrap.py'
IDENTITY_PROGRAM = '''import json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from clusterctl.onboarding_custody import FirstCustody
value=json.load(sys.stdin)
FirstCustody._run(value['arguments'],None if value['password'] is None else Path(value['password']))
'''


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk-commit', required=True)
    parser.add_argument('--identity-python', required=True, type=Path)
    parser.add_argument('tests', nargs='*', default=['tests/test_onboarding_group_admission.py'])
    args = parser.parse_args(argv)
    if (not re.fullmatch('[0-9a-f]{40}', args.sdk_commit) or not args.identity_python.is_absolute()
            or any(item.split('::', 1)[0] not in TESTS | {OWNER_TEST} for item in args.tests)):
        parser.error('an explicit SDK commit, absolute identity interpreter and supported tests are required')
    installed = json.loads(importlib.metadata.distribution('daimon-matrix').read_text('direct_url.json') or 'null')
    if not isinstance(installed, dict) or installed.get('vcs_info', {}).get('commit_id') != args.sdk_commit:
        parser.error('the candidate SDK must have matching installed VCS provenance')
    sys.path.insert(0, str(ROOT))
    from clusterctl import matrix_host
    from clusterctl.onboarding_custody import FirstCustody
    original_pin, original_run = matrix_host.MATRIX_CONTRACT_COMMIT, FirstCustody._run
    try:
        matrix_host.MATRIX_CONTRACT_COMMIT = args.sdk_commit
        matrix_host._matrix_api()
        def identity(arguments, password):
            result = subprocess.run([str(args.identity_python), '-B', '-I', '-c', IDENTITY_PROGRAM, str(ROOT)],
                input=json.dumps(dict(arguments=arguments, password=None if password is None else str(password))),
                text=True, capture_output=True, timeout=150, env={'PATH': os.defpath, 'LANG': 'C.UTF-8'})
            if result.returncode:
                raise RuntimeError('candidate_test_default_identity_producer_failed')
        FirstCustody._run = staticmethod(identity)
        import pytest
        return pytest.main(['-q', '-x', '--tb=short', *args.tests,
            '-W', 'error::ResourceWarning', '-W', 'error::pytest.PytestUnraisableExceptionWarning'])
    finally:
        matrix_host.MATRIX_CONTRACT_COMMIT = original_pin
        FirstCustody._run = staticmethod(original_run)


if __name__ == '__main__':
    raise SystemExit(main())
