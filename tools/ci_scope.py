"""Select maintained CI coverage for known change boundaries.

Unknown or shared changes retain the full suite. Onboarding changes keep their
complete journey tests and the existing authority, registry, API and access
contracts. Workflow-only changes exercise the workflow and selector themselves.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from pathlib import Path

CI_FILES = {'.github/workflows/tests.yml', 'README.md', 'tools/ci_scope.py',
            'tests/test_ci_scope.py', 'tests/test_ci_workflow.py'}
ONBOARDING_FILES = {'clusterctl/being_seed.py', 'clusterctl/onboarding.py',
    'clusterd/seed_handlers.py', 'clusterd/seed_ui.py', 'scripts/being-seed',
    'tools/build_onboarding_code.py', 'tools/build_onboarding_sdk.py',
    'tools/configure_onboarding_account.py', 'tools/install_onboarding_worker.py',
    'tools/check_rc_types.py', 'docs/design/onboarding-jobs.md', 'tests/test_being_seed.py',
    'clusterctl/onboarding_peer_native.py', 'support/matrix-onboarding/PROVENANCE.json'}
ONBOARDING_CONTRACTS = ('tests/test_being_seed.py', 'tests/test_admission.py',
    'tests/test_production_fences.py', 'tests/test_embodiments.py',
    'tests/test_matrix_host.py', 'tests/test_matrix_host_process.py',
    'tests/test_matrix_v8_snapshot.py', 'tests/test_matrix_status.py',
    'tests/test_matrix_parity.py', 'tests/test_effect_truth.py',
    'tests/test_honest_read_models.py', 'tests/test_auth.py', 'tests/test_clusterd.py',
    'tests/test_operational_assets.py', 'tests/test_ci_workflow.py', 'tests/test_ci_scope.py')
APPROVAL_FILES = {'clusterctl/onboarding_approvals.py', 'tests/test_onboarding_approvals.py'}
APPROVAL_TESTS = ('tests/test_onboarding_approvals.py', 'tests/test_onboarding_consent.py',
    'tests/test_onboarding_intake.py', 'tests/test_onboarding_host.py',
    'tests/test_ci_scope.py', 'tests/test_ci_workflow.py')


def select(changed: list[str], root: Path) -> tuple[str, list[str]]:
    if not changed:
        return 'full', ['tests']
    if set(changed) <= CI_FILES:
        return 'ci', ['tests/test_ci_scope.py', 'tests/test_ci_workflow.py']
    if (set(changed) <= APPROVAL_FILES | CI_FILES
            and all((root / path).is_file() for path in APPROVAL_TESTS)):
        return 'approval', list(APPROVAL_TESTS)
    def onboarding(path):
        return (path in ONBOARDING_FILES or path in CI_FILES
                or re.fullmatch(r'(?:clusterctl/onboarding_|tests/test_onboarding)[A-Za-z0-9_]*\.py', path))
    if all(onboarding(path) for path in changed):
        # Resolve enumeration relative to the supplied checkout, not the caller.
        tests = [p.relative_to(root).as_posix() for p in sorted(root.joinpath('tests').glob('test_onboarding*.py'))]
        if (tests and all(re.fullmatch(r'tests/test_onboarding[A-Za-z0-9_]*\.py', path) for path in tests)
                and all((root / path).is_file() for path in ONBOARDING_CONTRACTS)):
            return 'onboarding', sorted(set(tests) | set(ONBOARDING_CONTRACTS))
    return 'full', ['tests']


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', default='')
    parser.add_argument('--full', action='store_true')
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    changed = []
    if not args.full and re.fullmatch(r'[0-9a-f]{40}', args.base):
        result = subprocess.run(['git', 'diff', '--name-only', '-z', args.base, 'HEAD'],
                                cwd=root, capture_output=True, check=False)
        if result.returncode == 0:
            changed = result.stdout.decode().rstrip('\0').split('\0') if result.stdout else []
    profile, tests = select(changed, root)
    print(json.dumps({'profile': profile, 'tests': tests, 'changed': changed}))
    output = os.environ.get('GITHUB_OUTPUT')
    if output:
        with open(output, 'a', encoding='utf-8') as stream:
            stream.write('profile=' + profile + '\n')
            stream.write('pytest_args=' + ' '.join(tests) + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
