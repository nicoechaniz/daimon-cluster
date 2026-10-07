"""CI selection preserves shared-change and onboarding regression coverage."""
from pathlib import Path

from tools.ci_scope import ONBOARDING_CONTRACTS, select

ROOT = Path(__file__).resolve().parents[1]


def test_onboarding_keeps_all_journey_tests_and_existing_authority_contracts():
    profile, tests = select(['clusterctl/onboarding_accounts.py',
                            'tests/test_onboarding_shared_login.py'], ROOT)
    assert profile == 'onboarding'
    assert set(ONBOARDING_CONTRACTS) <= set(tests)
    assert {p.relative_to(ROOT).as_posix() for p in (ROOT / 'tests').glob('test_onboarding*.py')} <= set(tests)
    assert 'tests/test_offline_qualifier.py' not in tests
    assert 'tests/test_rc_manifest.py' not in tests


def test_shared_unknown_deleted_coverage_and_unavailable_diff_require_full(tmp_path):
    for changed in [[], ['clusterctl/production_fences.py'], ['requirements-weave.txt'],
                    ['new-component.py'], ['tests/test_offline_qualifier.py']]:
        assert select(changed, ROOT) == ('full', ['tests'])
    assert select(['clusterctl/onboarding_accounts.py'], tmp_path) == ('full', ['tests'])


def test_workflow_only_changes_test_workflow_without_repeating_runtime_rehearsals():
    profile, tests = select(['.github/workflows/tests.yml', 'README.md', 'tools/ci_scope.py'], ROOT)
    assert profile == 'ci'
    assert set(tests) == {'tests/test_ci_scope.py', 'tests/test_ci_workflow.py'}
