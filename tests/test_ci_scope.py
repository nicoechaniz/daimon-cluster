"""CI selection preserves shared-change and onboarding regression coverage."""
from pathlib import Path

from tools.ci_scope import ONBOARDING_CONTRACTS, select

ROOT = Path(__file__).resolve().parents[1]


def test_welcome_keeps_owner_retry_and_telegram_contracts_without_dependency_rehearsals(tmp_path):
    changed = ['clusterctl/onboarding_welcome.py', 'clusterctl/onboarding_host.py',
               'tests/test_onboarding_welcome.py', 'tools/check_rc_types.py']
    profile, tests = select(changed, ROOT)
    assert profile == 'welcome'
    assert {'tests/test_onboarding.py', 'tests/test_onboarding_telegram.py',
            'tests/test_onboarding_consent.py', 'tests/test_onboarding_host_ownership.py',
            'tests/test_onboarding_guest.py', 'tests/test_onboarding_code_successor.py'} <= set(tests)
    assert select(changed, tmp_path) == ('full', ['tests'])
    assert select(changed + ['clusterctl/onboarding_provider.py'], ROOT)[0] == 'onboarding'
    assert select(changed + ['requirements-weave.txt'], ROOT) == ('full', ['tests'])


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


def test_approval_reconciliation_covers_receiving_and_host_without_native_rehearsals():
    profile, tests = select(['clusterctl/onboarding_approvals.py',
        'tests/test_onboarding_approvals.py', 'tools/ci_scope.py', '.github/workflows/tests.yml'], ROOT)
    assert profile == 'approval'
    assert set(tests) == {'tests/test_onboarding_approvals.py', 'tests/test_onboarding_consent.py',
        'tests/test_onboarding_intake.py', 'tests/test_onboarding_host.py',
        'tests/test_ci_scope.py', 'tests/test_ci_workflow.py'}
    assert select(['clusterctl/onboarding_approvals.py', 'clusterctl/onboarding_custody.py'], ROOT)[0] == 'onboarding'


def test_local_portal_covers_shared_http_auth_without_repeating_body_lifecycle(tmp_path):
    changed = ['clusterctl/onboarding_local_body.py', 'clusterd/server.py',
               'clusterd/handlers.py', 'clusterd/routes.py', 'tests/test_onboarding_local_body.py']
    profile, tests = select(changed, ROOT)
    assert profile == 'portal'
    assert {'tests/test_auth.py', 'tests/test_clusterd.py', 'tests/test_human_approvals.py',
            'tests/test_being_seed.py', 'tests/test_onboarding_local_body.py'} <= set(tests)
    assert 'tests/test_onboarding_runtime.py' not in tests
    assert select(changed, tmp_path) == ('full', ['tests'])
    assert select(changed + ['clusterctl/admission.py'], ROOT) == ('full', ['tests'])
    assert select(['clusterd/server.py'], ROOT) == ('full', ['tests'])


def test_peer_host_keeps_signed_services_and_owner_separation_without_snapshot_rehearsals():
    changed = ['clusterctl/onboarding_peer_host.py', 'tests/test_onboarding_peer_host.py', 'tools/ci_scope.py']
    profile, tests = select(changed, ROOT)
    assert profile == 'peer'
    assert {'tests/test_onboarding_peer_host.py', 'tests/test_onboarding_source.py',
            'tests/test_onboarding_managed.py', 'tests/test_onboarding_host_ownership.py'} <= set(tests)
    assert select(changed + ['clusterctl/onboarding_target.py'], ROOT)[0] == 'onboarding'
    assert select(changed + ['clusterctl/admission.py'], ROOT)[0] == 'full'


def test_native_peer_tool_keeps_crypto_export_and_context_checks_without_sdk_recovery_repeat(tmp_path):
    changed = ['clusterctl/onboarding_peer.py', 'clusterctl/onboarding_peer_native.py',
        'tools/export_local_matrix_identity.py', 'support/matrix-onboarding/PROVENANCE.json',
        'tests/test_onboarding_source.py', 'docs/design/onboarding-jobs.md']
    profile, tests = select(changed, ROOT)
    assert profile == 'peer'
    assert {'tests/test_onboarding_source.py', 'tests/test_onboarding_managed.py',
            'tests/test_onboarding_peer_host.py', 'tests/test_onboarding_peer.py',
            'tests/test_onboarding_local_body.py', 'tests/test_onboarding_code_successor.py'} <= set(tests)
    assert select(changed, tmp_path) == ('full', ['tests'])
    assert select(changed + ['requirements-weave.txt'], ROOT) == ('full', ['tests'])
    assert select(changed + ['clusterctl/onboarding_target.py'], ROOT) == ('full', ['tests'])


def test_account_mount_permissions_keep_shared_login_and_owner_isolation(tmp_path):
    changed = ['clusterctl/onboarding_accounts.py', 'tests/test_onboarding_accounts.py', 'tools/ci_scope.py']
    profile, tests = select(changed, ROOT)
    assert profile == 'account'
    assert {'tests/test_onboarding_shared_login.py', 'tests/test_onboarding_provider.py',
            'tests/test_onboarding_consent.py', 'tests/test_onboarding_ingress.py',
            'tests/test_onboarding_host_ownership.py'} <= set(tests)
    assert select(changed, tmp_path) == ('full', ['tests'])
    assert select(changed + ['clusterctl/onboarding_provider.py'], ROOT)[0] == 'onboarding'
    assert select(changed + ['requirements-weave.txt'], ROOT) == ('full', ['tests'])
