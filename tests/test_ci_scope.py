"""CI selection preserves shared-change and onboarding regression coverage."""
from pathlib import Path

from tools.ci_scope import ONBOARDING_CONTRACTS, select

ROOT = Path(__file__).resolve().parents[1]


def test_exact_sdk_successor_keeps_native_authority_and_receiving_generations(tmp_path):
    from tools.ci_scope import SDK_FILES, SDK_TESTS
    changed = sorted(SDK_FILES)
    assert select(changed, ROOT) == ('sdk', list(SDK_TESTS))
    assert {'tests/test_onboarding_sdk.py', 'tests/test_onboarding_code_successor.py',
        'tests/test_onboarding_source.py', 'tests/test_onboarding_target.py',
        'tests/test_onboarding_peer.py', 'tests/test_onboarding_custody.py',
        'tests/test_onboarding_credential.py', 'tests/test_admission.py',
        'tests/test_production_fences.py', 'tests/test_matrix_host.py',
        'tests/test_clusterd.py'} <= set(SDK_TESTS)
    assert 'tests/test_offline_qualifier.py' not in SDK_TESTS
    assert select(changed, tmp_path) == ('full', ['tests'])
    for boundary in ('constraints.txt', 'clusterctl/production_fences.py',
                     'clusterctl/onboarding_target.py', 'requirements.txt'):
        assert select(changed + [boundary], ROOT) == ('full', ['tests'])


def test_input_cache_scope_keeps_drift_owner_context_and_worker_recovery():
    from tools.ci_scope import INPUT_CACHE_FILES, INPUT_CACHE_TESTS
    changed = sorted(INPUT_CACHE_FILES)
    assert select(changed, ROOT) == ('portal', list(INPUT_CACHE_TESTS))
    profile, tests = select(changed + ['clusterctl/onboarding_custody.py'], ROOT)
    assert profile == 'onboarding' and 'tests/test_onboarding_custody.py' in tests
    assert select(changed + ['requirements.txt'], ROOT) == ('full', ['tests'])


def test_receiving_browser_keeps_context_retry_sdk_and_owner_acceptance(tmp_path):
    from tools.ci_scope import BROWSER_FILES
    changed = sorted(BROWSER_FILES)
    profile, tests = select(changed, ROOT)
    assert profile == 'portal'
    assert {'tests/test_onboarding_browser.py', 'tests/test_being_seed.py',
        'tests/test_onboarding_guest.py', 'tests/test_onboarding_host.py',
        'tests/test_onboarding_acceptance.py', 'tests/test_onboarding_sdk.py',
        'tests/test_onboarding.py', 'tests/test_onboarding_host_ownership.py',
        'tests/test_auth.py', 'tests/test_clusterd.py'} <= set(tests)
    assert select(changed, tmp_path) == ('full', ['tests'])
    for shared in ('requirements-weave.txt', 'clusterctl/production_fences.py',
                   'clusterctl/onboarding_custody.py'):
        assert select(changed + [shared], ROOT) == ('full', ['tests'])


def test_public_identity_export_and_reuse_keep_native_and_private_owner_contracts(tmp_path):
    from tools.ci_scope import IDENTITY_EXPORT_FILES
    changed = sorted(IDENTITY_EXPORT_FILES)
    profile, tests = select(changed, ROOT)
    assert profile == 'portal'
    assert {'tests/test_onboarding_local_body.py', 'tests/test_onboarding_existing.py',
        'tests/test_onboarding_peer.py', 'tests/test_onboarding_target.py',
        'tests/test_auth.py', 'tests/test_clusterd.py', 'tests/test_human_approvals.py'} <= set(tests)
    assert select(changed, tmp_path) == ('full', ['tests'])
    assert select(changed + ['requirements-weave.txt'], ROOT) == ('full', ['tests'])
    assert select(changed + ['clusterctl/onboarding_enrollment_root.py'], ROOT)[0] != 'portal'


def test_context_copy_keeps_receiving_crash_retry_sdk_and_job_owner_contracts(tmp_path):
    from tools.ci_scope import CONTEXT_COPY_FILES
    changed = sorted(CONTEXT_COPY_FILES)
    profile, tests = select(changed, ROOT)
    assert profile == 'portal'
    assert {'tests/test_onboarding_guest.py', 'tests/test_onboarding_input.py',
        'tests/test_onboarding_sdk.py', 'tests/test_onboarding_worker_install.py',
        'tests/test_onboarding_host_ownership.py', 'tests/test_onboarding_consent.py',
        'tests/test_auth.py', 'tests/test_clusterd.py'} <= set(tests)
    assert select(changed, tmp_path) == ('full', ['tests'])
    for shared in ('requirements-weave.txt', 'clusterctl/production_fences.py'):
        assert select(changed + [shared], ROOT) == ('full', ['tests'])
    assert select(changed + ['clusterctl/onboarding_custody.py'], ROOT)[0] == 'onboarding'


def test_participant_continuation_keeps_native_signing_receiving_and_owner_boundaries(tmp_path):
    from tools.ci_scope import CONTINUATION_FILES
    changed = sorted(CONTINUATION_FILES)
    profile, tests = select(changed, ROOT)
    assert profile == 'portal'
    assert {'tests/test_onboarding_continuation.py', 'tests/test_onboarding_existing.py',
        'tests/test_onboarding_intake.py', 'tests/test_being_seed.py',
        'tests/test_auth.py', 'tests/test_clusterd.py'} <= set(tests)
    assert select(changed, tmp_path) == ('full', ['tests'])
    for shared in ('requirements-weave.txt', 'clusterctl/onboarding_enrollment_root.py',
                   'clusterctl/onboarding_custody.py'):
        assert select(changed + [shared], ROOT) == ('full', ['tests'])


def test_existing_root_enrollment_keeps_native_authority_custody_and_admission(tmp_path):
    from tools.ci_scope import ENROLLMENT_FILES
    changed = sorted(ENROLLMENT_FILES)
    profile, tests = select(changed, ROOT)
    assert profile == 'onboarding'
    assert {'tests/test_onboarding_existing.py',
        'tests/test_onboarding_managed.py',
        'tests/test_admission.py', 'tests/test_production_fences.py',
        'tests/test_onboarding_peer_host.py', 'tests/test_onboarding_local_body.py',
        'tests/test_auth.py', 'tests/test_clusterd.py'} <= set(tests)
    assert any('test_receiving_credential_upgrade' in path for path in tests)
    assert any('test_existing_identity_and_wrong_or_missing_grant' in path for path in tests)
    assert any('test_response_cannot_change_history' in path for path in tests)
    assert select(changed, tmp_path) == ('full', ['tests'])
    for shared in ('requirements-weave.txt', 'clusterctl/matrix_host.py', 'clusterctl/onboarding_custody.py'):
        assert select(changed + [shared], ROOT) == ('full', ['tests'])


def test_hosted_witness_keeps_native_prerequisite_job_retry_and_owner_http_scope(tmp_path):
    changed = ['clusterctl/onboarding_acceptance.py', 'clusterctl/onboarding_host.py',
        'clusterctl/onboarding.py', 'clusterctl/cli.py', 'clusterd/routes.py',
        'clusterd/seed_handlers.py', 'clusterd/handlers.py', 'clusterd/seed_ui.py',
        'tests/test_onboarding_acceptance.py', 'tests/test_being_seed.py', 'tools/check_rc_types.py']
    profile, tests = select(changed, ROOT)
    assert profile == 'portal'
    assert {'tests/test_onboarding.py', 'tests/test_onboarding_acceptance.py',
        'tests/test_onboarding_worker_install.py', 'tests/test_onboarding_progress.py',
        'tests/test_onboarding_owner_client.py', 'tests/test_auth.py',
        'tests/test_clusterd.py', 'tests/test_human_approvals.py'} <= set(tests)
    assert select(changed, tmp_path) == ('full', ['tests'])
    assert select(changed + ['requirements-weave.txt'], ROOT) == ('full', ['tests'])


def test_new_seed_keeps_native_memory_context_custody_job_and_http_boundaries(tmp_path):
    from tools.ci_scope import NEW_SEED_FILES
    changed = sorted(NEW_SEED_FILES)
    profile, tests = select(changed, ROOT)
    assert profile == 'portal'
    assert {'tests/test_onboarding_new.py', 'tests/test_onboarding_guest.py',
        'tests/test_onboarding_sdk.py', 'tests/test_onboarding_code_successor.py',
        'tests/test_onboarding_custody.py', 'tests/test_onboarding_intake.py',
        'tests/test_onboarding_acceptance.py', 'tests/test_auth.py', 'tests/test_clusterd.py'} <= set(tests)
    assert select(changed, tmp_path) == ('full', ['tests'])
    assert select(changed + ['requirements-weave.txt'], ROOT) == ('full', ['tests'])
    assert select(changed + ['clusterctl/onboarding_custody.py'], ROOT)[0] != 'portal'


def test_protected_transfer_keeps_auth_actual_crypto_receiving_and_host_retry_scope(tmp_path):
    from tools.ci_scope import TRANSFER_FILES
    changed = sorted(TRANSFER_FILES)
    profile, tests = select(changed, ROOT)
    assert profile == 'portal'
    assert {'tests/test_onboarding_transfer.py', 'tests/test_being_seed.py',
        'tests/test_onboarding_input.py', 'tests/test_onboarding_intake.py',
        'tests/test_onboarding_release.py', 'tests/test_onboarding_guest.py',
        'tests/test_auth.py', 'tests/test_clusterd.py',
        'tests/test_onboarding_owner_client.py'} <= set(tests)
    assert select(changed, tmp_path) == ('full', ['tests'])
    assert select(changed + ['requirements-weave.txt'], ROOT) == ('full', ['tests'])


def test_owner_client_keeps_native_authority_and_context_without_unchanged_sdk_rebuild(tmp_path):
    changed = ['clusterctl/onboarding_owner_client.py', 'clusterctl/onboarding_host.py',
               'tests/test_onboarding_owner_client.py', 'tools/check_rc_types.py', 'tools/ci_scope.py',
               'support/matrix-agent-chat/install_agent_chat.py',
               'support/matrix-agent-chat/PROVENANCE.json']
    profile, tests = select(changed, ROOT)
    assert profile == 'peer'
    assert {'tests/test_onboarding_owner_client.py', 'tests/test_onboarding_target.py',
            'tests/test_onboarding_runtime.py', 'tests/test_onboarding_sdk.py',
            'tests/test_onboarding_welcome.py', 'tests/test_onboarding_host_ownership.py',
            'tests/test_onboarding_peer.py'} <= set(tests)
    assert select(changed, tmp_path) == ('full', ['tests'])
    assert select(changed + ['requirements-weave.txt'], ROOT) == ('full', ['tests'])
    assert select(changed + ['clusterctl/onboarding_target.py'], ROOT)[0] == 'full'


def test_portable_exporter_pin_keeps_http_context_and_original_archives(tmp_path):
    changed = ['support/being-seed-tools/tools/export_being.py',
               'support/being-seed-tools/PROVENANCE.json', 'clusterctl/being_seed.py',
               'clusterd/seed_ui.py', 'tests/test_being_seed.py']
    profile, tests = select(changed, ROOT)
    assert profile == 'portal'
    assert {'tests/test_being_seed.py', 'tests/test_onboarding_input.py',
            'tests/test_onboarding_release.py', 'tests/test_onboarding_guest.py',
            'tests/test_auth.py', 'tests/test_onboarding_consent.py'} <= set(tests)
    assert select(changed, tmp_path) == ('full', ['tests'])
    assert select(changed + ['support/being-seed-tools/tools/receive_being.py'], ROOT) == ('full', ['tests'])


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


def test_intake_only_changes_keep_stream_crypto_and_owner_boundaries(tmp_path):
    changed = ['clusterctl/being_seed.py', 'clusterd/seed_ui.py']
    profile, tests = select(changed, ROOT)
    assert profile == 'portal'
    assert {'tests/test_onboarding_transfer.py', 'tests/test_being_seed.py',
            'tests/test_onboarding_intake.py', 'tests/test_onboarding_input.py',
            'tests/test_onboarding_release.py', 'tests/test_auth.py'} <= set(tests)
    assert select(changed, tmp_path) == ('full', ['tests'])
    assert select(changed + ['requirements-weave.txt'], ROOT) == ('full', ['tests'])
    assert select(changed + ['clusterctl/matrix_host.py'], ROOT) == ('full', ['tests'])


def test_resumable_upload_keeps_http_auth_and_integrity_without_runtime_recovery(tmp_path):
    from tools.ci_scope import UPLOAD_FILES
    changed = sorted(UPLOAD_FILES)
    profile, tests = select(changed, ROOT)
    assert profile == 'portal'
    assert {'tests/test_being_seed.py', 'tests/test_clusterd.py', 'tests/test_auth.py',
            'tests/test_onboarding_transfer.py', 'tests/test_onboarding_intake.py'} <= set(tests)
    assert 'tests/test_onboarding_existing.py' not in tests
    assert select(changed, tmp_path) == ('full', ['tests'])
    assert select(changed + ['clusterctl/onboarding_target.py'], ROOT) == ('full', ['tests'])


def test_telegram_upgrade_covers_native_binding_idle_database_and_receiving_mounts(tmp_path):
    from tools.ci_scope import TELEGRAM_FILES
    changed = sorted(TELEGRAM_FILES)
    profile, tests = select(changed, ROOT)
    assert profile == 'portal'
    assert {'tests/test_onboarding_telegram.py', 'tests/test_onboarding_code_successor.py',
            'tests/test_onboarding_host.py', 'tests/test_onboarding_intake.py'} <= set(tests)
    assert select(changed, tmp_path) == ('full', ['tests'])
    assert select(changed + ['requirements-weave.txt'], ROOT) == ('full', ['tests'])
