"""Current receiving proof refresh never requires a second lifecycle effect."""
import copy
import time
from types import SimpleNamespace

import pytest

from clusterctl.onboarding import OnboardingError
from clusterctl.onboarding_receiving_update import observe_current_reader


def fixture():
    server = dict(embodiment_id='body:current', incarnation_id='incarnation:current')
    identity = dict(being_ref='being:current', credential_ref='credential:current', manifest_hash='a'*64)
    contract = dict(capabilities=['signed-roster-cas/v1', 'credential-bound-reader-validity/v1'],
        wire_read=['dm.tribe.conversation/v1', 'dm.tribe.direct-conversation/v1', 'dm.tribe.recovery-conversation/v1'],
        store_versions=dict(reader_control=[2], communication=[4], visibility_catalog=[2]))
    loaded = dict(process_id=123, local_origin=server, runtime_bundle_sha256='b'*64,
        authority_epoch=dict(accepted_manifest_hashes=['a'*64]),
        qualified_startup=dict(code_digest='c'*64, matrix_wheel_sha256='d'*64, reader=dict(contract=contract)))
    application = dict(application_sha256='e'*64, publication_sha256='f'*64, loaded_view_sha256='1'*64,
        shared_relationships=True, communication_store_role='ledger',
        shared_stores=dict(ledger=dict(schema_versions=dict(communication=4))), authorities={},
        visibility=dict(installation_sha256='2'*64, catalog_mode='validate',
            catalog_validation='validated', release_enabled=True, catalog_schema_version=2))
    roster = dict(schema='dm.runtime.tribe-roster/v1', roster_sha256='3'*64,
        required_authority_epochs=['a'*64], audience=[dict(being_ref=identity['being_ref'],
            embodiment_id=server['embodiment_id'], credential_id=identity['credential_ref'],
            authority_manifest_hash=identity['manifest_hash'])])
    data = dict(server=server, process=dict(pid=123), identity=identity, gate=dict(controlled=True),
        runtime_status=dict(loaded_runtime=loaded, loaded_application=application,
            receiving=dict(features=contract['capabilities'], contracts=['dm.runtime.reader-selection/v2'],
                rosters=dict(tribe=roster))))
    calls = []
    def observe(**kwargs):
        calls.append(kwargs)
        return {**copy.deepcopy(data), 'verified_identity':dict(identity=copy.deepcopy(identity),
            runtime_bundle_sha256='b'*64, expires_at_ms=kwargs['expires_at_ms'],
            credential_validity=dict(mode='until-revoked', not_before_ms=0))}
    selection = dict(receiving_code='c'*64, matrix_sdk='d'*64, runtime_bundle_sha256='b'*64,
        application_sha256='e'*64, publication_sha256='f'*64, visibility_installation_sha256='2'*64)
    return SimpleNamespace(qualified_identity=observe), data, selection, calls


def test_current_adoption_preserves_credential_and_finite_proof_without_lifecycle():
    owner, data, selection, calls = fixture()
    horizon = time.time_ns()//1_000_000+30_000
    result = observe_current_reader(owner, expected_selection=selection, expires_at_ms=horizon)
    assert calls == [dict(expires_at_ms=horizon, require_admitted=True)]
    assert result['reader']['validity'] == dict(mode='until-revoked', not_before_ms=0)
    assert result['identity_expires_at_ms'] == horizon
    assert result['reader']['loaded_view_sha256'] == '1'*64
    assert result['expected']['selection'] == selection
    assert result['roster'] == data['runtime_status']['receiving']['rosters']['tribe']
    # No journal, seed, manager or task dispatcher exists on this owner.
    assert list(vars(owner)) == ['qualified_identity']


@pytest.mark.parametrize('change,error', [
    ('selection','selection_changed'), ('process','selection_changed'),
    ('origin','selection_changed'), ('roster','identity_changed'),
    ('authority','authority_unready'), ('wire','roster_unready'),
    ('control','roster_unready'), ('visibility','store_unready'),
    ('store','store_unready'),
])
def test_current_adoption_refuses_stale_or_incompatible_loaded_proof(change, error):
    owner, data, selection, _ = fixture()
    status = data['runtime_status']
    if change == 'selection':
        selection['matrix_sdk']='9'*64
    elif change == 'process':
        data['process']['pid']=456
    elif change == 'origin':
        status['loaded_runtime']['local_origin']={}
    elif change == 'roster':
        status['receiving']['rosters']['tribe']['audience']=[]
    elif change == 'authority':
        status['receiving']['rosters']['tribe']['required_authority_epochs']=['9'*64]
    elif change == 'wire':
        status['loaded_runtime']['qualified_startup']['reader']['contract']['wire_read']=[]
    elif change == 'control':
        data['gate']['controlled']=False
    elif change == 'visibility':
        status['loaded_application']['visibility']['catalog_validation']='unvalidated'
    elif change == 'store':
        status['loaded_application']['shared_stores']['ledger']['schema_versions']['communication']=99
    with pytest.raises(OnboardingError,match=error):
        observe_current_reader(owner,expected_selection=selection,expires_at_ms=time.time_ns()//1_000_000+30_000)


@pytest.mark.parametrize('offset', [-1, 61_000])
def test_invalid_observation_horizon_never_queries_owner(offset):
    owner, _, selection, calls = fixture()
    with pytest.raises(OnboardingError,match='horizon_expired'):
        observe_current_reader(owner,expected_selection=selection,expires_at_ms=time.time_ns()//1_000_000+offset)
    assert calls == []
