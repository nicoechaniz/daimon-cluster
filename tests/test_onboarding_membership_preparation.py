"""Real signed fixtures exercise a strictly read-only owner metadata route."""
import json
import sqlite3
import uuid

import pytest

from clusterctl.onboarding import OnboardingError
from clusterctl.onboarding_membership_preparation import preview
from tests import test_onboarding_group_authorities as native_fixtures

group_source = native_fixtures.group_source


def selected(group_source):
    source, target, _peer, _peer_bundle, _old = group_source
    bundle = target.document_bundle()
    selection = json.loads((source.outputs/'tribe/selection.json').read_bytes())['document']
    return source, bundle, selection['tribe_ref']


def test_preparation_reads_canonical_governance_without_loader_or_writer(group_source, monkeypatch):
    from daimon_matrix.relationship_store import RelationshipStore
    source, bundle, tribe = selected(group_source)
    database = source.root/bundle['relationships']['store_filename']
    original = {path: path.read_bytes() for path in (database, source.root/'runtime.json')}
    monkeypatch.setattr(RelationshipStore, 'initialize', lambda *a: pytest.fail('store initialization'))
    monkeypatch.setattr(source, '_reader', lambda: pytest.fail('custody reader'))
    monkeypatch.setattr(source, 'writer', lambda: pytest.fail('native writer'))
    result = source.group_publication(dict(operation_id=str(uuid.uuid4()), step='prepare',
        action='preparation-preview', params=dict(tribe_ref=tribe)), authority_closure={})
    assert result['being_ref'] == bundle['manifest']['being_ref']
    assert result['origin'] == bundle['local_origin']
    assert len(result['governance']) == 1
    assert result['governance'][0]['kind'] == 'matrix/tribe-declaration'
    assert result['governance_verified'] is False
    assert result['receiving_readiness'] == 'unobserved'
    assert set(result['public']) == {'authority', 'history'}
    assert {path: path.read_bytes() for path in original} == original
    # A selected different Tribe cannot expose the fixture's governance.
    assert preview(source.root, operation_id=str(uuid.uuid4()), tribe_ref='tribe:other')['governance'] == []


def test_missing_canonical_store_is_not_created_or_replaced_by_published_history(group_source):
    source, bundle, tribe = selected(group_source)
    database = source.root/bundle['relationships']['store_filename']
    preserved = database.with_suffix('.preserved')
    database.rename(preserved)
    with pytest.raises(OnboardingError, match='preparation_unavailable'):
        preview(source.root, operation_id=str(uuid.uuid4()), tribe_ref=tribe)
    assert preserved.is_file() and not database.exists()


def test_private_governance_is_refused_instead_of_silently_dropped(group_source):
    source, bundle, tribe = selected(group_source)
    database = source.root/bundle['relationships']['store_filename']
    # Deliberate fixture corruption: this is not a native authoring operation.
    with sqlite3.connect(database) as connection:
        row = connection.execute('SELECT rowid,event_json FROM events').fetchone()
        event = json.loads(row[1])
        event['sensitivity'] = 'private'
        connection.execute('UPDATE events SET event_json=? WHERE rowid=?',
                           (json.dumps(event).encode(), row[0]))
    with pytest.raises(OnboardingError, match='preparation_unavailable'):
        preview(source.root, operation_id=str(uuid.uuid4()), tribe_ref=tribe)
