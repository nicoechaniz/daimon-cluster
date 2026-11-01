"""Protected speech scope and native evidence classification, without effects.

These are contract fixtures, not native delivery or full portal qualification.
Native signing, transport and visibility are qualified by the SDK integration.
"""
import copy
import uuid

import pytest

from clusterctl.onboarding import OnboardingError
from clusterctl.onboarding_group_coordinator import communication_recipe, communication_result


def reference(label):
    return 'dm:being:v1:' + label * 43


@pytest.fixture
def recipe():
    receivers = {name:dict(being_ref=reference(letter), embodiment_id='embodiment:'+name)
        for name,letter in (('founder','A'), ('entrant','B'))}
    row = dict(intended_transition=dict(portal_admission=dict(social=dict(founder_owner='founder', entrant_owner='entrant'))))
    admission = dict(receivers=receivers, activation=dict(expires_at_ms=2000))
    def sender(name):
        return dict(owner=name, **receivers[name])
    value = dict(schema='cluster-admission-communication/v1', expires_at_ms=1500,
        group=dict(sender=sender('founder'), text='Group check'),
        direct=dict(sender=sender('entrant'), text='Directed check', destination=dict(kind='being', being_ref=reference('A'))),
        reply=dict(sender=sender('entrant'), text='Connected reply', parent='group'))
    return value, row, admission


@pytest.mark.parametrize('fault', [None, 'actor', 'destination', 'body', 'expiry', 'parent', 'extra'])
def test_technical_scope_is_bound_to_the_approved_bodies_and_fixed_horizon(recipe, fault):
    value, row, admission = recipe
    if fault == 'actor':
        value['group']['sender']['owner'] = 'entrant'
    elif fault == 'destination':
        value['direct']['destination']['being_ref'] = reference('B')
    elif fault == 'body':
        value['direct']['destination'].update(kind='body', embodiment_id='embodiment:unknown')
    elif fault == 'expiry':
        value['expires_at_ms'] = 2001
    elif fault == 'parent':
        value['reply']['parent'] = 'direct'
    elif fault == 'extra':
        value['allow_models'] = True
    if fault:
        with pytest.raises(OnboardingError, match='communication_scope_required'):
            communication_recipe(value, row, admission)
    else:
        result = communication_recipe(value, row, admission)
        assert result == value
        result['group']['text'] = 'changed copy'
        assert value['group']['text'] == 'Group check'
        value['direct']['destination'].update(kind='body', embodiment_id='embodiment:founder')
        assert communication_recipe(value, row, admission) == value


def delivery(step='group', *, parent=None):
    author = dict(being_ref=reference('A'), embodiment_id='embodiment:founder')
    recipient = dict(being_ref=reference('B'), embodiment_id='embodiment:entrant')
    parameters = dict(channel_id='tribe', send_id=str(uuid.uuid4()), thread_id=str(uuid.uuid4()))
    context = None
    if step == 'direct':
        parameters['destination'] = dict(kind='body', **recipient)
    elif step == 'reply':
        parameters.pop('thread_id')
        parameters.update(message_id=parent['message_id'], received_channel_id='tribe')
        context = dict(message_id=parent['message_id'], message_hash=parent['message_hash'],
            sender_being_ref=parent['author']['being_ref'], sender_embodiment_id=parent['author']['embodiment_id'])
    result = dict(schema='dm.tribe.direct-delivery/v1' if step == 'direct' else 'dm.tribe.delivery/v1',
        send_id=parameters['send_id'], message_id=str(uuid.uuid4()), message_hash='a'*64,
        thread_id=parent['thread_id'] if parent else parameters['thread_id'], tribe_ref='tribe:fixture', author=author,
        response_context=context, visibility=dict(echo_state='confirmed', part_count=3, confirmed_parts=3),
        audience=[dict(membership_ref='membership:author', **author), dict(membership_ref='membership:recipient', **recipient)],
        semantic=dict(legs=[]), transport=dict(expired=True))
    if step == 'direct':
        result['audience'] = result['audience'][1:]
        result['destination'] = dict(**parameters['destination'], authority_manifest_hash='b'*64)
    for item in result['audience']:
        result['semantic']['legs'].append(dict(recipient_id=item['membership_ref'], receipt_origin_embodiment_id=item['embodiment_id'],
            message_id=result['message_id'], thread_id=result['thread_id'], state='delivered',
            terminal_receipt_event_id=str(uuid.uuid4()), terminal_receipt_hash='c'*64))
    response = dict(schema='dm.local.response/v1', ok=True, error=None, result=result)
    intent = dict(step=step, parameters=parameters, sender=author)
    return response, intent


def qualify(response, intent, parent=None):
    return communication_result(response, intent, tribe_ref='tribe:fixture', parent=parent)


def test_late_signed_intake_is_distinct_from_the_authors_retained_copy():
    response, intent = delivery()
    result = qualify(response, intent)
    assert [(item['being_ref'], item['embodiment_id']) for item in result['inbound']] == [(reference('B'), 'embodiment:entrant')]
    response['result']['semantic']['legs'].pop()
    assert qualify(response, intent)['inbound'] == [], 'author retention never proves any receiving body'


@pytest.mark.parametrize('fault', ['unconfirmed', 'partial', 'empty', 'receipt', 'audience', 'author', 'message'])
def test_incomplete_or_unrelated_proof_is_not_admission_acceptance(fault):
    response, intent = delivery()
    result = response['result']
    if fault == 'unconfirmed':
        result['visibility']['echo_state'] = 'pending'
    elif fault == 'partial':
        result['visibility']['confirmed_parts'] = 2
    elif fault == 'empty':
        result['visibility'].update(part_count=0, confirmed_parts=0)
    elif fault == 'receipt':
        result['semantic']['legs'][-1]['terminal_receipt_hash'] = None
    elif fault == 'audience':
        result['audience'].append(copy.deepcopy(result['audience'][0]))
    elif fault == 'author':
        result['author'] = dict(being_ref=reference('C'), embodiment_id='embodiment:unknown')
    elif fault == 'message':
        result['semantic']['legs'][-1]['message_id'] = str(uuid.uuid4())
    with pytest.raises(OnboardingError, match='communication_unobserved'):
        qualify(response, intent)


def test_reply_is_correlated_to_the_exact_signed_parent_and_native_request():
    response, intent = delivery()
    parent = qualify(response, intent)
    response, intent = delivery('reply', parent=parent)
    result = qualify(response, intent, parent)
    assert result['response_context']['message_hash'] == parent['message_hash']
    response['result']['response_context']['message_hash'] = 'f'*64
    with pytest.raises(OnboardingError, match='communication_unobserved'):
        qualify(response, intent, parent)
    response, intent = delivery('reply', parent=parent)
    intent['parameters']['message_id'] = str(uuid.uuid4())
    with pytest.raises(OnboardingError, match='communication_unobserved'):
        qualify(response, intent, parent)
    with pytest.raises(OnboardingError, match='communication_unobserved'):
        qualify(response, intent)


def test_direct_preserves_the_exact_target_with_no_group_fanout():
    response, intent = delivery('direct')
    assert qualify(response, intent)['inbound'][0]['embodiment_id'] == 'embodiment:entrant'
    response['result']['audience'][0]['embodiment_id'] = 'embodiment:other'
    with pytest.raises(OnboardingError, match='communication_unobserved'):
        qualify(response, intent)


def followup_fixture(recipe):
    from clusterctl.onboarding import digest
    from clusterctl.onboarding_group_coordinator import GroupCoordinator
    scope, row, admission = copy.deepcopy(recipe)
    row.update(operation='receiving-update', state='runtime-dispatching',
        operation_id='operation:'+str(uuid.uuid4()), target='receiving:tribe:fixture',
        expected_precondition={'technical':'fixture'})
    row['intended_transition']['admission_communication'] = scope
    admission['tribe_ref'] = 'tribe:fixture'
    row['intended_transition']['cohort_admission'] = copy.deepcopy(admission)
    row['intent'] = dict(runtime_call=dict(precondition_digest=digest(row['expected_precondition']),
        transition_digest=digest(row['intended_transition'])))
    row['intent_hash'] = digest(row['intent'])
    selection = dict(schema='cluster-receiving-cohort-selection/v1', operation_id=row['operation_id'])
    intent = GroupCoordinator._communication_intent(row, scope, 'group', None)
    row['runtime_observation'] = dict(portal_admission=dict(activation_ready=selection,
        steady_ready=dict(schema='cluster-managed-initial-steady/v1', cohort_selection_sha256=digest(selection)),
        **{'communication-intent-group': intent}))
    response = response_for(intent, admission)
    response['result']['visibility'].update(echo_state='ambiguous', confirmed_parts=0)
    for leg in response['result']['semantic']['legs']:
        leg.update(state='accepted', terminal_receipt_event_id=None, terminal_receipt_hash=None)
    response['result']['carrier'] = {'expired': True}
    request = dict(schema='cluster-admission-communication-followup-request/v1',
        qualification_id=str(uuid.uuid4()), parent_operation_id=row['operation_id'],
        parent_intent_sha256=row['intent_hash'], previous_step='group', expires_at_ms=62000)
    return request, row, admission, response


def response_for(intent, admission, parent=None):
    """Synthetic native projection only; no signed/authenticated delivery claim."""
    from clusterctl.onboarding_group_coordinator import communication_recipients
    response, _ = delivery(intent['step'], parent=parent)
    result = response['result']
    result.update(send_id=intent['parameters']['send_id'],
        author={key:intent['sender'][key] for key in ('being_ref','embodiment_id')},
        thread_id=parent['thread_id'] if parent else intent['parameters']['thread_id'])
    audience = [dict(membership_ref='membership:'+name, **{key:item[key]
        for key in ('being_ref','embodiment_id')}) for name,item in admission['receivers'].items()
        if intent['step'] != 'direct' or (item['being_ref'],item['embodiment_id']) in
            communication_recipients(intent, admission)]
    result['audience'] = audience
    if intent['step'] == 'direct':
        result['destination'] = copy.deepcopy(intent['parameters']['destination'])
    result['semantic']['legs'] = [dict(recipient_id=item['membership_ref'],
        receipt_origin_embodiment_id=item['embodiment_id'], message_id=result['message_id'],
        thread_id=result['thread_id'], state='delivered', terminal_receipt_event_id=str(uuid.uuid4()),
        terminal_receipt_hash='c'*64) for item in audience]
    return response


def test_explicit_followup_preserves_failed_original_and_uses_distinct_technical_intents(recipe):
    from clusterctl.onboarding_group_coordinator import communication_followup, GroupCoordinator
    request, row, admission, response = followup_fixture(recipe)
    originals = copy.deepcopy((request, row, admission, response))
    record = communication_followup(request, row, admission, response, now_ms=2001)
    assert (request, row, admission, response) == originals
    original = row['runtime_observation']['portal_admission']['communication-intent-group']
    expected_id = str(uuid.uuid5(uuid.NAMESPACE_URL, 'portal-communication:'+row['operation_id']+':group'))
    assert original['parameters']['send_id'] == expected_id
    next_intent = GroupCoordinator._communication_intent(row, record['scope'], 'group', None,
        qualification_id=request['qualification_id'])
    assert next_intent['parameters']['send_id'] != expected_id
    assert next_intent['parameters']['thread_id'] != original['parameters']['thread_id']
    assert response['result']['message_id'] in next_intent['parameters']['text']
    assert 'remains unconfirmed' in next_intent['parameters']['text']
    assert record['previous_response']['result']['visibility']['echo_state'] == 'ambiguous'
    assert communication_followup(request, row, admission, response, now_ms=2002) == record
    assert communication_followup(request, row, admission, response,
        now_ms=request['expires_at_ms']+1, historical=True) == record
    with pytest.raises(OnboardingError, match='followup_required'):
        communication_followup(request, row, admission, response, now_ms=request['expires_at_ms'])


@pytest.mark.parametrize('change', ['parent','intent','id','expiry','step','live-carrier','send-id',
    'author','tribe','not-steady','accepted-original','extra','schema','thread','parts','vectors'])
def test_followup_refuses_unrelated_unexpired_or_already_accepted_original(recipe, change):
    from clusterctl.onboarding_group_coordinator import communication_followup
    request, row, admission, response = followup_fixture(recipe)
    if change == 'parent':
        request['parent_operation_id'] = 'operation:'+str(uuid.uuid4())
    elif change == 'intent':
        request['parent_intent_sha256'] = '0'*64
    elif change == 'id':
        request['qualification_id'] = 'not-a-uuid'
    elif change == 'expiry':
        request['expires_at_ms'] = 2001+3_600_001
    elif change == 'step':
        request['previous_step'] = 'direct'
    elif change == 'live-carrier':
        response['result']['carrier']['expired'] = False
    elif change == 'send-id':
        response['result']['send_id'] = str(uuid.uuid4())
    elif change == 'author':
        response['result']['author']['being_ref'] = reference('C')
    elif change == 'tribe':
        response['result']['tribe_ref'] = 'tribe:other'
    elif change == 'not-steady':
        row['runtime_observation']['portal_admission']['steady_ready']['cohort_selection_sha256'] = '0'*64
    elif change == 'extra':
        request['allow_models'] = True
    elif change == 'schema':
        response['result']['schema'] = 'unrelated-result'
    elif change == 'thread':
        response['result']['thread_id'] = str(uuid.uuid4())
    elif change == 'parts':
        response['result']['visibility']['part_count'] = 0
    elif change == 'vectors':
        row['expected_precondition']['unrelated'] = True
    else:
        intent = row['runtime_observation']['portal_admission']['communication-intent-group']
        response = response_for(intent, admission)
        response['result']['carrier'] = {'expired': True}
    with pytest.raises(OnboardingError, match='followup_required'):
        communication_followup(request, row, admission, response, now_ms=2001)


def test_followup_completion_needs_each_current_journey_and_keeps_prior_uncertainty(recipe):
    from clusterctl.onboarding_group_coordinator import (communication_followup, communication_followup_result,
        GroupCoordinator)
    request, row, admission, response = followup_fixture(recipe)
    record = communication_followup(request, row, admission, response, now_ms=2001)
    proofs, phases = {}, {}
    for step in ('group','direct','reply'):
        intent = GroupCoordinator._communication_intent(row, record['scope'], step, proofs.get('group'),
            qualification_id=request['qualification_id'])
        response = response_for(intent, admission, proofs.get('group') if step == 'reply' else None)
        proof = communication_result(response, intent, tribe_ref=admission['tribe_ref'],
            parent=proofs.get('group') if step == 'reply' else None)
        proofs[step] = proof
        phases['communication-intent-'+step] = intent
        phases['communication-'+step] = dict(intent=intent,response=response,proof=proof)
    result = communication_followup_result(record,row,admission,phases)
    assert result['communication_acceptance'] == 'signed-intake-and-confirmed-echo'
    assert result['previous_outcome'] == 'retained-unconfirmed'
    assert result['previous_send_id'] == record['previous_response']['result']['send_id']
    for step in ('group','direct','reply'):
        broken = copy.deepcopy(phases)
        broken['communication-'+step]['response']['result']['visibility']['echo_state'] = 'ambiguous'
        with pytest.raises(OnboardingError, match='followup_unobserved'):
            communication_followup_result(record,row,admission,broken)
    changed = copy.deepcopy(record)
    changed['previous_response']['result']['visibility']['echo_state'] = 'confirmed'
    with pytest.raises(OnboardingError, match='followup_unobserved'):
        communication_followup_result(changed,row,admission,phases)



def test_followup_does_not_replay_original_text_even_at_the_original_size_limit(recipe):
    from clusterctl.onboarding_group_coordinator import communication_followup, GroupCoordinator
    request, row, admission, response = followup_fixture(recipe)
    original = row['intended_transition']['admission_communication']
    original['group']['text'] = 'x'*2048
    from clusterctl.onboarding import digest
    row['intent']['runtime_call']['transition_digest'] = digest(row['intended_transition'])
    row['intent_hash'] = digest(row['intent'])
    request['parent_intent_sha256'] = row['intent_hash']
    intent = GroupCoordinator._communication_intent(row, original, 'group', None)
    row['runtime_observation']['portal_admission']['communication-intent-group'] = intent
    # Text is deliberately absent from the native delivery projection; exact
    # retained send/thread correlation is still the original one.
    record = communication_followup(request, row, admission, response, now_ms=2001)
    assert record['scope']['group']['text'] != original['group']['text']
    assert len(record['scope']['group']['text']) <= 2048
    assert 'Check current Tribe group delivery.' in record['scope']['group']['text']
