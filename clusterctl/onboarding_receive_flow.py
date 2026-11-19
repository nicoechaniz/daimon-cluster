"""Original-job first receive publication; existing applications remain read-only.

The coordinator owns invocation, authorization and journal locking. This module
joins existing private resources, native publication and scoped restoration.
It never enrolls a member or claims all-current reader selection from a file.
"""
from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import json
from pathlib import Path
import time
from urllib.parse import urlsplit

from . import being_seed
from .onboarding import OnboardingError, digest
from .onboarding_membership_scope import Endpoint, preserved, configuration as helper_configuration
from .onboarding_receive_keys import parameters, relay

SCHEMA = 'cluster-companion-receive-preparation/v1'


def controller_configuration(value: dict) -> dict:
    """An explicit existing native update, separate from immutable publication."""
    import re
    try:
        if (set(value) != {'code', 'code_digest', 'manifest_path', 'manifest_digest', 'expires_at_ms', 'host_config'}
                or any(not isinstance(value[k], str) or not Path(value[k]).is_absolute()
                    or '..' in Path(value[k]).parts for k in ('code', 'manifest_path', 'host_config'))
                or any(re.fullmatch('[0-9a-f]{64}', value[k]) is None
                    for k in ('code_digest', 'manifest_digest'))
                or type(value['expires_at_ms']) is not int or not 0 < value['expires_at_ms'] < 2**53):
            raise ValueError
    except (KeyError, TypeError, ValueError):
        raise OnboardingError('companion_receive_controller_preparation_required') from None
    return copy.deepcopy(value)


def ensure_controller(*, plan, preparation, backend, config_path, journal, row, validate, deadline_ns):
    """Join the supported native controller bootstrap to this original job.

    Publication/key/snapshot receipts stay immutable. The native child verifies
    unchanged identity and signed application, then retains its forward load.
    """
    from .onboarding_code_successor import plan_update, sdk_parameters
    from .onboarding_receiving_update import prepare_guest_bootstrap, GuestBootstrapController
    from .onboarding_host import HostConfig
    preparation = controller_configuration(preparation)
    if backend.config != HostConfig.load(config_path):
        raise OnboardingError('companion_receive_original_changed')
    phase = (row['runtime_observation'] or {}).get('receive_application', {})
    snapshot = phase.get('snapshot', {}).get('result')
    if not isinstance(snapshot, dict) or not phase.get('restoration'):
        raise OnboardingError('companion_receive_restoration_required')
    name, parent = plan['name'], row['operation_id']
    binding = dict(schema='cluster-companion-receive-controller/v1', parent=parent,
        parent_intent_sha256=digest(row['intent']), receive_binding=phase['binding'],
        snapshot_sha256=digest(snapshot), preparation_sha256=digest(preparation))

    def check():
        validate()
        fresh = journal.get(parent)
        current = (fresh['runtime_observation'] or {}).get('receive_application', {})
        if (fresh['intent'] != row['intent'] or current.get('binding') != phase['binding']
                or current.get('snapshot', {}).get('result') != snapshot
                or current.get('restoration') != phase['restoration']):
            raise OnboardingError('companion_receive_original_changed')
        if time.monotonic_ns() >= deadline_ns:
            raise OnboardingError('receiving_host_deadline_expired')

    check()
    child = journal.latest_for_target('companion-receive-controller:' + parent)
    if child is None:
        candidate = Path(preparation['code']), preparation['code_digest']
        if sdk_parameters(candidate[0], uid=0).get('matrix_wheel_sha256') != phase['baseline']['matrix_sdk']:
            raise OnboardingError('companion_receive_controller_sdk_changed')
        if not backend.runtime_available(plan, candidate, prepare=True, deadline_ns=deadline_ns):
            raise OnboardingError('qualified_onboarding_candidate_mount_required')
        frozen, request = prepare_guest_bootstrap(backend, plan,
            candidate=candidate,
            manifest_path=Path(preparation['manifest_path']), manifest_digest=preparation['manifest_digest'],
            expires_at_ms=preparation['expires_at_ms'], installed_only=True,
            timeout_seconds=60, deadline_ns=deadline_ns)
        group = frozen['owner']['group']
        if (group['application_sha256'] != snapshot['group']['application_sha256']
                or group['publication_sha256'] != snapshot['group']['publication_sha256']
                or group['installation_sha256'] is not None):
            raise OnboardingError('companion_receive_source_changed')
        host = being_seed._read(config_path)
        check()
        child = plan_update(journal, manifest_digest=preparation['manifest_digest'],
            target='companion-receive-controller:' + parent,
            expected_precondition=dict(host_config=str(config_path), host_configuration=host,
                host_config_sha256=digest(host), guest_bootstraps={name:frozen}, companion_receive=binding),
            intended_transition=dict(guest_bootstraps={name:request}),
            audit_identity={'actor':'authorized-original-companion-receiving'})
    if child['expected_precondition'].get('companion_receive') != binding:
        raise OnboardingError('companion_receive_original_changed')
    fresh = journal.get(parent)
    retained = (fresh['runtime_observation'] or {}).get('receive_controller')
    link = dict(binding=binding, child_operation_id=child['operation_id'])
    if retained is None:
        observed = copy.deepcopy(fresh['runtime_observation'] or {})
        observed['receive_controller'] = link
        journal.advance(parent, fresh['state'], runtime_observation=observed,
            expected_runtime_observation=fresh['runtime_observation'])
    elif any(retained.get(k) != v for k, v in link.items()):
        raise OnboardingError('companion_receive_original_changed')
    if retained is not None and retained.get('software_recovery') is not None:
        recovery = retained['software_recovery']
        published = (child['runtime_observation'] or {}).get('guest_bootstraps', {}).get(name, {}).get('owner_published')
        selection = retained.get('selection', {})
        if (not isinstance(published, dict)
                or recovery.get('schema') != 'cluster-companion-controller-software-recovery/v1'
                or recovery.get('publication_sha256') != digest(published)
                or recovery.get('proof_sha256') != retained.get('loaded_receipt_sha256')
                or selection.get('runtime_bundle_sha256') != published.get('runtime_sha256')
                or selection.get('matrix_sdk') != phase['baseline']['matrix_sdk']
                or selection.get('application_sha256') != snapshot['group']['application_sha256']
                or selection.get('publication_sha256') != snapshot['group']['publication_sha256']
                or selection.get('visibility_installation_sha256') is not None):
            raise OnboardingError('companion_receive_original_changed')
        return copy.deepcopy(retained)
    if child['state'] == 'completed':
        result = child['result']
    else:
        result = GuestBootstrapController(journal, child['operation_id'], backend, name).execute(
            timeout_seconds=60, deadline_ns=deadline_ns)
        check()
    check()
    loaded, app = result['loaded_runtime'], result['loaded_application']
    if (result['schema'] != 'cluster-guest-bootstrap-loaded/v1'
            or app['application_sha256'] != snapshot['group']['application_sha256']
            or app['publication_sha256'] != snapshot['group']['publication_sha256']
            or app['visibility']['installation_sha256'] is not None
            or app['visibility'].get('release_enabled') is not False):
        raise OnboardingError('companion_receive_source_changed')
    if child['state'] != 'completed':
        child = journal.get(child['operation_id'])
        journal.advance(child['operation_id'], 'completed', result=result,
            expected_runtime_observation=child['runtime_observation'])
    selection = dict(receiving_code=result['code_digest'],
        matrix_sdk=loaded['qualified_startup']['matrix_wheel_sha256'],
        runtime_bundle_sha256=loaded['runtime_bundle_sha256'],
        application_sha256=app['application_sha256'], publication_sha256=app['publication_sha256'],
        visibility_installation_sha256=None)
    complete = dict(link, loaded_receipt_sha256=digest(result), selection=selection)
    fresh = journal.get(parent)
    observed = copy.deepcopy(fresh['runtime_observation'])
    previous = observed['receive_controller']
    if previous != link and previous != complete:
        raise OnboardingError('companion_receive_original_changed')
    if previous != complete:
        observed['receive_controller'] = complete
        journal.advance(parent, fresh['state'], runtime_observation=observed,
            expected_runtime_observation=fresh['runtime_observation'])
    return complete


def adopt_controller_software_recovery(*, plan, owner, code, code_digest,
                                      manifest_path, manifest_digest, journal, row,
                                      validate, deadline_ns):
    """Record a qualified compatible load after an already-published controller.

    Never dispatch the old child again or reissue its authority. The failed
    software load stays degraded; fresh authenticated native proof establishes
    the same runtime/app under the explicitly selected compatible software.
    """
    from .onboarding_receiving_update import preflight, observe_current_reader
    phase = row['runtime_observation']['receive_application']
    snapshot = phase['snapshot']['result']
    retained = row['runtime_observation']['receive_controller']
    child = journal.get(retained['child_operation_id'])
    published = child['runtime_observation']['guest_bootstraps'][plan['name']]['owner_published']
    frozen = child['expected_precondition']['guest_bootstraps'][plan['name']]['owner']
    if (child['expected_precondition']['companion_receive'] != retained['binding']
            or retained['binding']['snapshot_sha256'] != digest(snapshot)
            or owner.plan != plan or owner.candidate != (code, code_digest)
            or not phase.get('restoration')):
        raise OnboardingError('companion_receive_original_changed')
    validate()
    checked = preflight(code, code_digest, manifest_path, manifest_digest,
        being_ref=frozen['being_ref'], embodiment_id=frozen['origin']['embodiment_id'])
    if checked['matrix_wheel_sha256'] != phase['baseline']['matrix_sdk']:
        raise OnboardingError('companion_receive_controller_sdk_changed')
    expected = dict(receiving_code=code_digest, matrix_sdk=checked['matrix_wheel_sha256'],
        runtime_bundle_sha256=published['runtime_sha256'],
        application_sha256=snapshot['group']['application_sha256'],
        publication_sha256=snapshot['group']['publication_sha256'], visibility_installation_sha256=None)
    previous = owner.deadline_ns
    try:
        owner.deadline_ns = deadline_ns
        proof = observe_current_reader(owner, expected_selection=expected, require_admitted=True,
            expires_at_ms=time.time_ns()//1_000_000+max(1,min(60000,(deadline_ns-time.monotonic_ns())//1_000_000)),
            receive_only=True)
    finally:
        owner.deadline_ns = previous
    if ((proof['reader']['being_ref'], proof['reader']['embodiment_id']) !=
            (frozen['being_ref'], frozen['origin']['embodiment_id'])):
        raise OnboardingError('companion_receive_source_changed')
    validate()
    recovery = dict(schema='cluster-companion-controller-software-recovery/v1',
        publication_sha256=digest(published), manifest_digest=manifest_digest,
        proof_sha256=digest(proof), source_code_digest=code_digest)
    complete = dict(retained, loaded_receipt_sha256=digest(proof), selection=expected,
        software_recovery=recovery)
    fresh = journal.get(row['operation_id'])
    if fresh['runtime_observation'].get('receive_controller') != retained:
        raise OnboardingError('companion_receive_original_changed')
    observed = copy.deepcopy(fresh['runtime_observation'])
    observed['receive_controller'] = complete
    journal.advance(fresh['operation_id'], fresh['state'], runtime_observation=observed,
        expected_runtime_observation=fresh['runtime_observation'])
    if child['state'] != 'degraded':
        journal.advance(child['operation_id'], 'degraded', result=dict(
            failed_software_load_retained=True, authority_publication_retained=True,
            compatible_software_recovery_sha256=digest(complete)),
            expected_runtime_observation=child['runtime_observation'])
    return complete


def configuration(value: dict, names) -> dict:
    try:
        fields = {'schema', 'helpers', 'key', 'policy', 'listen', 'intake_endpoint', 'stores', 'authority_order'}
        if (not isinstance(value, dict) or set(value) - {'ingress'} != fields or value['schema'] != SCHEMA
                or len(json.dumps(value).encode()) > 65536
                or not isinstance(value['policy'], dict)
                or set(value['policy']) != {'classification', 'max_ttl_ms'}
                or value['policy']['classification'] != 'shareable'
                or type(value['policy']['max_ttl_ms']) is not int
                or not 0 < value['policy']['max_ttl_ms'] <= 60000
                or not isinstance(value['listen'], dict) or set(value['listen']) != {'host', 'port'}
                or type(value['listen']['port']) is not int or not 0 < value['listen']['port'] <= 65535):
            raise ValueError
        ipaddress.IPv4Address(value['listen']['host'])
        helper_configuration(value['helpers'], names)
        parameters(value['key'])
        parameters(dict(value['key'], endpoint=value['intake_endpoint']))
        endpoint = urlsplit(value['intake_endpoint'])
        if (endpoint.hostname != value['listen']['host'] or endpoint.port != value['listen']['port']
                or not isinstance(value['stores'], dict)
                or set(value['stores']) != {'records', 'envelopes', 'opaque-evidence', 'opaque-message'}
                or any(not isinstance(v, str) or not 1 <= len(v) <= 128
                    or Path(v).name != v or v in {'.', '..', 'client.key'} for v in value['stores'].values())
                or len(set(value['stores'].values())) != len(value['stores'])
                or value['authority_order'] is not None and (not isinstance(value['authority_order'], list)
                    or any(not isinstance(ref, str) for ref in value['authority_order'])
                    or len(value['authority_order']) != len(set(value['authority_order'])))):
            raise ValueError
        if 'ingress' in value:
            from .onboarding_conversation_proxy import configuration as listener_configuration
            ingress = listener_configuration({'receiver': value['ingress']})['receiver']
            public = urlsplit(value['key']['endpoint'])
            target = ingress.get('vm', {}).get('address', '127.0.0.1')
            if (public.hostname != ingress['listen_host'] or public.port != ingress['listen_port']
                    or value['listen']['host'] != target):
                raise ValueError
    except (KeyError, TypeError, ValueError, AttributeError, OnboardingError):
        raise OnboardingError('companion_receive_preparation_required') from None
    return copy.deepcopy(value)


def publish(*, plan: dict, selected: dict, journal, row: dict, admission: dict,
            owners: dict, validate, deadline_ns: int) -> dict:
    """Resume one explicit receive phase without changing completed membership.

    Only the entrant Matrix service may pause. Other owners expose their own
    signed intake metadata/private resource through their existing granted pipe.
    Every effect has its original native operation/step before dispatch.
    """
    from .onboarding_group_admission import admission_owner_contexts, publication_command
    selected = configuration(selected, owners)
    name = plan['name']
    if (name not in owners or set(owners) != set(admission['receivers'])
            or set(selected['helpers']['owners']) != set(owners)
            or set(owners)-{name} != {p['name'] for p in row['expected_precondition']['senders']}):
        raise OnboardingError('companion_receive_preparation_required')
    social = row['intended_transition']['portal_admission']['social']
    contexts = admission_owner_contexts(row, social)
    original = row['operation_id']
    binding = digest(dict(original_intent=row['intent'], preparation=selected))

    def budget():
        if time.monotonic_ns() >= deadline_ns:
            raise OnboardingError('receiving_host_deadline_expired')
        validate()

    def current():
        return journal.get(original)

    def phase():
        return (current()['runtime_observation'] or {}).get('receive_application', {})

    def retain(key, value):
        budget()
        latest = current()
        observed = copy.deepcopy(latest['runtime_observation'] or {})
        entry = observed.setdefault('receive_application', dict(schema='cluster-companion-receive-phase/v1', binding=binding))
        if entry.get('binding') != binding or key in entry and entry[key] != value:
            raise OnboardingError('companion_receive_original_changed')
        entry[key] = value
        if len(json.dumps(entry).encode()) > being_seed.MAX_SELECTION-1024:
            raise OnboardingError('companion_receive_capacity')
        journal.advance(original, latest['state'], runtime_observation=observed,
            expected_runtime_observation=latest['runtime_observation'])

    entry = phase()
    if entry and (entry.get('schema') != 'cluster-companion-receive-phase/v1' or entry.get('binding') != binding):
        raise OnboardingError('companion_receive_original_changed')
    previous = {key:(owner.deadline_ns, owner.maintenance) for key,owner in owners.items()}
    try:
        # Reuse qualified helper preparation without opening any old service guard.
        for key, owner in owners.items():
            budget()
            owner.deadline_ns = deadline_ns
            Endpoint(owner, selected['helpers']['owners'][key], parent=original,
                binding=binding, deadline_ns=deadline_ns, validate=budget)
        one = dict(schema=selected['helpers']['schema'], owners={name:selected['helpers']['owners'][name]})
        # Recover an interrupted original pause before a base-status read could
        # mistake our own stopped service for a missing receiving capability.
        if (current()['runtime_observation'] or {}).get('receive_maintenance') is not None:
            with preserved({name:owners[name]}, one, journal=journal, row=current(),
                           deadline_ns=min(deadline_ns,time.monotonic_ns()+60_000_000_000),
                           validate=budget, phase='receive', restore_only=True):
                pass
        if isinstance(phase().get('snapshot', {}).get('result'), dict):
            budget()
            return copy.deepcopy(phase()['snapshot']['result'])
        if 'key' not in phase():
            budget()
            preview = owners[name].group_publication(dict(operation_id=social['operation_id'],
                step='receive-context-preview', action='context-preview', params={}),
                authority_closure={ref:v for ref,v in social['authority_closure'].items()
                    if ref != admission['receivers'][name]['being_ref']})
            if (preview.get('schema') != 'cluster-group-owner-context-preview/v1'
                    or preview.get('owner_context_sha256') != contexts[name]):
                raise OnboardingError('companion_receive_source_changed')
            if preview.get('predecessor_selection_sha256') is not None:
                raise OnboardingError('companion_receive_existing_application_preserved')
        if 'baseline' not in phase():
            budget()
            baseline = owners[name].base_status()
            loaded = baseline['runtime_status']['loaded_runtime']
            startup = loaded['qualified_startup']
            if baseline['server']['embodiment_id'] != admission['receivers'][name]['embodiment_id']:
                raise OnboardingError('companion_receive_source_changed')
            retain('baseline', dict(receiving_code=startup['code_digest'], matrix_sdk=startup['matrix_wheel_sha256'],
                runtime_bundle_sha256=loaded['runtime_bundle_sha256']))
        if 'ingress' in selected:
            # One stable Incus device, under this original job's authorization.
            # Lost add replies reconcile the same exact device; existing web,
            # Home and administrative routes are never replaced.
            from .onboarding_conversation_proxy import reconcile_listener
            budget()
            owner = owners[name]
            intent = dict(device='matrix-message', listener=selected['ingress'],
                guest_port=selected['listen']['port'])
            if 'ingress_intent' not in phase():
                retain('ingress_intent', intent)
            elif phase()['ingress_intent'] != intent:
                raise OnboardingError('companion_receive_original_changed')
            result = reconcile_listener(owner.backend, owner.plan, selected['ingress'],
                dict(port=selected['listen']['port'], listen_host=selected['listen']['host']),
                device_name='matrix-message', apply=True)
            if result.state != 'complete':
                raise OnboardingError('companion_receive_ingress_unconfirmed')
            if 'ingress' not in phase():
                retain('ingress', dict(intent, state='complete'))
        for key in sorted(set(owners)-{name}):
            if 'route-'+key in phase():
                continue
            budget()
            result = owners[key].group_publication(dict(operation_id=social['operation_id'],
                step='receive-route-preview', action='receive-route-preview', params={}), authority_closure={})
            approved = admission['receivers'][key]
            if (result.get('schema') != 'cluster-receive-route-preview/v1'
                    or result.get('operation_id') != social['operation_id']
                    or result.get('being_ref') != approved['being_ref']
                    or result.get('origin', {}).get('embodiment_id') != approved['embodiment_id']):
                raise OnboardingError('companion_receive_source_changed')
            retain('route-'+key, result)
        if 'reader_baselines' not in phase():
            baselines = {}
            for key in sorted(set(owners)-{name}):
                budget()
                observed = owners[key].status()
                loaded = observed['runtime_status']['loaded_runtime']
                app = observed['runtime_status']['loaded_application']
                source = phase()['route-'+key]['source']
                if (loaded['runtime_bundle_sha256'] != phase()['route-'+key]['runtime_bundle_sha256']
                        or app['application_sha256'] != source['application_sha256']
                        or app['publication_sha256'] != source['publication_sha256']):
                    raise OnboardingError('companion_receive_source_changed')
                baselines[key] = dict(receiving_code=loaded['qualified_startup']['code_digest'],
                    matrix_sdk=loaded['qualified_startup']['matrix_wheel_sha256'],
                    runtime_bundle_sha256=loaded['runtime_bundle_sha256'],
                    application_sha256=app['application_sha256'], publication_sha256=app['publication_sha256'],
                    visibility_installation_sha256=app['visibility']['installation_sha256'])
            retain('reader_baselines', baselines)
        with preserved({name:owners[name]}, one, journal=journal, row=current(),
                       deadline_ns=min(deadline_ns,time.monotonic_ns()+60_000_000_000),
                       validate=budget, phase='receive') as check:

            def submit(key, action, params, **guards):
                budget()
                check()
                command = publication_command(dict(operation_id=social['operation_id'], step='receive-'+key,
                    action=action, params=params, **guards))
                old = phase().get(key)
                if old is None:
                    retain(key, dict(command=command, result=None))
                elif old['command'] != command:
                    raise OnboardingError('companion_receive_original_changed')
                if old is not None and old.get('result') is not None:
                    return old['result']
                result = owners[name].group_publication(command, expected_context_sha256=contexts[name],
                    authority_closure={ref:v for ref,v in social['authority_closure'].items()
                        if ref != admission['receivers'][name]['being_ref']})
                if (result.get('schema') != 'cluster-group-publication-result/v1'
                        or result.get('status') != 'recorded'
                        or result.get('receiving_readiness') != 'unobserved'
                        or action == 'receive-snapshot' and (result.get('outbound_release') is not False
                            or not isinstance(result.get('group'), dict))
                        or any(result.get(k) != command[k] for k in ('operation_id', 'step', 'action'))):
                    raise OnboardingError('companion_receive_publication_unobserved')
                # Update a pending result by CAS, never replace a recorded result.
                latest = current()
                observed = copy.deepcopy(latest['runtime_observation'])
                saved = observed['receive_application'][key]
                if saved != dict(command=command, result=None):
                    raise OnboardingError('companion_receive_original_changed')
                saved['result'] = result
                if len(json.dumps(observed['receive_application']).encode()) > being_seed.MAX_SELECTION-1024:
                    raise OnboardingError('companion_receive_capacity')
                journal.advance(original, latest['state'], runtime_observation=observed,
                    expected_runtime_observation=latest['runtime_observation'])
                return result

            schema = phase().get('communication')
            if schema is None:
                budget()
                check()
                preview = owners[name].group_publication(dict(operation_id=social['operation_id'],
                    step='receive-schema-preview', action='context-preview', params={}),
                    expected_context_sha256=contexts[name],
                    authority_closure={ref:v for ref,v in social['authority_closure'].items()
                        if ref != admission['receivers'][name]['being_ref']})
                schema_plan = preview.get('communication_plan')
                if (preview.get('owner_context_sha256') != contexts[name]
                        or not isinstance(schema_plan, dict) or schema_plan.get('target_version') not in {3,4}
                        or not isinstance(schema_plan.get('plan_sha256'), str)):
                    raise OnboardingError('onboarding_group_initial_schema_required')
                schema_params = dict(expected_plan_sha256=schema_plan['plan_sha256'])
            else:
                schema_params = schema['command']['params']
            prepared_schema = submit('communication', 'receive-communication-prepare', schema_params)
            migration = prepared_schema.get('migration', {})
            if (migration.get('target_version') not in {3,4}
                    or migration.get('source_plan_sha256',migration.get('plan_sha256')) != schema_params['expected_plan_sha256']):
                raise OnboardingError('onboarding_group_initial_schema_required')
            own = submit('key', 'receive-key', selected['key'])
            own_route = own['route']
            sources = {}
            roster = []
            used_files = set()
            for key in sorted(owners):
                approved = admission['receivers'][key]
                if key == name:
                    route = own_route
                    source = dict(kind='prepared', command=phase()['key']['command'])
                else:
                    route = phase()['route-'+key]['route']
                    source = phase()['route-'+key]['source']
                if route['secret_file'] in used_files:
                    raise OnboardingError('companion_receive_resource_names_conflict')
                used_files.add(route['secret_file'])
                if 'import-'+key not in phase():
                    outgoing = dict(schema='cluster-private-receive-resource/v1', action='export',
                        operation_id=social['operation_id'], owner_context_sha256=contexts[key], route=route, source=source)
                    incoming = dict(outgoing, action='import', owner_context_sha256=contexts[name], source={})
                    retain('import-'+key, relay(owners[key], owners[name], outgoing, incoming, validate=budget))
                sources[route['secret_file']] = dict(receive_import=digest(route))
                # Body labels come from the already approved signed manifest.
                manifest = social['authority_closure'][approved['being_ref']]['authority']['manifest']
                bodies = [body for body in manifest['embodiments']
                    if body['embodiment_id'] == approved['embodiment_id'] and body['status'] == 'active']
                if len(bodies) != 1:
                    raise OnboardingError('companion_receive_source_changed')
                roster.append(dict(being_ref=approved['being_ref'], embodiment_id=approved['embodiment_id'],
                    body_ref=bodies[0]['body_ref'], route=route))
            application = submit('application', 'receive-application', dict(tribe_ref=admission['tribe_ref'],
                policy=selected['policy'], listen=selected['listen'],
                intake=dict(own_route, endpoint=selected['intake_endpoint']), roster=roster,
                stores=selected['stores'], secret_sources=sources, authority_order=selected['authority_order']))
            submit('selection', 'selection', dict(expected_selection_sha256=None),
                application_precondition=dict(application_step='receive-application',
                    application_sha256=application['application_sha256']))
            return submit('snapshot', 'receive-snapshot', dict(application_step='receive-application',
                selection_step='receive-selection', owner_context_sha256=contexts[name]))
    finally:
        for key, owner in owners.items():
            owner.deadline_ns, owner.maintenance = previous[key]



def require_current_reader_coverage(proofs: dict, receivers: dict) -> dict:
    """Cover every protected receiver/body and every represented Tribe being.

    Signed rosters can retain other embodiments of an already covered being.
    Their presence is not evidence of current placement or an instruction to
    revive retired bodies. Keep them visible without inventing reader proofs.
    """
    required = {(r['being_ref'], r['embodiment_id']) for r in receivers.values()}
    observed = {(p['reader']['being_ref'], p['reader']['embodiment_id']) for p in proofs.values()}
    beings = {being for being, _body in observed}
    if (not receivers or len(required) != len(receivers) or len(observed) != len(proofs)
            or set(proofs) != set(receivers) or required != observed
            or any((p['reader']['being_ref'], p['reader']['embodiment_id']) !=
                (receivers[name]['being_ref'], receivers[name]['embodiment_id']) for name,p in proofs.items())
            or any({r['being_ref'] for r in p['roster']['audience']} != beings for p in proofs.values())):
        raise OnboardingError('receiving_current_required_reader_missing')
    audience = {(r['being_ref'], r['embodiment_id']) for p in proofs.values() for r in p['roster']['audience']}
    if not observed <= audience:
        raise OnboardingError('receiving_current_required_reader_missing')
    return dict(coverage='authorized-current-receivers', unobserved_sibling_bodies=[
        dict(being_ref=being, embodiment_id=body) for being,body in sorted(audience-observed)])


def _collect(*, plan, selected, row, admission, owners, validate, deadline_ns, prepare=True,
             selection_updates=None):
    """Observe a complete current vector without changing any native gate."""
    from .onboarding_receiving_update import observe_current_reader, conversation_cohort, _reader_active, SourceGroupClient
    selected = configuration(selected, owners)
    entry = (row['runtime_observation'] or {}).get('receive_application', {})
    if (entry.get('binding') != digest(dict(original_intent=row['intent'], preparation=selected))
            or not isinstance(entry.get('snapshot', {}).get('result'), dict)):
        raise OnboardingError('onboarding_group_admission_pending')
    snapshot = entry['snapshot']['result']
    if selection_updates is None:
        selection_updates = entry.get('reader_selection', {}).get('selection_updates', {})
    name = plan['name']
    expected = copy.deepcopy(entry['reader_baselines'])
    expected[name] = dict(entry['baseline'],
        application_sha256=snapshot['group']['application_sha256'],
        publication_sha256=snapshot['group']['publication_sha256'], visibility_installation_sha256=None)
    forward = (row['runtime_observation'] or {}).get('receive_controller')
    if forward is not None:
        if (forward.get('binding', {}).get('parent') != row['operation_id']
                or forward['binding'].get('snapshot_sha256') != digest(snapshot)
                or forward.get('selection', {}).get('application_sha256') != expected[name]['application_sha256']
                or forward['selection'].get('publication_sha256') != expected[name]['publication_sha256']
                or forward['selection'].get('visibility_installation_sha256') is not None
                or not isinstance(forward.get('loaded_receipt_sha256'), str)):
            raise OnboardingError('companion_receive_original_changed')
        expected[name] = copy.deepcopy(forward['selection'])
    if set(expected) != set(owners) or set(owners) != set(admission['receivers']):
        raise OnboardingError('companion_receive_source_changed')
    for key, value in (selection_updates or {}).items():
        if (key not in expected or not isinstance(value, dict) or set(value) != set(expected[key])
                or any(value[field] != expected[key][field] for field in expected[key]
                    if field not in {'receiving_code', 'matrix_sdk'})):
            raise OnboardingError('companion_receive_source_changed')
        expected[key] = copy.deepcopy(value)
    previous = {key:(owner.deadline_ns, owner.maintenance) for key,owner in owners.items()}
    try:
        for key, owner in owners.items():
            validate()
            owner.deadline_ns = deadline_ns
            if prepare:
                Endpoint(owner, selected['helpers']['owners'][key], parent=row['operation_id'],
                    binding=entry['binding'], deadline_ns=deadline_ns, validate=validate)
        proofs = {}
        expires = time.time_ns()//1_000_000+max(1, min(60_000, (deadline_ns-time.monotonic_ns())//1_000_000))
        def read(item):
            key, owner = item
            validate()
            proof = observe_current_reader(owner, expected_selection=expected[key],
                require_admitted=not isinstance(owner, SourceGroupClient), expires_at_ms=expires,
                receive_only=expected[key]['visibility_installation_sha256'] is None)
            approved = admission['receivers'][key]
            reader = proof['reader']
            if (reader['being_ref'], reader['embodiment_id']) != (approved['being_ref'], approved['embodiment_id']):
                raise OnboardingError('companion_receive_source_changed')
            return key, proof
        # Independent owners share a finite proof-validity window. Serial CLI
        # startup/verification must not consume another owner's entire horizon.
        # Every result still passes the same identity, cohort and expiry checks.
        with ThreadPoolExecutor(max_workers=min(8, len(owners))) as pool:
            proofs = dict(pool.map(read, sorted(owners.items())))
        cohort = conversation_cohort(proofs)
        now = time.time_ns()//1_000_000
        if (time.monotonic_ns() >= deadline_ns
                or any(p['identity_expires_at_ms'] <= now or not _reader_active(p['reader'], now) for p in proofs.values())):
            raise OnboardingError('receiving_cohort_observation_expired')
        require_current_reader_coverage(proofs, admission['receivers'])
        validate()
        return proofs, cohort
    finally:
        for key, owner in owners.items():
            owner.deadline_ns, owner.maintenance = previous[key]


def observe(**options):
    """Read every current required reader; publication cannot satisfy this check."""
    from .onboarding import Observation
    entry = (options['row']['runtime_observation'] or {}).get('receive_application', {})
    if not isinstance(entry.get('snapshot', {}).get('result'), dict):
        return Observation('waiting', reason='group_admission_pending')
    proofs, cohort = _collect(**options)
    if any(proof['gate'].get('phase') != 'select'
            or proof['gate'].get('readers') != cohort['readers'] for proof in proofs.values()):
        return Observation('waiting', reason='group_admission_pending')
    return Observation('complete', dict(tribe_reader_selection_verified=True))


def select_readers(*, plan, selected, row, journal, admission, owners, validate, deadline_ns,
                   selection_updates=None):
    """Compose existing native revoke/select controls under the original job.

    All readers are observed before the barrier and must have unexpired proofs
    before each positive effect. Reuse the same finite vector while valid;
    each native control still checks its exact local gate and roster.
    Commands and owner-private request files are immutable; a later foreground
    invocation continues them without resetting membership, dates or reader data.
    The caller holds the original journal lock. No application/visibility changes.
    """
    import uuid
    selected = configuration(selected, owners)
    parent = row['operation_id']
    binding = digest(dict(original_intent=row['intent'], preparation=selected))
    if selection_updates is None:
        selection_updates = (row['runtime_observation'] or {}).get('receive_application', {}).get(
            'reader_selection', {}).get('selection_updates', {})
    revision = digest(selection_updates or {})
    previous_selection = None
    def current():
        return journal.get(parent)
    def phase():
        return (current()['runtime_observation'] or {}).get('receive_application', {})
    def check():
        if time.monotonic_ns() >= deadline_ns:
            raise OnboardingError('receiving_host_deadline_expired')
        validate()
        state = phase()
        snapshot = state.get('snapshot', {}).get('result')
        if (state.get('binding') != binding or not isinstance(snapshot, dict)
                or state.get('restoration') != dict(schema='cluster-companion-receive-restored/v1',
                    operation_id=parent, snapshot_sha256=digest(snapshot), preparation_sha256=digest(selected))):
            raise OnboardingError('companion_receive_restoration_required')
    def collect():
        check()
        return _collect(plan=plan, selected=selected, row=current(), admission=admission,
            owners=owners, validate=check, deadline_ns=deadline_ns, prepare=False,
            selection_updates=selection_updates)
    def save(value):
        check()
        latest = current()
        observed = copy.deepcopy(latest['runtime_observation'])
        if previous_selection is not None:
            observed['receive_application']['reader_selection_previous'] = previous_selection
        observed['receive_application']['reader_selection'] = value
        if len(json.dumps(observed['receive_application']).encode()) > being_seed.MAX_SELECTION-1024:
            raise OnboardingError('companion_receive_capacity')
        journal.advance(parent, latest['state'], runtime_observation=observed,
            expected_runtime_observation=latest['runtime_observation'])
    previous = {key:(owner.deadline_ns, owner.maintenance) for key,owner in owners.items()}
    try:
        check()
        def prepare_owner(item):
            key, owner = item
            owner.deadline_ns = deadline_ns
            Endpoint(owner, selected['helpers']['owners'][key], parent=parent,
                binding=binding, deadline_ns=deadline_ns, validate=check)
        # Independent helper preparation must not serialize eight
        # host/guest traversals before the finite proof/control window.
        with ThreadPoolExecutor(max_workers=min(8, len(owners))) as pool:
            list(pool.map(prepare_owner, owners.items()))
        proofs, cohort = collect()
        state = phase().get('reader_selection')
        if state is not None and state.get('selection_updates_sha256', digest({})) != revision:
            if not all(state.get('controls', {}).get('select-'+name, {}).get('result')
                       for name in owners):
                raise OnboardingError('companion_receive_reader_control_changed')
            # Completed effects retain one full predecessor. A software update
            # gets fresh native controls, never replays old process-bound ones.
            previous_selection, state = copy.deepcopy(state), None
        if state is None:
            if all(p['gate'].get('phase') == 'select' and p['gate'].get('readers') == cohort['readers']
                    for p in proofs.values()):
                # Already selected elsewhere: observe that fact, never replace its owner.
                return dict(tribe_reader_selection_verified=True)
            state = dict(schema='cluster-companion-current-readers/v1',
                selection_updates_sha256=revision,
                selection_updates=copy.deepcopy(selection_updates or {}),
                readers=cohort['readers'], membership_basis_sha256=cohort['membership_basis_sha256'],
                expected={name:p['expected'] for name,p in proofs.items()},
                initial_gates={name:p['gate'] for name,p in proofs.items()}, controls={})
            # A different in-progress barrier is not ours to take over.
            if any(p['gate'].get('phase') == 'revoke' for p in proofs.values()):
                raise OnboardingError('companion_receive_reader_control_changed')
            save(state)
        identity = 'companion-readers:'+parent+':'+binding
        if selection_updates:
            identity += ':'+revision
        control_id = str(uuid.uuid5(uuid.NAMESPACE_URL, identity))
        release = digest(dict(original=parent, binding=binding, readers=state['readers'],
            membership_basis_sha256=state['membership_basis_sha256']))
        def unchanged(proofs, cohort):
            if (state.get('schema') != 'cluster-companion-current-readers/v1'
                    or state['readers'] != cohort['readers']
                    or state['membership_basis_sha256'] != cohort['membership_basis_sha256']
                    or state['expected'] != {name:p['expected'] for name,p in proofs.items()}):
                raise OnboardingError('companion_receive_reader_control_changed')
        unchanged(proofs, cohort)
        for mode in ('revoke', 'select'):
            for name in sorted(owners):
                key = mode+'-'+name
                old = state['controls'].get(key)
                # Once select starts, already selected owners remain selected.
                # Never replay a revocation on a completed retry.
                if mode == 'revoke' and 'select-'+name in state['controls']:
                    continue
                gate = proofs[name]['gate']
                before = (state['initial_gates'][name] if mode == 'revoke'
                    else state['controls']['revoke-'+name]['result']['gate'])
                command = (old['command'] if old is not None else dict(
                    schema='dm.runtime.reader-selection/v2', channel_id='tribe',
                    process_instance_id=before['process_instance_id'], expected_head=before['head'],
                    operation_id=control_id, release_digest=release, phase=mode,
                    readers=[] if mode == 'revoke' else state['readers'],
                    expected_roster_sha256=proofs[name]['roster']['roster_sha256']))
                if old is not None and old.get('result') is not None:
                    if gate != old['result']['gate']:
                        raise OnboardingError('companion_receive_reader_control_changed')
                    continue
                if mode == 'select':
                    # A proof already has a native <=60-second validity. Repeating
                    # eight cold CLI reads for every gate can exhaust the whole
                    # operator window while the barrier is closed. Refresh only
                    # when that existing proof window ends; local gate/roster CAS
                    # and the final complete observation remain mandatory.
                    from .onboarding_receiving_update import _reader_active
                    now = time.time_ns() // 1_000_000
                    if any(p['identity_expires_at_ms'] <= now
                            or not _reader_active(p['reader'], now) for p in proofs.values()):
                        proofs, cohort = collect()
                    unchanged(proofs, cohort)
                    gate = proofs[name]['gate']
                    for other,p in proofs.items():
                        done = state['controls'].get('select-'+other, {}).get('result')
                        required = (done or state['controls']['revoke-'+other]['result'])['gate']
                        pending_own = (other == name and old is not None and old.get('result') is None
                            and all(p['gate'].get(k) == command[k] for k in
                                ('process_instance_id','operation_id','release_digest','phase','readers')))
                        if p['gate'] != required and not pending_own:
                            raise OnboardingError('companion_receive_reader_control_changed')
                # A pending exact request can already have changed this gate.
                # The owner reconciles its retained private request and hash.
                if old is None:
                    if gate != before:
                        raise OnboardingError('companion_receive_reader_control_changed')
                    state['controls'][key] = dict(command=command, result=None)
                    save(state)
                check()
                path = owners[name].root/'receiving-control'/(control_id+'-'+mode+'.json')
                result = owners[name].prepare_apply_control(command, path)
                if (result.get('schema') != 'cluster-receiving-owner-control-observation/v1'
                        or result.get('command_sha256') != digest(command)
                        or not isinstance(result.get('request_sha256'), str) or len(result['request_sha256']) != 64
                        or result.get('process') != state['expected'][name]['process']
                        or result.get('server') != state['expected'][name]['server']
                        or result.get('gate', {}).get('phase') != mode
                        or result['gate'].get('readers') != command['readers']
                        or result['gate'].get('operation_id') != control_id
                        or result['gate'].get('release_digest') != release
                        or result['gate'].get('request_sha256') != result.get('request_sha256')):
                    raise OnboardingError('companion_receive_reader_control_unobserved')
                state['controls'][key]['result'] = {k:result[k] for k in ('gate','process','server','request_sha256')}
                proofs[name]['gate'] = result['gate']
                save(state)
        proofs, cohort = collect()
        unchanged(proofs, cohort)
        if any(p['gate'] != state['controls']['select-'+name]['result']['gate'] for name,p in proofs.items()):
            raise OnboardingError('companion_receive_reader_control_changed')
        return dict(tribe_reader_selection_verified=True)
    finally:
        for key, owner in owners.items():
            owner.deadline_ns, owner.maintenance = previous[key]
