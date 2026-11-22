"""Resource and failed-coverage boundaries for the finite daily phase."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zlib

SPEC = importlib.util.spec_from_file_location('children_daily', Path(__file__).parents[1]/'tools/children_daily.py')
daily = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(daily)


class Response:
    def __init__(self, raw, url=daily.FEED):
        self.raw, self.url = raw, url

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def geturl(self):
        return self.url

    def read(self, limit):
        return self.raw[:limit]


class Opener:
    def __init__(self, response):
        self.response = response

    def open(self, request, timeout):
        return self.response


class DailyTests(unittest.TestCase):
    def test_command_caps_combined_stderr_and_stdout(self):
        with self.assertRaises(daily.LimitError):
            daily.command([sys.executable, '-c', 'import sys;sys.stderr.write("x"*2048)'], limit=128)

    def test_timed_out_read_process_is_terminated(self):
        with self.assertRaises(daily.LimitError):
            daily.command([sys.executable, '-c', 'import time;time.sleep(5)'], seconds=.05)

    def test_nonzero_read_never_returns_successful_empty_inventory(self):
        with self.assertRaises(ValueError):
            daily.command([sys.executable, '-c', 'raise SystemExit(3)'])

    def test_vendor_feed_requires_valid_schema_and_complete_stream(self):
        raw = zlib.compress(b'VERSION 1\nfixture\n')
        self.assertEqual(daily.fetch_feed(Opener(Response(raw))), raw)
        for invalid in (raw[:-1], zlib.compress(b'VERSION 9\n'), raw+b'unexpected'):
            with self.assertRaises(ValueError):
                daily.fetch_feed(Opener(Response(invalid)))

    def test_redirect_is_not_accepted_as_vendor_evidence(self):
        with self.assertRaises(ValueError):
            daily.fetch_feed(Opener(Response(zlib.compress(b'VERSION 1\n'), 'https://example.invalid')))

    def test_expansion_bomb_is_bounded_before_matching(self):
        raw = zlib.compress(b'VERSION 1\n'+b'x'*(65*daily.MIB))
        with self.assertRaises(daily.LimitError):
            daily.fetch_feed(Opener(Response(raw)))

    def test_atomic_receipt_refuses_symlink_target(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); original=root/'protected';original.write_text('keep')
            (root/'current').symlink_to(original)
            with self.assertRaises(ValueError):
                daily.atomic(root/'current', b'replacement')
            self.assertEqual(original.read_text(), 'keep')

    def test_offline_guest_and_unavailable_feed_remain_unassessed(self):
        with tempfile.TemporaryDirectory() as temp:
            config={'state':temp,'targets':[{'id':'pixin','instance':'dm-pixin'}]}
            with patch.object(daily,'validate'), patch.object(daily,'fetch_feed',side_effect=OSError), \
                    patch.object(daily,'command',side_effect=ValueError('offline')):
                result=daily.collect(config)
            self.assertEqual(result['source']['state'],'unavailable')
            self.assertEqual(result['targets']['pixin']['debian_advisories'],'unassessed')
            self.assertEqual(result['coverage'],'partial')
            self.assertEqual(json.loads((Path(temp)/'current.json').read_text()),result)

    def test_matcher_failure_preserves_successful_inventory_as_separate_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            config={'state':temp,'scanner':'unused','targets':[{'id':'pixin','instance':'dm-pixin'}]}
            observed={'os':{'ID':'debian','VERSION_ID':'13','VERSION_CODENAME':'trixie'},
                      'package_status':'Package: fixture\nVersion: 1\n'}
            with patch.object(daily,'validate'), patch.object(daily,'fetch_feed',return_value=b'feed'), \
                    patch.object(daily,'command',side_effect=[json.dumps(observed).encode(),ValueError('matcher')]):
                result=daily.collect(config)
            self.assertEqual(result['targets']['pixin']['inventory'],'observed')
            self.assertEqual(result['targets']['pixin']['debian_advisories'],'unassessed')
            self.assertEqual((Path(temp)/'no-suppressions').read_text(),'VERSION 0\n')

    def test_cleanup_failure_never_discards_real_inventory_or_advisory_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            config={'state':temp,'scanner':'unused','compiler_cleanup_enabled':True,
                    'targets':[{'id':'pixin','instance':'dm-pixin'}]}
            observed={'os':{'ID':'debian','VERSION_ID':'13','VERSION_CODENAME':'trixie'},
                      'package_status':'Package: fixture\nVersion: 1\n'}
            with patch.object(daily,'validate'),patch.object(daily,'fetch_feed',return_value=b'feed'),\
                 patch.object(daily,'command',side_effect=[ValueError('cleanup failed'),
                   json.dumps(observed).encode(),b'CVE-fictional fixture\n']):
                result=daily.collect(config)
            value=result['targets']['pixin']
            self.assertEqual(value['inventory'],'observed')
            self.assertEqual(value['debian_advisories'],'matched')
            self.assertEqual(value['compiler_cleanup']['status'],'unavailable')

    def test_selected_cleanup_uses_its_own_finite_guest_unit(self):
        with tempfile.TemporaryDirectory() as temp:
            config={'state':temp,'scanner':'unused','compiler_cleanup_enabled':True,
                    'targets':[{'id':'pixin','instance':'dm-pixin'}]}
            observed={'os':{'ID':'debian','VERSION_ID':'13','VERSION_CODENAME':'trixie'},
                      'package_status':'Package: fixture\nVersion: 1\n'}
            cleanup={'schema':'children-cache-cleanup/v1','status':'complete','cache_dirs_removed':0}
            with patch.object(daily,'validate'),patch.object(daily,'fetch_feed',return_value=b'feed'),\
                 patch.object(daily,'command',side_effect=[b'',json.dumps(cleanup).encode(),
                   json.dumps(observed).encode(),b'']) as calls:
                result=daily.collect(config)
            self.assertEqual(result['targets']['pixin']['compiler_cleanup'],cleanup)
            first=calls.call_args_list[0]
            self.assertIn('children-cache-cleanup.service',first.args[0])
            self.assertEqual(first.kwargs['seconds'],100)

    def test_disabling_cleanup_preserves_pending_state_and_other_daily_phases(self):
        with tempfile.TemporaryDirectory() as temp:
            pending=Path(temp)/'pending-evidence';pending.write_bytes(b'keep pending')
            config={'state':temp,'scanner':'unused','compiler_cleanup_enabled':False,
                    'targets':[{'id':'pixin','instance':'dm-pixin'}]}
            observed={'os':{'ID':'debian','VERSION_ID':'13','VERSION_CODENAME':'trixie'},
                      'package_status':'Package: fixture\nVersion: 1\n'}
            with patch.object(daily,'validate'),patch.object(daily,'fetch_feed',return_value=b'feed'),\
                 patch.object(daily,'command',side_effect=[json.dumps(observed).encode(),b'']) as calls:
                result=daily.collect(config)
            self.assertEqual(calls.call_count,2)
            self.assertEqual(result['targets']['pixin']['debian_advisories'],'matched')
            self.assertNotIn('compiler_cleanup',result['targets']['pixin'])
            self.assertEqual(pending.read_bytes(),b'keep pending')


class BrowserObservationTests(unittest.TestCase):
    selection={'helper':'/opt/children-maintenance/browser-helpers/fixture/children_browser.py',
               'sha256':'a'*64}

    def test_selection_requires_exact_explicit_fields(self):
        daily.validate_browser_selection(self.selection)
        for value in (True,{},dict(self.selection,extra=True),
                      dict(self.selection,helper='relative.py'),
                      dict(self.selection,sha256='not-a-hash')):
            with self.subTest(value=value),self.assertRaises(ValueError):
                daily.validate_browser_selection(value)

    def test_standby_read_contains_no_lifecycle_or_tab_command(self):
        reply={'schema':'children-browser-status/v1','state':'standby','intentional':True}
        with patch.object(daily,'command',return_value=json.dumps(reply).encode()) as call:
            result=daily.browser_status('dm-pixin',self.selection)
        self.assertEqual(result['state'],'standby')
        argv=call.call_args.args[0]
        self.assertEqual(argv[:4],['incus','exec','dm-pixin','--'])
        source=argv[-1]
        self.assertIn("str(p),'status'",source)
        self.assertIn("hashlib.sha256(p.read_bytes())",source)
        self.assertNotIn("'start'",source)
        self.assertNotIn('/command',source)
        self.assertEqual(call.call_args.kwargs,{'seconds':25,'limit':128*1024})

    def test_connection_metadata_is_not_a_browser_journey(self):
        reply={'schema':'children-browser-status/v1','state':'ready',
               'bridge':{'running':True,'extension_connected':True,'version':'v2.0.22'},
               'arbitrary_private_field':'never propagate'}
        with patch.object(daily,'command',return_value=json.dumps(reply).encode()):
            result=daily.browser_status('dm-pixin',self.selection)
        self.assertEqual(result['observation'],'connection-metadata-only')
        self.assertNotIn('arbitrary_private_field',result)
        for bridge in ({'running':True,'extension_connected':False,'version':'v2.0.22'},
                       {'running':True,'extension_connected':True,'version':'2.0.23'}):
            with patch.object(daily,'command',return_value=json.dumps(dict(reply,bridge=bridge)).encode()):
                with self.assertRaises(ValueError):daily.browser_status('dm-pixin',self.selection)

    def test_unknown_and_false_standby_are_not_green(self):
        for reply in ({'schema':'children-browser-status/v1','state':'standby','intentional':False},
                      {'schema':'children-browser-status/v1','state':'unknown'},
                      {'schema':'other','state':'standby','intentional':True},[]):
            with patch.object(daily,'command',return_value=json.dumps(reply).encode()):
                with self.assertRaises(ValueError):daily.browser_status('dm-pixin',self.selection)

    def test_unavailable_browser_keeps_inventory_findings_and_pending_work(self):
        with tempfile.TemporaryDirectory() as temp:
            pending=Path(temp)/'pending-evidence';pending.write_bytes(b'keep')
            config={'state':temp,'scanner':'unused','browser_status':self.selection,
                    'targets':[{'id':'pixin','instance':'dm-pixin'}]}
            observed={'os':{'ID':'debian','VERSION_ID':'13','VERSION_CODENAME':'trixie'},
                      'package_status':'Package: fixture\nVersion: 1\n'}
            with patch.object(daily,'validate'),patch.object(daily,'fetch_feed',return_value=b'feed'),                  patch.object(daily,'browser_status',side_effect=ValueError('unavailable')),                  patch.object(daily,'command',side_effect=[json.dumps(observed).encode(),b'CVE-fictional\n']):
                result=daily.collect(config)
            self.assertEqual(result['targets']['pixin']['browser']['state'],'unavailable')
            self.assertEqual(result['targets']['pixin']['inventory'],'observed')
            self.assertEqual(result['targets']['pixin']['debian_advisories'],'matched')
            self.assertEqual(pending.read_bytes(),b'keep')
            with patch.object(sys,'argv',['daily','--config',str(Path(temp)/'config.json')]),                  patch.object(daily,'collect',return_value=result):
                (Path(temp)/'config.json').write_text(json.dumps(config))
                self.assertEqual(daily.main(),2)

    def test_omitting_browser_selection_does_not_run_its_reader(self):
        with tempfile.TemporaryDirectory() as temp:
            config={'state':temp,'scanner':'unused','targets':[{'id':'pixin','instance':'dm-pixin'}]}
            observed={'os':{'ID':'debian','VERSION_ID':'13','VERSION_CODENAME':'trixie'},
                      'package_status':'Package: fixture\nVersion: 1\n'}
            with patch.object(daily,'validate'),patch.object(daily,'fetch_feed',return_value=b'feed'),                  patch.object(daily,'browser_status',side_effect=AssertionError('disabled reader')),                  patch.object(daily,'command',side_effect=[json.dumps(observed).encode(),b'']):
                result=daily.collect(config)
            self.assertNotIn('browser',result['targets']['pixin'])


class ApplicationObservationTests(unittest.TestCase):
    selection={'helper':'/opt/children-maintenance/qualified/reader.py','sha256':'a'*64,
               'units':{n:['own.service'] for n in ['lordoftheflies','pixin','calipso','c-137','noodles']}}

    def test_network_selection_is_explicit_and_reaches_existing_reader(self):
        chosen=dict(self.selection,network_listeners=True)
        daily.validate_application_selection(chosen)
        value={'schema':'children-application-inventory/v1','units':{'own.service':{'state':'observed'}}}
        with patch.object(daily,'command',return_value=json.dumps(value).encode()) as call:
            daily.application_inventory('pixin','dm-pixin',chosen)
        self.assertIn("options['include_network_listeners']=True",call.call_args.args[0][-1])
        with self.assertRaises(ValueError):
            daily.validate_application_selection(dict(self.selection,network_listeners='yes'))

    def test_selected_components_cannot_hide_missing_data_or_require_host_browser(self):
        value={'schema':'children-application-inventory/v1','units':{'own.service':{'state':'observed'}}}
        chosen=dict(self.selection,browser_components=True)
        with patch.object(daily,'command',return_value=json.dumps(value).encode()):
            self.assertEqual(daily.application_inventory('pixin','dm-pixin',chosen)['state'],'unavailable')
            self.assertEqual(daily.application_inventory('lordoftheflies',None,chosen)['state'],'observed')
        with self.assertRaises(ValueError):daily.validate_application_selection(dict(self.selection,browser_components='yes'))

    def test_application_selection_is_explicit_bounded_and_not_shell(self):
        daily.validate_application_selection(self.selection)
        for value in ({},dict(self.selection,units={}),
                      dict(self.selection,units={**self.selection['units'],'pixin':['own.service; bad']}),
                      dict(self.selection,units={**self.selection['units'],'pixin':[{}]})):
            with self.assertRaises(ValueError):daily.validate_application_selection(value)

    def test_reader_uses_own_bounded_native_read_job_and_keeps_partial_data(self):
        value={'schema':'children-application-inventory/v1','units':{'own.service':{'state':'unavailable','reason':'fixture'}},'coverage':'partial'}
        with patch.object(daily,'command',return_value=json.dumps(value).encode()) as call:
            result=daily.application_inventory('pixin','dm-pixin',self.selection)
        self.assertEqual(result['state'],'unavailable');self.assertEqual(result['units'],value['units'])
        argv=call.call_args.args[0]
        self.assertEqual(argv[:4],['incus','exec','dm-pixin','--'])
        self.assertIn('RuntimeMaxSec=40',argv);self.assertIn('-S',argv)
        self.assertIn('hashlib.sha256(p.read_bytes())',argv[-1])
        self.assertEqual(call.call_args.kwargs,{'seconds':55,'limit':384*1024})

    def test_application_read_failure_keeps_other_daily_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            config={'state':temp,'scanner':'unused','application_inventory':self.selection,
                    'targets':[{'id':'pixin','instance':'dm-pixin'}]}
            observed={'os':{'ID':'debian','VERSION_ID':'13','VERSION_CODENAME':'trixie'},
                      'package_status':'Package: fixture\nVersion: 1\n'}
            with patch.object(daily,'validate'),patch.object(daily,'fetch_feed',return_value=b'feed'),                  patch.object(daily,'application_inventory',side_effect=ValueError('fixture')),                  patch.object(daily,'command',side_effect=[json.dumps(observed).encode(),b'CVE-fictional\n']):
                result=daily.collect(config)
            self.assertEqual(result['targets']['pixin']['applications']['state'],'unavailable')
            self.assertEqual(result['targets']['pixin']['debian_advisories'],'matched')

    def test_disabled_stage_does_not_run_a_reader(self):
        with tempfile.TemporaryDirectory() as temp:
            config={'state':temp,'scanner':'unused','targets':[{'id':'pixin','instance':'dm-pixin'}]}
            observed={'os':{'ID':'debian','VERSION_ID':'13','VERSION_CODENAME':'trixie'},'package_status':'Package: fixture\nVersion: 1\n'}
            with patch.object(daily,'validate'),patch.object(daily,'fetch_feed',return_value=b'feed'),                  patch.object(daily,'application_inventory',side_effect=AssertionError('disabled')),                  patch.object(daily,'command',side_effect=[json.dumps(observed).encode(),b'']):
                result=daily.collect(config)
            self.assertNotIn('applications',result['targets']['pixin'])


class CleanupReceiptReadTests(unittest.TestCase):
    def test_malformed_read_reconciles_receipt_without_another_mutation(self):
        receipt={'schema':'children-cache-cleanup/v1','status':'complete'}
        with patch.object(daily,'command',side_effect=[b'',json.dumps(receipt).encode()]) as calls:
            result=daily.cleanup_receipt('dm-calipso')
        self.assertEqual(result['status'],'complete')
        self.assertEqual(result['receipt_read_recovery']['bytes'],0)
        self.assertEqual(calls.call_count,2)
        for call in calls.call_args_list:
            self.assertNotIn('systemctl',call.args[0])
            self.assertIn('json.loads(raw)',call.args[0][-1])

    def test_second_bad_read_stays_unavailable(self):
        with patch.object(daily,'command',return_value=b'not-json') as calls:
            with self.assertRaises(ValueError):daily.cleanup_receipt('dm-calipso')
        self.assertEqual(calls.call_count,2)


class PublicAdvisoryPhaseTests(unittest.TestCase):
    selection={'helper':'/opt/qualified/advisories.py','sha256':'a'*64,'public_names':['public-one']}

    def test_explicit_public_selection_is_required(self):
        daily.validate_advisory_selection(self.selection)
        for value in (dict(self.selection,public_names=['private token']),
                      dict(self.selection,public_names=['public_one','public-one']),{},
                      dict(self.selection,public_names=[])):
            with self.assertRaises(ValueError):daily.validate_advisory_selection(value)

    def test_source_failure_preserves_last_success_not_a_clean_empty_result(self):
        from types import SimpleNamespace
        good={'schema':'children-public-advisories/v1','state':'matched','checked':100,
              'query_sha256':'previous','needs_triage':True,'records':[{'id':'MAL-fixture'}]}
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            with patch.object(daily,'load_public_matcher',return_value=SimpleNamespace(match=lambda *a:good)):
                self.assertEqual(daily.public_advisories(self.selection,[],root),good)
            original=(root/'public-advisories/current.json').read_bytes()
            with patch.object(daily,'load_public_matcher',side_effect=OSError('offline')):
                failed=daily.public_advisories(self.selection,[],root)
            self.assertEqual(failed['state'],'unavailable')
            self.assertEqual(failed['last_success_checked'],100)
            self.assertEqual((root/'public-advisories/current.json').read_bytes(),original)
            status=json.loads((root/'public-advisories/status.json').read_text())
            self.assertEqual(status['state'],'unavailable')
            self.assertNotIn('records',status)

    def test_untriaged_candidate_is_pending_even_with_successful_queries(self):
        result={'coverage':'partial','source':{'state':'fresh'},'targets':{},
                'public_advisories':{'state':'matched','needs_triage':True}}
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)/'config.json';p.write_text('{}')
            with patch.object(sys,'argv',['daily','--config',str(p)]),patch.object(daily,'collect',return_value=result):
                self.assertEqual(daily.main(),2)


class KnownExploitationTests(unittest.TestCase):
    selection={'helper':'/opt/qualified/kev.py','sha256':'a'*64}

    def test_vendor_selection_is_explicit_and_boolean(self):
        daily.validate_known_selection(dict(self.selection,assess_chromium=True))
        daily.validate_known_selection(dict(self.selection,assess_chromium=True,assess_freetype=True))
        with self.assertRaises(ValueError):daily.validate_known_selection(dict(self.selection,assess_freetype=True))
        for value in ({},dict(self.selection,assess_chromium='yes'),dict(self.selection,source='arbitrary')):
            with self.assertRaises(ValueError):daily.validate_known_selection(value)

    def test_vendor_failure_keeps_accepted_evidence_and_never_returns_clean(self):
        from types import SimpleNamespace
        good={'schema':'children-known-exploitation/v1','state':'matched','checked':100,
              'source_sha256':'previous','needs_triage':True,'matches':[]}
        report={'targets':{n:{'debian_advisories':'matched'} for n in ('pixin','calipso','c-137','noodles')}}
        fake=SimpleNamespace(match=lambda *a:dict(good),chromium_context=lambda *a:{},
                             assess_chromium=lambda *a:(_ for _ in ()).throw(OSError('vendor unavailable')))
        with tempfile.TemporaryDirectory() as temp,patch.object(daily,'load_public_matcher',return_value=fake):
            root=Path(temp);candidates={n:[] for n in report['targets']}
            daily.known_exploitation(self.selection,candidates,report,root)
            original=(root/'known-exploitation/current.json').read_bytes()
            for n in report['targets']:
                (root/n).mkdir();(root/n/'packages.status').write_text('fixture');(root/n/'debian-findings.txt').write_text('')
            result=daily.known_exploitation(dict(self.selection,assess_chromium=True),candidates,report,root)
            self.assertEqual(result['state'],'unavailable');self.assertEqual(result['last_success_checked'],100)
            self.assertEqual((root/'known-exploitation/current.json').read_bytes(),original)

    def test_failure_keeps_original_receipt_and_records_old_freshness(self):
        from types import SimpleNamespace
        good={'schema':'children-known-exploitation/v1','state':'matched','checked':100,
              'source_sha256':'previous','needs_triage':True,'matches':[{'cve':'CVE-2026-12345'}]}
        report={'targets':{'pixin':{'debian_advisories':'matched'}}}
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            with patch.object(daily,'load_public_matcher',return_value=SimpleNamespace(match=lambda *a:good)):
                self.assertEqual(daily.known_exploitation(self.selection,{'pixin':[]},report,root),good)
            original=(root/'known-exploitation/current.json').read_bytes()
            with patch.object(daily,'load_public_matcher',side_effect=ValueError('bad hash')):
                failed=daily.known_exploitation(self.selection,{'pixin':[]},report,root)
            self.assertEqual(failed['state'],'unavailable')
            self.assertEqual(failed['last_success_checked'],100)
            self.assertEqual((root/'known-exploitation/current.json').read_bytes(),original)
            with patch.object(daily,'load_public_matcher') as loader:
                self.assertEqual(daily.known_exploitation(self.selection,{},report,root)['state'],'unavailable')
                loader.assert_not_called()

    def test_osv_aliases_bind_current_candidates_but_withdrawn_records_do_not(self):
        from types import SimpleNamespace
        report={'targets':{'pixin':{'debian_advisories':'matched'}},'public_advisories':{
            'state':'matched','records':[{'id':'GHSA-test','aliases':['CVE-2026-12345'],'withdrawn':None},
                {'id':'CVE-2026-99999','aliases':[],'withdrawn':'yesterday'}]}}
        seen=[]
        def match(values):
            seen.append(values)
            return {'schema':'children-known-exploitation/v1','state':'matched','checked':100,'needs_triage':False}
        with tempfile.TemporaryDirectory() as temp, patch.object(daily,'load_public_matcher',return_value=SimpleNamespace(match=match)):
            daily.known_exploitation(self.selection,{'pixin':[]},report,Path(temp))
        self.assertEqual(seen,[{'pixin':[],'public-python':['CVE-2026-12345']}])

    def test_matches_or_unavailable_source_leave_daily_pending(self):
        for state,triage in [('matched',True),('unavailable',False)]:
            result={'coverage':'partial','source':{'state':'fresh'},'targets':{},
                    'known_exploitation':{'state':state,'needs_triage':triage}}
            with tempfile.TemporaryDirectory() as temp:
                p=Path(temp)/'config.json';p.write_text('{}')
                with patch.object(sys,'argv',['daily','--config',str(p)]),patch.object(daily,'collect',return_value=result):
                    self.assertEqual(daily.main(),2)


if __name__ == '__main__':
    unittest.main()


class CurrentPhaseEvidenceTests(unittest.TestCase):
    def test_completed_observation_does_not_clear_pending_security_assessment(self):
        result = {'coverage': 'partial', 'source': {'state': 'fresh'},
            'targets': {'pixin': {'debian_advisories': 'matched',
                'compiler_cleanup': {'status': 'complete'}, 'browser': {'state': 'standby'},
                'applications': {'state': 'observed'}}},
            'public_advisories': {'state': 'matched', 'needs_triage': True},
            'known_exploitation': {'state': 'matched', 'needs_triage': True},
            'unassessed': ['malicious-release-advisories']}
        self.assertTrue(daily.observation_complete(result))
        self.assertEqual(result['coverage'], 'partial')
        self.assertTrue(result['known_exploitation']['needs_triage'])
        for key in ('public_advisories', 'known_exploitation'):
            result[key]['state'] = 'unavailable'
            self.assertFalse(daily.observation_complete(result))
            result[key]['state'] = 'matched'
        result['targets']['pixin']['applications']['state'] = 'unavailable'
        self.assertFalse(daily.observation_complete(result))
        result['targets'] = {}
        self.assertFalse(daily.observation_complete(result))

    def test_current_cleanup_and_browser_success_survive_pending_advisory_triage(self):
        names = ['pixin', 'calipso', 'c-137', 'noodles']
        config = {'targets': [{'id': 'host', 'instance': None}] +
                  [{'id': name, 'instance': 'dm-' + name} for name in names],
                  'application_inventory': {'selected': True}, 'compiler_cleanup_enabled': True,
                  'browser_status': {'selected': True}, 'public_advisories': {'selected': True},
                  'known_exploitation': {'selected': True}}
        report = {'targets': {name: {'debian_advisories': 'matched',
                    'applications': {'state': 'observed'},
                    'compiler_cleanup': {'status': 'complete'},
                    'browser': {'state': 'standby'}} for name in ['host', *names]},
                  'public_advisories': {'state': 'matched', 'needs_triage': True},
                  'known_exploitation': {'state': 'matched', 'needs_triage': True}}
        result = daily.phase_observations(config, report)
        self.assertEqual(result['compiler_cleanup']['observed_targets'], sorted(names))
        self.assertEqual(result['browser_metadata']['state'], 'observed')
        self.assertEqual(result['application_inventory']['state'], 'observed')
        self.assertEqual(result['known_exploitation']['applicability'], 'pending')
        self.assertEqual(result['package_transactions']['state'], 'external-producer')
        self.assertEqual(result['incident_delivery_and_missed_runs']['state'], 'external-observer')
        del report['targets']['calipso']
        changed = daily.phase_observations(config, report)
        for key in ('debian_advisories', 'application_inventory', 'compiler_cleanup', 'browser_metadata'):
            self.assertEqual(changed[key]['state'], 'incomplete')
            self.assertEqual(changed[key]['unavailable_targets'], ['calipso'])

    def test_disabled_and_empty_phases_do_not_claim_observed_success(self):
        report = {'targets': {}, 'public_advisories': {'state': 'matched', 'needs_triage': False}}
        result = daily.phase_observations({'targets': []}, report)
        self.assertEqual(result['debian_advisories']['state'], 'incomplete')
        self.assertEqual(result['compiler_cleanup']['state'], 'not-selected')
        self.assertEqual(result['public_advisories']['state'], 'not-selected')
        config = {'targets': [{'id': 'pixin', 'instance': 'dm-pixin'}],
                  'compiler_cleanup_enabled': True, 'public_advisories': {'selected': True}}
        report['public_advisories'] = {'state': 'unavailable', 'last_success_checked': 1}
        result = daily.phase_observations(config, report)
        self.assertEqual(result['compiler_cleanup']['unavailable_targets'], ['pixin'])
        self.assertEqual(result['public_advisories']['applicability'], 'unavailable')


class SelectedMaliciousObservationTests(unittest.TestCase):
    def public_result(self, *, malicious=True, withdrawn=None, alias=False):
        from tools import children_public_advisories as advisory
        package = {'name': 'selected-public-package', 'version': '1.2', 'direct_url_present': False}
        inventory = {'schema': 'children-application-inventory/v1', 'state': 'observed',
                     'environments': {'private-path-never-sent': {'packages': [package]}}}
        identifier = 'GHSA-example' if alias or not malicious else 'MAL-2026-1'
        record = {'id': identifier, 'aliases': ['MAL-2026-1'] if alias else [],
                  'modified': '2026-11-09T00:00:00Z', 'withdrawn': withdrawn,
                  'summary': 'Ordinary text is not a malicious classification',
                  'affected': [{'package': {'ecosystem': 'PyPI', 'name': package['name']},
                                'ranges': [{'type': 'ECOSYSTEM', 'events': [{'introduced': '0'}]}]}]}
        calls = []
        def transport(path, payload=None):
            calls.append((path, payload))
            return {'results': [{'vulns': [{'id': identifier}]}]} if path == 'querybatch' else record
        result = advisory.match([inventory], [package['name']], transport)
        return result, calls

    def test_existing_non_cve_no_fix_report_is_actionable_without_more_queries(self):
        public, calls = self.public_result()
        before = list(calls)
        phase = daily.selected_malicious_observation(public)
        self.assertEqual(calls, before)
        self.assertEqual(phase['state'], 'observed')
        self.assertEqual(phase['active_record_ids'], ['MAL-2026-1'])
        self.assertEqual(phase['applicability'], 'pending')
        self.assertTrue(phase['needs_triage'])
        self.assertEqual(phase['query_sha256'], public['query_sha256'])
        self.assertNotIn('private-path', json.dumps(phase))
        self.assertEqual(public['records'][0]['affected'][0]['fix_events_listed'], [])

    def test_alias_and_withdrawal_remain_attributed_not_remediation(self):
        public, _ = self.public_result(alias=True)
        phase = daily.selected_malicious_observation(public)
        self.assertEqual(phase['active_alias_groups'], [['GHSA-example']])
        public, _ = self.public_result(withdrawn='2026-11-09T01:00:00Z')
        phase = daily.selected_malicious_observation(public)
        self.assertEqual(phase['active_record_ids'], [])
        self.assertEqual(phase['withdrawn_record_ids'], ['MAL-2026-1'])
        self.assertEqual(phase['applicability'], 'no-selected-triage')

    def test_empty_selected_result_is_observation_not_global_clearance(self):
        public, _ = self.public_result(malicious=False)
        phase = daily.selected_malicious_observation(public)
        self.assertFalse(phase['needs_triage'])
        self.assertEqual(phase['scope'], 'selected-public-PyPI-versions')
        self.assertIn('unassessed', phase['meaning'])
        public['records'][0]['summary'] = 'malicious malware MAL-2026-2'
        self.assertEqual(daily.selected_malicious_observation(public), phase)

    def test_unavailable_changed_query_or_incomplete_record_never_clears(self):
        import copy
        public, _ = self.public_result()
        cases = [None, {'state': 'unavailable', 'last_success_checked': public['checked']},
                 {**public, 'public_queries': []}, {**public, 'query_sha256': '0'*64},
                 {**public, 'active_alias_groups': []}, {**public, 'records': [{}]}]
        for invalid in cases:
            with self.subTest(invalid=list(invalid) if isinstance(invalid, dict) else None):
                self.assertEqual(daily.selected_malicious_observation(invalid)['state'], 'incomplete')
        malformed = copy.deepcopy(public)
        malformed['records'][0]['withdrawn'] = 'not-a-timestamp'
        self.assertEqual(daily.selected_malicious_observation(malformed)['state'], 'incomplete')
        duplicate = copy.deepcopy(public)
        duplicate['active_alias_groups'].append(duplicate['active_alias_groups'][0])
        self.assertEqual(daily.selected_malicious_observation(duplicate)['state'], 'incomplete')

    def test_phase_scope_and_execution_health_do_not_hide_missing_assessment(self):
        public, _ = self.public_result()
        phase = daily.phase_observations({'targets': [], 'public_advisories': {'selected': True}},
                                         {'targets': {}, 'public_advisories': public})
        self.assertEqual(phase['selected_public_python_malicious']['state'], 'observed')
        failed = {'source': {'state': 'fresh'}, 'targets': {'pixin': {'debian_advisories': 'matched'}},
                  'phases': {'selected_public_python_malicious': {'state': 'incomplete'}}}
        self.assertFalse(daily.observation_complete(failed))


class SelectedDeploymentPhaseTests(unittest.TestCase):
    def test_selected_network_requires_every_main_process_and_preserves_unknown_exposure(self):
        config={'targets':[{'id':'pixin','instance':'dm-pixin'}], 'application_inventory':{
            'network_listeners':True,'units':{'pixin':['web.service','native.service']}}}
        units={name:{'state':'observed','network_listeners':{'state':'observed','listeners':[]}}
            for name in ('web.service','native.service')}
        report={'targets':{'pixin':{'applications':{'state':'observed','units':units}}}}
        self.assertEqual(daily.phase_observations(config,report)['selected_main_process_listeners']['state'],'observed')
        for gap in (None,{},'unavailable'):
            units['native.service']['network_listeners']=gap
            self.assertEqual(daily.phase_observations(config,report)['selected_main_process_listeners']['state'],'incomplete')
        del config['application_inventory']['network_listeners']
        self.assertEqual(daily.phase_observations(config,report)['selected_main_process_listeners']['state'],'not-selected')
        failed={'source':{'state':'fresh'},'targets':{'pixin':{'debian_advisories':'matched'}},
                'phases':{'selected_main_process_listeners':{'state':'incomplete'}}}
        self.assertFalse(daily.observation_complete(failed))

    def test_selected_files_do_not_claim_unselected_units_or_healthy_changed_process(self):
        config={'targets':[{'id':'pixin','instance':'dm-pixin'}], 'application_inventory':{
            'units':{'pixin':['native.service','web.service','supervisor.service']},
            'deployment_manifests':{'pixin':{'path':'/etc/children-maintenance/deployments.json','sha256':'a'*64}}}}
        units={u:{'state':'observed','deployment':{'state':'verified'}} for u in ('native.service','web.service')}
        app={'state':'observed','deployment_manifest_sha256':'a'*64,
             'deployment_selection_units':['native.service','web.service'],'units':units}
        report={'targets':{'pixin':{'applications':app}}}
        phase=daily.phase_observations(config,report)['selected_deployments']
        self.assertEqual(phase['state'],'observed')
        self.assertEqual(phase['unselected_units'],['pixin:supervisor.service'])
        self.assertIn('unassessed',phase['scope'])
        units['web.service']['state']='unavailable'
        self.assertEqual(daily.phase_observations(config,report)['selected_deployments']['state'],'incomplete')
        units['web.service']['state']='observed'
        app['deployment_manifest_sha256']='b'*64
        self.assertEqual(daily.phase_observations(config,report)['selected_deployments']['state'],'incomplete')

    def test_malformed_or_missing_selection_stays_unavailable_without_losing_other_phases(self):
        config={'targets':[{'id':'pixin','instance':'dm-pixin'}], 'application_inventory':{
            'units':{'pixin':['native.service']}, 'deployment_manifests':{'pixin':{'sha256':'a'*64}}}}
        report={'targets':{'pixin':{'debian_advisories':'matched','applications':{
            'state':'observed','deployment_selection_units':None}}}}
        phase=daily.phase_observations(config,report)
        self.assertEqual(phase['selected_deployments']['state'],'incomplete')
        self.assertEqual(phase['debian_advisories']['state'],'observed')
