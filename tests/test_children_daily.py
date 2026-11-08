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
