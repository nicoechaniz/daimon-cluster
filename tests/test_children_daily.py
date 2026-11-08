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


if __name__ == '__main__':
    unittest.main()
