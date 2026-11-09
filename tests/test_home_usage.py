import importlib.util
from pathlib import Path
import sqlite3

from clusterctl.homes.usage import aggregate


def row(being, name, threads, at=100):
    return dict(being=being, name=name, state='available', reading=dict(
        schema='cluster-native-usage/v1', observed_at_ms=at, partial=False,
        threads=threads, account_state='observed', account=dict(key='a'*64,
        label='Account', windows=[dict(limit='codex', used_percent=72,
        window_minutes=10080, resets_at=300)], plan='pro')))


def test_deduplicates_copied_threads_without_merging_distinct_beings():
    rows = [row('one', 'One', [['1'*64, 10, 1, 4]]),
            row('one', 'One', [['1'*64, 20, 1, 5], ['2'*64, 5, 2, 5]]),
            row('two', 'Two', [['1'*64, 8, 1, 4]], at=110)]
    value = aggregate(rows)
    assert [r['total_tokens'] for r in value['daimons']] == [25, 8]
    assert value['daimons'][0]['conversations'] == 2
    assert len(value['accounts']) == 1
    assert value['accounts'][0]['daimons'] == ['One', 'Two']
    assert value['accounts'][0]['windows'][0]['window_minutes'] == 10080
    assert '1'*64 not in str(value) and 'a'*64 not in str(value)


def test_unavailable_is_not_zero_and_missing_body_preserves_partial_total():
    value = aggregate([dict(being='one', name='One', state='unavailable'),
                       row('two', 'Two', [['1'*64, 8, 1, 4]]),
                       dict(being='two', name='Two', state='unavailable')])
    one, two = value['daimons']
    assert one['total_tokens'] is None and one['partial']
    assert two['total_tokens'] == 8 and two['partial']


def test_probe_reads_only_counter_metadata_in_readonly_database(tmp_path):
    path = Path(__file__).parents[1] / 'clusterctl/homes/usage_probe.py'
    spec = importlib.util.spec_from_file_location('probe', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    db = tmp_path/'state.sqlite'
    c = sqlite3.connect(db)
    c.execute('CREATE TABLE threads(id TEXT,tokens_used INTEGER,created_at INTEGER,updated_at INTEGER,title TEXT)')
    c.execute('INSERT INTO threads VALUES(?,?,?,?,?)', ('one', 44, 1, 9, 'PRIVATE PROMPT'))
    c.commit()
    c.close()
    before = db.read_bytes()
    value = module.probe_usage(dict(database=str(db), codex_home=str(tmp_path), binary='/unused'), native_factory=None)
    assert value['threads'][0][1:] == [44, 1, 9]
    assert 'PRIVATE' not in str(value) and db.read_bytes() == before
    assert value['account_state'] == 'unavailable'


def test_weekly_primary_native_response_and_no_credentials_in_output(tmp_path):
    import json
    import socket
    path = Path(__file__).parents[1] / 'clusterctl/homes/usage_probe.py'
    spec = importlib.util.spec_from_file_location('probe', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    db = tmp_path/'state.sqlite'
    c = sqlite3.connect(db)
    c.execute('CREATE TABLE threads(id TEXT,tokens_used INTEGER,created_at INTEGER,updated_at INTEGER)')
    c.close()
    (tmp_path/'app-server-control').mkdir()
    sock = socket.socket(socket.AF_UNIX)
    sock.bind(str(tmp_path/'app-server-control/app-server-control.sock'))
    class Native:
        def __init__(self, binary):
            assert binary == '/test'
        def rpc(self, method, params):
            assert method == 'account/rateLimits/read' and params is None
            return dict(accountId='PRIVATE-ID', rateLimitsByLimitId={'codex':dict(primary=dict(
                usedPercent=91, windowDurationMins=10080, resetsAt=300))})
        def close(self):
            pass
    try:
        # Missing auth metadata must not discard the genuine live windows.
        data = module.probe_usage(dict(database=str(db), codex_home=str(tmp_path), binary='/test'), native_factory=Native)
        value = aggregate([dict(being='one', name='One', state='available', reading=data)])
        assert value['accounts'][0]['windows'][0]['window_minutes'] == 10080
        assert 'PRIVATE-ID' not in json.dumps(value)
    finally:
        sock.close()
