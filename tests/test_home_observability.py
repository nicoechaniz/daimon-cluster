import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from clusterctl.homes.observability import observations


def test_private_snapshot_and_unknown_are_distinct(tmp_path):
    path = tmp_path / 'health.json'
    path.write_text(json.dumps({'schema': 'computer-health/v1', 'targets': [
        dict(id='host', label='Host', scope='OS', state='available', attempted_at='now',
             private_key='NEVER', reading=dict(observed_at='now', scope='OS', sample_seconds=1,
             credential='NEVER', memory=dict(kind='host', total_bytes=100, available_bytes=40,
             credential='NEVER'), disks=[], services=[]))]}))
    path.chmod(0o600)
    result = observations({'health_file': str(path)})
    assert result['health_state'] == 'observed'
    assert 'NEVER' not in str(result)
    path.chmod(0o644)
    assert observations({'health_file': str(path)})['health_state'] == 'unavailable'
    assert observations({})['health_state'] == 'unconfigured'
    path.unlink(); path.symlink_to('/dev/zero')
    assert observations({'health_file': str(path)})['health_state'] == 'unavailable'


def test_live_alert_read_is_scoped_bounded_and_never_writes(tmp_path):
    calls = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            calls.append((self.command, self.path, self.headers['Authorization']))
            body = dict(items=[dict(projection=dict(producer_id='producer',incident_id='incident',
                resource_ref='host-test', severity='critical', summary='Disk full', action='Inspect',
                processing_state='open', updated_at=1, secret='NEVER'), freshness='stale',
                acknowledgments=[], deliveries=[{'private': 'NEVER'}])], next_cursor='100')
            self.send_response(200); self.end_headers(); self.wfile.write(json.dumps(body).encode())
    server = HTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    token = tmp_path / 'token'; token.write_text('fixture-token'); token.chmod(0o600)
    config = {'alerts': dict(base_url=f'http://127.0.0.1:{server.server_port}', token_file=str(token))}
    try:
        result = observations(config)
        assert result['alerts_state'] == 'observed' and result['alerts_partial']
        assert result['alerts'][0]['acknowledged'] is False
        assert 'NEVER' not in str(result) and 'fixture-token' not in str(result)
        assert len(calls) == 1 and calls[0][0] == 'GET'
        config['alerts']['base_url'] = 'https://untrusted.example'
        assert observations(config)['alerts_state'] == 'unavailable'
        assert len(calls) == 1
    finally:
        server.shutdown(); server.server_close(); thread.join()
