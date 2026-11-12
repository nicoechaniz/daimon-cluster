"""Fixed-scope native metadata probe; injected beside the maintained Native reader.

Never reads prompts, turns, media or goals. Account windows are provider-reported
metadata; tokens_used is the native state's accumulated total_token_usage value.
"""
import base64
import hashlib
import json
import os
import queue
from pathlib import Path
import sqlite3
import stat
import time


def probe_usage(spec, *, native_factory):
    home = Path(spec['codex_home'])
    db = Path(spec['database'])
    if db.is_symlink() or not db.is_file():
        raise ValueError('usage_database_unavailable')
    connection = sqlite3.connect(db.as_uri() + '?mode=ro', uri=True, timeout=1)
    try:
        connection.execute('PRAGMA query_only=ON')
        connection.set_progress_handler(lambda: time.monotonic() > deadline, 1000)
        deadline = time.monotonic() + 2
        rows = connection.execute(
            'SELECT id,tokens_used,created_at,updated_at FROM threads ORDER BY id LIMIT 4097'
        ).fetchall()
    finally:
        connection.close()
    partial = len(rows) > 4096
    clean = []
    for thread, tokens, created, updated in rows[:4096]:
        if type(tokens) is not int or tokens < 0:
            partial = True
            continue
        clean.append([hashlib.sha256(thread.encode()).hexdigest(), tokens, created, updated])
    result = dict(schema='cluster-native-usage/v1', observed_at_ms=int(time.time()*1000),
                  threads=clean, partial=partial, account_state='unavailable')
    # Attach only to an existing daemon. No startup, turn or account switching.
    sock = home / 'app-server-control/app-server-control.sock'
    if not sock.exists() or not stat.S_ISSOCK(sock.stat().st_mode):
        return result
    os.environ['CODEX_HOME'] = str(home)
    native = None
    try:
        native = native_factory(spec['binary'])  # Existing bounded read-only transport.
        response = native.rpc('account/rateLimits/read', None)
        account_id = response.get('accountId') if isinstance(response, dict) else None
        if not isinstance(account_id, str) or not account_id:
            return result
        label = 'Codex account'
        # Metadata stays inside the host; no credential/token bytes leave it.
        auth_path = home / 'auth.json'
        try:
            if auth_path.stat().st_size <= 65536:
                auth = json.loads(auth_path.read_bytes())
                tokens = auth.get('tokens') or {}
                if tokens.get('account_id') == account_id:
                    token = tokens.get('id_token', '').split('.')
                    if len(token) == 3:
                        claims = json.loads(base64.urlsafe_b64decode(token[1] + '='*(-len(token[1]) % 4)))
                        email = claims.get('email')
                        if isinstance(email, str) and 0 < len(email) <= 160:
                            label = email
        except (OSError, ValueError, KeyError, TypeError):
            pass
        limits = response.get('rateLimitsByLimitId')
        if not isinstance(limits, dict):
            limits = {'codex': response.get('rateLimits')}
        windows = []
        for key, limit in list(limits.items())[:8]:
            if not isinstance(limit, dict):
                continue
            for field in ('primary', 'secondary'):
                window = limit.get(field)
                if not isinstance(window, dict):
                    continue
                used, minutes, reset = (window.get(k) for k in ('usedPercent', 'windowDurationMins', 'resetsAt'))
                if (type(used) in (int, float) and 0 <= used <= 100
                        and type(minutes) is int and minutes > 0
                        and (reset is None or type(reset) is int)):
                    windows.append(dict(limit=str(key)[:64], used_percent=used,
                                        window_minutes=minutes, resets_at=reset))
        result.update(account_state='observed', account=dict(
            key=hashlib.sha256(account_id.encode()).hexdigest(), label=label,
            plan=(response.get('rateLimits') or {}).get('planType'), windows=windows,
            ordinary_usage_allowed=response.get('ordinaryUsageAllowed'),
            reset_credits=(response.get('rateLimitResetCredits') or {}).get('availableCount')))
    except (OSError, ValueError, KeyError, TypeError, TimeoutError, EOFError, queue.Empty):
        pass
    finally:
        if native is not None:
            native.close()
    return result
