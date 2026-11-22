"""Sanitize and aggregate fixed-scope usage metadata, never private thread data."""
import math


def aggregate(rows):
    beings, accounts = {}, {}
    account_unavailable_sources = 0
    for row in rows:
        identity, name = row['being'], row['name']
        being = beings.setdefault(identity, dict(name=name, _threads={}, bodies=0,
            unavailable_bodies=0, partial=False, observed_at_ms=None))
        data = row.get('reading')
        if row.get('state') != 'available' or not isinstance(data, dict):
            account_unavailable_sources += 1
            being['unavailable_bodies'] += 1
            being['partial'] = True
            continue
        if data.get('schema') != 'cluster-native-usage/v1':
            raise ValueError('invalid_usage_schema')
        at = data['observed_at_ms']
        if type(at) is not int or not isinstance(data.get('threads'), list) or len(data['threads']) > 4096:
            raise ValueError('invalid_usage_observation')
        being['bodies'] += 1
        being['observed_at_ms'] = max(being['observed_at_ms'] or 0, at)
        being['partial'] |= data.get('partial') is not False
        for thread, tokens, created, updated in data['threads']:
            if (not isinstance(thread, str) or len(thread) != 64
                    or type(tokens) is not int or not 0 <= tokens <= 2**53-1
                    or type(created) is not int or type(updated) is not int):
                raise ValueError('invalid_usage_counter')
            previous = being['_threads'].get(thread)
            if previous is None or tokens > previous[0]:
                being['_threads'][thread] = (tokens, created, updated)
        account = data.get('account')
        if data.get('account_state') != 'observed' or not isinstance(account, dict):
            account_unavailable_sources += 1
        if data.get('account_state') == 'observed' and isinstance(account, dict):
            key = account.get('key')
            if not isinstance(key, str) or len(key) != 64:
                raise ValueError('invalid_usage_account')
            label = account.get('label')
            if not isinstance(label, str) or len(label) > 160:
                raise ValueError('invalid_usage_account')
            windows = []
            for window in account.get('windows', [])[:16]:
                used, minutes, reset = (window.get(k) for k in ('used_percent', 'window_minutes', 'resets_at'))
                if (type(used) not in (int, float) or not math.isfinite(used) or not 0 <= used <= 100
                        or type(minutes) is not int or minutes <= 0
                        or (reset is not None and type(reset) is not int)):
                    raise ValueError('invalid_usage_window')
                windows.append(dict(limit=str(window.get('limit', 'codex'))[:64],
                    used_percent=used, window_minutes=minutes, resets_at=reset))
            old = accounts.get(key)
            names = set(old['daimons'] if old else []) | {name}
            if old is None or at >= old['observed_at_ms']:
                accounts[key] = dict(label=label, windows=windows, observed_at_ms=at,
                    ordinary_usage_allowed=account.get('ordinary_usage_allowed') if type(account.get('ordinary_usage_allowed')) is bool else None,
                    reset_credits=account.get('reset_credits') if type(account.get('reset_credits')) is int else None,
                    plan=account.get('plan') if account.get('plan') in ('free', 'plus', 'pro', 'team', 'business', 'enterprise', 'edu') else None,
                    daimons=sorted(names))
            else:
                old['daimons'] = sorted(names)
    public = []
    for being in beings.values():
        threads = being.pop('_threads')
        being.update(total_tokens=sum(t[0] for t in threads.values()) if being['bodies'] else None,
            conversations=len(threads), since=min((t[1] for t in threads.values()), default=None),
            last_activity=max((t[2] for t in threads.values()), default=None))
        public.append(being)
    return dict(schema='cluster-usage/v1', daimons=public, accounts=list(accounts.values()),
                account_unavailable_sources=account_unavailable_sources,
                coverage='Recorded native conversation counters; copied thread IDs counted once per being. Voice/API calls outside these counters and unobserved bodies excluded.')
