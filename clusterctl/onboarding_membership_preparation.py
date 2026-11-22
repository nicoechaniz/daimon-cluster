"""Bounded owner-local public preparation reads for original-job admission.

No native loader, custody reader, store initialization or application/visibility
selection is used. Governance signatures are checked later against the complete
explicit owner closure by the existing membership compiler.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import time

from . import being_seed
from .onboarding import OnboardingError, digest

MAX_GOVERNANCE = 1024 * 1024


def _file(path):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid != os.geteuid() or info.st_mode & 0o077):
        raise OnboardingError('onboarding_group_preparation_unavailable')
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def preview(runtime_root: Path, *, operation_id: str, tribe_ref: str,
            deadline_ns: int | None = None, qualified_startup: dict | None = None) -> dict:
    """Return only own public authority and selected shareable Tribe events.

    A missing canonical relationship store is unavailable, never an empty
    history or a fallback to the possibly lagging published application.
    """
    from daimon_matrix.canonical import canonical_bytes
    from daimon_matrix.messaging_config import _public_identity
    from daimon_matrix.operator_rebirth import AUTHORITY_SCHEMA, authority_from_runtime_bundle
    horizon = time.monotonic_ns() + 3_000_000_000
    if deadline_ns is not None:
        horizon = min(horizon, deadline_ns)

    def budget():
        if time.monotonic_ns() >= horizon:
            raise OnboardingError('onboarding_group_preparation_unavailable')

    try:
        budget()
        bundle_path = runtime_root/'runtime.json'
        before_bundle = _file(bundle_path)
        bundle = being_seed._read(bundle_path, limit=being_seed.MAX_SELECTION)
        authority = authority_from_runtime_bundle(bundle)
        origin = bundle['local_origin']
        public = dict(authority=dict(schema=AUTHORITY_SCHEMA, **{key: bundle[key] for key in
            ('manifest', 'control_artifacts', 'control_head', 'credentials', 'incarnations')}),
            history=bundle['authority_history'])
        _public_identity(authority, origin, bundle['runtime_id'], bundle['runtime_label'],
                         time.time_ns()//1_000_000)
        selected = bundle['relationships']
        filename = selected['store_filename']
        if (not isinstance(filename, str) or Path(filename).name != filename
                or filename in {'', '.', '..'}):
            raise ValueError
        path = runtime_root/filename
        before_store = _file(path)
        budget()
        events, size = [], 0
        # Keep SQLite's normal journal handling. immutable=1 would ignore an
        # active journal and can certify stale data. mode=ro cannot create a DB.
        with closing(sqlite3.connect(path.as_uri()+'?mode=ro', uri=True, timeout=0.5)) as database:
            database.execute('PRAGMA query_only=ON')
            database.set_progress_handler(lambda: int(time.monotonic_ns() >= horizon), 1000)
            database.execute('BEGIN')
            rows = database.execute("""SELECT length(event_json),
                CASE WHEN length(event_json)<=65536 THEN event_json ELSE NULL END
                FROM events WHERE json_extract(event_json,'$.payload.tribe_ref')=?
                AND json_extract(event_json,'$.kind') LIKE 'matrix/tribe-%'
                ORDER BY being_ref,incarnation_id,sequence,content_hash LIMIT 257""", (tribe_ref,))
            for length, raw in rows:
                budget()
                if raw is None or length > 65536 or len(events) >= 256:
                    raise ValueError
                size += length
                if size > MAX_GOVERNANCE:
                    raise ValueError
                event = json.loads(raw)
                # Do not silently omit a non-shareable governance predecessor.
                if (event.get('sensitivity') != 'shareable'
                        or event.get('payload', {}).get('tribe_ref') != tribe_ref
                        or not event.get('kind', '').startswith('matrix/tribe-')):
                    raise ValueError
                events.append(event)
        budget()
        if (_file(bundle_path) != before_bundle or _file(path) != before_store
                or being_seed._read(bundle_path, limit=being_seed.MAX_SELECTION) != bundle):
            raise ValueError
        result = dict(schema='cluster-membership-preparation-preview/v1', operation_id=operation_id,
            tribe_ref=tribe_ref, being_ref=authority.manifest.being_ref, origin=origin, public=public,
            runtime_bundle_sha256=digest(bundle),
            native_runtime_bundle_sha256=hashlib.sha256(canonical_bytes(bundle)).hexdigest(),
            qualified_startup=None if qualified_startup is None else {
                key: qualified_startup[key] for key in ('code_digest', 'matrix_wheel_sha256')},
            governance=events, governance_verified=False, receiving_readiness='unobserved')
        if len(json.dumps(result).encode()) > being_seed.MAX_SELECTION:
            raise ValueError
        budget()
        return result
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error):
        raise OnboardingError('onboarding_group_preparation_unavailable') from None
