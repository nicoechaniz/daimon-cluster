"""Bounded annotated PNGs, always authorized against their current source resource."""
import base64
from contextlib import closing
import hashlib
import html
import json
import re
import struct
import uuid

MAX_IMAGE = 3 * 1024 * 1024
MAX_RECORDS = 128
MAX_TOTAL = 128 * 1024 * 1024


class ReviewNotes:
    def __init__(self, sessions):
        self.sessions = sessions
        with closing(sessions.connect()) as db:
            db.execute('''CREATE TABLE IF NOT EXISTS review_notes(
                id TEXT PRIMARY KEY, home TEXT NOT NULL, author TEXT NOT NULL,
                operation TEXT NOT NULL, digest TEXT NOT NULL, metadata TEXT NOT NULL,
                image BLOB NOT NULL, UNIQUE(home,author,operation))''')

    def save(self, home, author, payload):
        if not isinstance(payload, dict) or set(payload) != {'operation', 'snapshot', 'image'}:
            raise ValueError('invalid_review_note')
        if not re.fullmatch('[a-f0-9]{32}', str(payload['operation'])):
            raise ValueError('invalid_review_note_operation')
        state = payload['snapshot']
        metadata = json.dumps(state, allow_nan=False, sort_keys=True, separators=(',', ':'))
        if len(metadata.encode()) > 65536 or not isinstance(state, dict) or state.get('schema') != 'dm.review-3d-state/v1':
            raise ValueError('invalid_review_snapshot')
        model = state.get('model', {})
        if not isinstance(model, dict) or not isinstance(model.get('resource'), str) or not re.fullmatch('[a-f0-9]{32}', model['resource']) or not isinstance(model.get('publicationVersion'), str) or not re.fullmatch('[a-f0-9]{64}', model['publicationVersion']):
            raise ValueError('invalid_review_source')
        value = payload['image']
        if not isinstance(value, str) or not value.startswith('data:image/png;base64,') or len(value) > MAX_IMAGE * 4 // 3 + 64:
            raise ValueError('invalid_review_image')
        try:
            image = base64.b64decode(value.split(',', 1)[1], validate=True)
        except (ValueError, TypeError) as error:
            raise ValueError('invalid_review_image') from error
        if len(image) > MAX_IMAGE or len(image) < 45 or image[:16] != b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR' or image[-12:] != b'\x00\x00\x00\x00IEND\xaeB`\x82':
            raise ValueError('invalid_review_image')
        width, height = struct.unpack('>II', image[16:24])
        if not width or not height or width * height > 2_000_000:
            raise ValueError('review_image_dimensions_exceeded')
        digest = hashlib.sha256(metadata.encode() + b'\0' + image).hexdigest()
        with closing(self.sessions.connect()) as db:
            db.execute('BEGIN IMMEDIATE')
            previous = db.execute('SELECT id,digest FROM review_notes WHERE home=? AND author=? AND operation=?', (home, author, payload['operation'])).fetchone()
            if previous:
                if previous['digest'] != digest:
                    raise ValueError('review_note_operation_conflict')
                return previous['id']
            count, size = db.execute('SELECT count(*),coalesce(sum(length(image)+length(metadata)),0) FROM review_notes WHERE home=?', (home,)).fetchone()
            if count >= MAX_RECORDS or size + len(image) + len(metadata.encode()) > MAX_TOTAL:
                raise ValueError('review_note_storage_full')
            identifier = uuid.uuid4().hex
            db.execute('INSERT INTO review_notes VALUES(?,?,?,?,?,?,?)', (identifier, home, author, payload['operation'], digest, metadata, image))
            db.commit()
            return identifier

    def get(self, home, identifier):
        with closing(self.sessions.connect()) as db:
            row = db.execute('SELECT * FROM review_notes WHERE id=? AND home=?', (identifier, home)).fetchone()
        if not row:
            raise ValueError('review_note_unavailable')
        return dict(row) | {'snapshot': json.loads(row['metadata'])}

    def delete(self, home, identifier, author):
        with closing(self.sessions.connect()) as db:
            cursor = db.execute('DELETE FROM review_notes WHERE id=? AND home=? AND author=?', (identifier, home, author))
            if cursor.rowcount != 1:
                raise ValueError('review_note_delete_denied')
            db.commit()


def routes(request, app, method, data=None):
    path = request.path.split('?', 1)[0]
    match = re.fullmatch('/review-notes/([a-f0-9]{32})(?:/(image.png|metadata.json|delete))?', path)
    if path != '/review-notes' and not match:
        return False
    home, origin, subject, vpn, _, _ = request.context()
    if not subject:
        if method == 'GET' and match and not match[2] and app.sso:
            from urllib.parse import quote
            request.respond(303, b'', headers=(('Location', '/access/sso/start?return=' + quote(path, safe='')),))
            return True
        raise ValueError('review_note_sign_in_required')
    store = ReviewNotes(app.sessions)
    if method == 'POST' and request.headers.get('Origin') != origin:
        raise ValueError('review_note_origin_denied')
    if method == 'POST' and path == '/review-notes':
        payload = json.loads(data)
        state = payload.get('snapshot') if isinstance(payload, dict) else None
        model = state.get('model') if isinstance(state, dict) else None
        if not isinstance(model, dict) or not isinstance(model.get('resource'), str) or not isinstance(model.get('publicationVersion'), str):
            raise ValueError('invalid_review_source')
        selected = app.selected(home, model.get('resource'), model.get('publicationVersion'), subject, vpn)
        if (not selected or selected.get('kind') != 'artifact'
                or not {'review-live.json', 'gallery.json'}.issubset(selected.get('files', []))
                or not selected.get('entrypoint', '').endswith('.html')):
            raise ValueError('review_note_source_denied')
        identifier = store.save(home, subject.ref, payload)
        request.respond(200, {'url': origin + '/review-notes/' + identifier})
        return True
    if not match:
        raise ValueError('review_note_unavailable')
    identifier, part = match.groups()
    row = store.get(home, identifier)
    model = row['snapshot']['model']
    if method == 'POST' and part == 'delete':
        # The author can erase a note even after losing access to its model.
        store.delete(home, identifier, subject.ref)
        request.respond(303, b'', headers=(('Location', '/'),))
        return True
    if not app.selected(home, model['resource'], model['publicationVersion'], subject, vpn):
        raise ValueError('review_note_source_denied')
    if method != 'GET':
        raise ValueError('review_note_operation_denied')
    elif part == 'image.png':
        request.respond(200, row['image'], 'image/png')
    elif part == 'metadata.json':
        request.respond(200, {'schema': 'dm.review-note/v1', 'snapshot': row['snapshot'], 'image': path.replace('metadata.json', 'image.png'), 'provenance': 'Human-provided annotated viewport; source access checked, pixels not independently attested.'})
    elif part is None:
        esc = html.escape
        delete = f'<form method="post" action="{path}/delete"><button>Delete this note</button></form>' if row['author'] == subject.ref else ''
        page = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Annotated model view</title><link rel="stylesheet" href="/home.css"><script src="/home-style.js" defer></script></head><body><main><h1>Annotated model view</h1><p>Shared with the current readers of this model. The link grants no access.</p><img src="{path}/image.png" alt="Annotated frozen model viewport" width="100%"><p>Scene: {esc(str(model.get('id', '')))}</p><p><a href="{path}/image.png">Open image</a> · <a href="{path}/metadata.json">Model and camera reference</a></p>{delete}</main></body></html>'''
        request.respond(200, page.encode(), 'text/html; charset=utf-8')
    else:
        raise ValueError('review_note_unavailable')
    return True
