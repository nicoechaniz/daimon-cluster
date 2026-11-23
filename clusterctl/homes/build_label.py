"""Small truthful served-UI labels; never identify a publication as backend code."""

import hashlib
import os
import re
from pathlib import Path

ASSETS = Path(__file__).parent / "assets"


def digest(files):
    files = sorted(files, key=lambda p: str(p))
    if not 1 <= len(files) <= 4096:
        raise ValueError("ui_bundle_capacity")
    root = Path(os.path.commonpath([str(p.parent) for p in files]))
    result = hashlib.sha256()
    total = 0
    for path in files:
        if path.is_symlink() or not path.is_file():
            raise ValueError("ui_bundle_file_required")
        total += path.stat().st_size
        if total > 32 * 1024**2:
            raise ValueError("ui_bundle_capacity")
        result.update(path.relative_to(root).as_posix().encode() + b"\0")
        with path.open("rb") as stream:
            while chunk := stream.read(1024**2):
                result.update(chunk)
    result.update((ASSETS / "app-build.css").read_bytes())
    return result.hexdigest()


def stamp(body, revision, *, overlay=False, content_revision=None):
    if not re.fullmatch("[a-f0-9]{64}", revision):
        raise ValueError("invalid_ui_build")
    if content_revision is not None and not re.fullmatch(
        "[a-f0-9]{64}", content_revision
    ):
        raise ValueError("invalid_content_revision")
    if b"data-app-build=" in body:
        return body
    label = "".join("<span>" + digit + "</span>" for digit in revision[:12])
    content = ""
    if content_revision is not None:
        content_label = "".join(
            "<span>" + digit + "</span>" for digit in content_revision[:12]
        )
        content = (
            '<span data-app-content-revision="'
            + content_revision
            + '" title="Revisión publicada '
            + content_revision
            + '" aria-label="Revisión publicada '
            + content_revision[:12]
            + '"> · v <code>'
            + content_label
            + "</code></span>"
        )
    badge = (
        '<p class="app-build' + (" app-build--overlay" if overlay else "") + '" '
        'data-app-build="'
        + revision
        + '" title="Versión de interfaz '
        + revision
        + '" '
        'aria-label="Versión de interfaz '
        + revision[:12]
        + '">ui <code>'
        + label
        + "</code>"
        + content
        + "</p>"
    ).encode()
    version = hashlib.sha256((ASSETS / "app-build.css").read_bytes()).hexdigest()[:16]
    body = body.replace(
        b"</head>",
        (
            '<link rel="stylesheet" href="/app-build.css?v=' + version + '"></head>'
        ).encode(),
        1,
    )
    if not overlay and b"</h1>" in body:
        return body.replace(b"</h1>", b"</h1>" + badge, 1)
    return body.replace(b"</body>", badge + b"</body>", 1)
