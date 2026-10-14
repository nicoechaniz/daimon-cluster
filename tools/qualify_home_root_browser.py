"""Actual HTTPS receiving root + fictional Homemaker bundles, no live grant."""

from pathlib import Path
from email.message import Message
from urllib.response import addinfourl
import argparse
import hashlib
import io
import json
import mimetypes
import os
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.qualify_home_login_browser import gateway  # noqa: E402
from tests.test_home_passkeys import approved  # noqa: E402
from tests.test_home_gateway import selected  # noqa: E402
from clusterctl.homes.registry import version_digest  # noqa: E402
from playwright.sync_api import sync_playwright  # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    source = Path(args.source).resolve()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    checks = []
    with tempfile.TemporaryDirectory(prefix="home-root-browser-") as scratch:
        folder = Path(scratch)
        bundles = {}
        for world in ("paper", "tricorder"):
            destination = folder / world
            subprocess.run(
                [
                    os.environ.get("HOMEMAKER_NODE", "node"),
                    str(source / "scripts/render-home.mjs"),
                    str(source / "examples/shared-home/content.json"),
                    str(source / f"examples/shared-home/{world}.design.json"),
                    str(destination),
                ],
                check=True,
            )
            bundles[world] = destination
        with gateway(folder) as app, sync_playwright() as pw:
            origin = app.homes["one"]["public_url"]
            port = origin.rsplit(":", 1)[1]
            app.config.update(
                content_public_url=f"https://content.example.test:{port}",
                content_vpn_url=f"https://private-content.example.test:{port}",
            )
            state = {"schema": 1, "entries": []}
            current = {"directory": bundles["paper"]}

            class Bytes:
                def state(self):
                    return state

                def open(self, path, **kwargs):
                    parts = path.split("/")
                    name = "/".join(parts[5:])
                    version = parts[4]
                    directory = next(
                        d
                        for d in bundles.values()
                        if (d / "render-receipt.json").is_file()
                        and version == current["versions"].get(d.name)
                    )
                    data = (directory / name).read_bytes()
                    headers = Message()
                    headers["Content-Type"] = (
                        mimetypes.guess_type(name)[0] or "application/octet-stream"
                    )
                    headers["Content-Length"] = str(len(data))
                    headers["X-Home-Version"] = version
                    return addinfourl(io.BytesIO(data), headers, path, 200)

            app.backends["one"] = Bytes()
            current["versions"] = {}
            previous = []

            def choose(world):
                directory = bundles[world]
                files = [
                    f.relative_to(directory).as_posix()
                    for f in directory.rglob("*")
                    if f.is_file()
                ]
                entry = selected(
                    "a" * 32,
                    "human",
                    title="Casa del horizonte",
                    files=files,
                    revision=hashlib.sha256(world.encode()).hexdigest(),
                    versions=previous[:],
                    owner="owner",
                )
                entry["version_ref"] = version_digest(entry)
                current["versions"][world] = entry["version_ref"]
                state["entries"] = [entry]
                app.registry.register(
                    home="one",
                    owner="owner",
                    state=state,
                    expected_revision=app.registry.revision("one"),
                    known_actor=app.authority.actor,
                    known_tribe=lambda _: True,
                )
                app.roots.select(
                    "one",
                    app.authority.actor("owner"),
                    {
                        "expected_revision": app.roots.read("one")["revision"],
                        "resource": entry["artifact_ref"],
                        "version": entry["version_ref"],
                        "routes": {
                            "/blog/old-day.html": "journal/primer-horizonte/index.html",
                            "/blog/": "index.html",
                            "/blog/index.html": "index.html",
                        },
                    },
                )
                previous.append(entry)

            choose("paper")
            token, _ = approved(app)
            options = {
                "headless": True,
                "args": [
                    "--no-proxy-server",
                    "--host-resolver-rules=MAP *.example.test 127.0.0.1",
                ],
            }
            if os.environ.get("HOMEMAKER_CHROMIUM_PATH"):
                options["executable_path"] = os.environ["HOMEMAKER_CHROMIUM_PATH"]
            browser = pw.chromium.launch(**options)
            for width in (1440, 390, 320):
                context = browser.new_context(
                    ignore_https_errors=True, viewport={"width": width, "height": 900}
                )
                context.add_cookies(
                    [
                        {
                            "name": "__Host-home",
                            "value": token,
                            "url": origin,
                            "httpOnly": True,
                            "secure": True,
                            "sameSite": "Lax",
                        }
                    ]
                )
                for world in ("paper", "tricorder"):
                    choose(world)
                    page = context.new_page()
                    errors = []
                    page.on("pageerror", lambda e: errors.append(str(e)))
                    page.goto(origin + "/")
                    frame = page.frame_locator("iframe")
                    frame.locator(".production-page").wait_for()
                    frame.locator("body").evaluate(
                        """async()=>{await document.fonts.ready;document.querySelectorAll('img').forEach(i=>i.loading='eager');await Promise.all([...document.images].map(i=>i.decode()));}"""
                    )
                    assert page.locator("body").evaluate(
                        "()=>document.documentElement.scrollWidth<=innerWidth+1"
                    )
                    assert frame.locator("body").evaluate(
                        "()=>document.documentElement.scrollWidth<=innerWidth+1"
                    )
                    frame.locator(".journal-index a").first.click()
                    page.wait_for_url("**/journal/primer-horizonte/index.html")
                    assert (
                        page.frame_locator("iframe").locator("h1").text_content()
                        == "El primer horizonte"
                    )
                    for kind in ("audio", "video"):
                        media = page.frame_locator("iframe").locator(kind)
                        result = media.evaluate(
                            """async m=>{m.muted=true;await m.play();await new Promise(r=>setTimeout(r,300));const t=m.currentTime;m.pause();return t;}"""
                        )
                        assert result > 0
                    page.frame_locator("iframe").locator(
                        'a[href="../../index.html#journal"]'
                    ).last.click()
                    page.wait_for_url(origin + "/#journal")
                    assert (
                        page.frame_locator("iframe").locator(".journal-index a").count()
                        == 2
                    )
                    page.goto(origin + "/blog/old-day.html")
                    assert (
                        page.frame_locator("iframe").locator("h1").text_content()
                        == "El primer horizonte"
                    )
                    page.screenshot(
                        path=str(out / f"{world}-{width}.png"), full_page=True
                    )
                    assert not errors, errors
                    checks.append(
                        {
                            "world": world,
                            "width": width,
                            "stableJournalURL": True,
                            "legacyAlias": True,
                            "mediaPlayback": True,
                            "authenticatedFixture": True,
                        }
                    )
                    page.close()
                context.close()
            browser.close()
    (out / "receipt.json").write_text(
        json.dumps(
            {
                "checks": checks,
                "livePublication": False,
                "physicalPhoneAcceptance": False,
            },
            indent=2,
        )
        + "\n"
    )
    print(json.dumps({"homeRootBrowser": "passed", "checks": len(checks)}))


if __name__ == "__main__":
    main()
