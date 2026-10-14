# Selected home root

An owning home may select an accepted immutable artifact version as its landing
and journal surface. Artifact publication and root selection remain separate
operations. This component stores a delivery pointer and route map, not another
Homemaker catalog, recipe/default registry, owner identity or grant.

## Owning contract

The existing receiving owner gate verifies the home's current enabled being,
owner revision and bound credential before dispatching either operation:

- `home-root-status`, with an empty object, reads the current root revision and
  selection.
- `home-root-select` accepts exactly `expected_revision`, `resource`, `version`
  and `routes`. Resource and version name an accepted artifact owned by this
  home, with `index.html` as its entrypoint. Clearing uses null resource/version
  and an empty route map, with the current expected revision.

Replies use `dm.home.root/v1`: home, monotonically increasing revision, selected
resource/version/routes, and status `selected`, `cleared` or `unchanged`. SQLite
CAS updates and owner-attributed history preserve interrupted exact retries.
An identical current selection is unchanged even after a lost response; a
different selection with a stale revision raises a conflict.

The SDK/client adoption call still requires owning integration and a selected
operation. No artifact upload, design import, Telegram ID or URL invokes this
operation automatically. This source contribution performs no live selection.

## Reader and navigation boundaries

Every root/journal request passes the existing resource selector. Both the
current resource audience and the selected historical version's audience apply,
and the serving manifest must match the accepted shared projection. Anonymous
requests cannot disclose a private selected title. The normal catalog remains
available at `/home`; `/` falls back to it when there is no readable selection.

Default routes are `/`, `/index.html` and bounded canonical journal entry paths.
Explicit migration aliases accept `/blog`, `/blog/`, `/blog/<slug>.html` and
bounded journal/blog entry paths only, targeting published HTML files. They
cannot override canonical routes or occupy owner, authentication or work APIs.
This preserves selected paths within the new dmn.homes destination; it does not
redirect an old GitHub hostname or continue Pages publishing.

The receiving viewer retains its opaque `sandbox="allow-scripts"` and existing
content CSP. The parent accepts navigation only from its bound null-origin child
and only to a path in the selected route map, with a bounded fragment. Authored
Homemaker production navigation uses this optional bridge; standalone output
keeps ordinary links. Canonical journal paths take priority over old aliases.
External HTTPS links appear in a visible parent panel requiring a fresh click;
child scripts cannot open them automatically or call owner APIs. Existing media
download and fragment handling remain separate bounded capabilities.

The root toolbar keeps sign-in/out and catalog access, with readable text and
44px controls. Production content remains inside its own selected world.

## Qualification

Twenty-four focused local root/gateway/access/navigation cases pass against
synthetic owners, readers and disposable stores. They cover CAS/history/clear,
wrong owner, private/current/historical audiences, unaccepted manifests, bounded
aliases, actual root HTTP and opaque sandbox retention, fragment containment and
external-link click requirements. No production host is used.

`tools/qualify_home_root_browser.py --source <selected-Homemaker-source> --out
<scratch-output>` qualifies two fictional worlds through an actual loopback HTTPS
gateway with synthetic authenticated cookies. It checks desktop/narrow widths,
outer journal URLs, return fragments, legacy aliases, images/fonts and audio/video
playback, and writes screenshots/receipt. Homemaker CI
[38526557653](https://github.com/AnnieScigliano/homemaker/actions/runs/38526557653)
passed all six cases against root source61745c7 and Homemaker998d28d. Receipts and
two narrow screenshots were inspected; full source/scope evidence lives in
Homemaker docs/ROOT-NAVIGATION-VALIDATION.json. Broad local home/CI tests also
pass130 cases with one optional case skipped; two PATH-only Node failures passed
after correcting the selected executable environment. The upstream fork workflow
still requires maintainer approval. The owning SDK/CLI, real publication and
root selection, physical devices and existing-site migration remain separate
integration work.
