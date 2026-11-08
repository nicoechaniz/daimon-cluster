# Public Python-version advisory candidates

The existing daily application inventory remains local. An optional
`public_advisories` selection specifies a qualified root-owned `helper`, exact
`sha256` and explicit `public_names`. It requires the current application stage.
The maintained public name classification is
`support/children-maintenance/public-python-packages.json`, based on the owning
DaimonApp dependency lock/public transport. Never derive upload permission from
an unknown installed package. Names outside that selection, direct/VCS installs,
local/private build labels, filesystem paths, arguments, env and learner content
stay offline. Only ordinary public release-shaped name/version tuples are sent;
identical tuples across the four guests are deduplicated.

The adapter uses the official OSV
[batch API](https://google.github.io/osv.dev/post-v1-querybatch/) and
[record API](https://google.github.io/osv.dev/get-v1-vulns/). Each current run
queries every selected current version again, so new software and modified
records are reconsidered. Follow only pending per-query page tokens; refuse
repeated/unbounded pagination. Fetch full identified records, bind them to the
requested package, retain modified/withdrawn metadata, canonical source hash,
aliases, summary, matching package and listed fix events. Alias groups avoid
counting CVE/GHSA duplicates; withdrawn records remain recorded but inactive.
No-fix and non-CVE/MAL records are retained, not filtered away.

This is candidate evidence from OSV, not a diagnosis, upstream wheel authenticity,
loaded/imported code or proof of exposure. A successful empty response means no
listed matches for those tuples at the query time; it is not a clean-system
certificate or proof that the database covers every advisory. Non-Python,
unselected/private software, dynamic paths/descendants and other vendor/malicious
sources remain partial. Applicable candidates require their primary vendor/source
and actual receiving exposure/mitigation assessment before a fix claim.

## Bounds, state and failure

Maximum64queries,32identified records,4pagination rounds,40requests,4MiB/batch,
1MiB/detail and32MiB total responses. Requests use fixed HTTPS OSV routes, TLS
verification, no redirects/proxy/authentication cookie,10-second socket reads
and a120-second soft deadline checked between streamed reads. The existing
900-second finite collector is the hard outer bound; package writers are separate.
Compact accepted evidence is capped128KiB. Keep only matched current/previous
receipts and a compact latest status under the existing private daily state/cap.
A source/shape/capacity failure does not overwrite the last matched evidence;
report its checked/query digest separately from current unavailable coverage.
Do not evict pending evidence or turn a failed/capped source into zero findings.

Untriaged active candidates keep the occurrence pending/nonzero for the existing
scheduled-job observer, while the report distinguishes a matched query from an
unavailable source. No automatic package installation, service restart, extra
scheduler, grant, credential or model wake is part of this adapter. Remove only
`public_advisories` to stop its network reads; other phases and retained evidence
remain. Keep the original broad-security coverage incident open until its full
receiving requirements are actually met.
