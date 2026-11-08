# Shared home login

The optional shared login authority reuses the registered Home human identities,
pairings, session state and registered passkeys. These resource-access identities
do not establish native Matrix human membership. Authentication never creates an
artifact grant. A human authenticated in another owner's home remains a visitor;
that home's `human`, `individual`, Tribe and VPN audiences keep their meanings.

Enable the trusted gateway with `--passkey-rp-id DOMAIN --auth-origin ORIGIN`.
The login origin must be a separate HTTPS host within the passkey RP domain,
distinct from home and isolated-content origins. Public wildcard routing already
serves the gateway. Do not give artifact frames access to login cookies or routes.

## Browser journey

A home's Sign in button starts an exact-origin handoff. The login page requests
the existing passkey immediately, then returns to the same path, query and
fragment. If already signed in centrally, the handoff needs no new ceremony.
The initiating home has a host-only HttpOnly proof cookie; the login authority
sends a separate one-use response secret by form POST. Neither a copied public
request ID nor a different browser can redeem the response. Requests expire
after five minutes; responses expire after one minute. The callback accepts
only the configured login Origin and never VPN or bearer identity.

First identification and recovery still belong to the human's own daimon.
Approve the central code through the existing command with
`approve-browser --home dm.home-login/v1 --code CODE`. The authenticating owner
credential identifies only its own currently paired human, irrespective of the
destination home. Existing local-home approval remains compatible.

## Humans without Telegram

The gateway's existing `binding_source` can select an owner-only
`dm.home-identities/v1` declaration instead of a human-Tribu host configuration.
It contains exactly `schema`, `telegram_source` and `web`. `telegram_source` is
the absolute path of the unchanged existing human-Tribu configuration, or `null`
for an exclusively web deployment. The adapter reads no bot tokens. It never
loads a Matrix runtime or changes native admission. Operator-registered web
origins use their own protected signed public authority; they need not first
appear in the founder’s discovery catalog. Existing catalog roots still reject
conflicting authority pins, and Telegram bindings retain their current-source
checks.

`web` contains one to sixteen entries with exactly `being_ref`, `label`,
`human_ref`, `human_name`, `origin`, `authority_file` and boolean `enabled`.
Each `human_ref` is `human:local:` followed by a canonical lowercase UUID,
registered explicitly by the authorized host operator for that person. It is
stable across software updates and independent of email, paid provider login,
Telegram identifiers and another person's Home identity. Reusing an adult
identity for a child would reuse that adult's access and is not registration.
Keep actual pairings and declarations in protected operator storage, not source.

The existing native public-authority validator checks `being_ref` and active
`origin` against the protected absolute `authority_file`. Duplicate beings or
duplicate web human identities are refused. Web entries contain no bot ID,
username, token or invented Telegram account. They project the existing human
Actor and pairing contract; `bot()` returns unavailable for these homes.
Legacy human revisions, bots and sessions retain their original interpretation.
`origin` is the structured native origin object from that being's verified
public identity, including its body, embodiment, incarnation and principal
coordinates. A display label or string is not an origin. Preserve the native
object and let the existing authority validate it rather than translating it.

Use the same Home registration, owner credential, approved-browser and passkey
routes described above. This declaration does not create a browser session,
passkey, application grant, Drive authorization or provider credential. Each
application must select the exact registered human reference and its current
grant. Disabling the entry removes the current actor and pairing; normal current
revision checks refuse its prior authentication. Preserve the declaration UUIDs,
passkeys and original sessions when changing the selected code. Deployment and a
real person's device acceptance are separate from adapter tests.

Home sign-out revokes that home's session. Central sign-out revokes the shared
session and its derived home sessions and private-content tickets. Sessions
created independently before adoption are not descendants and retain their own
logout controls. The signed-out page does not immediately launch another
fingerprint prompt. Credential revocation and current identity revisions still
invalidate sessions. No cross-domain cookie is installed.

## Optional Google identity

Install `requirements-home-login.txt` alongside the existing optional passkey
adapter in the gateway's candidate environment. Configure `--google-client FILE`
with owner-only JSON containing `client_id` and `client_secret`; do not put this
file or OAuth responses in source, issues or logs. Register a Google Web
application redirect URI equal to the login origin plus `/google/callback`.
The [official Google OIDC documentation](https://developers.google.com/identity/openid-connect/openid-connect)
describes the client and consent-screen setup.

An already identified human explicitly chooses to link Google. The verified
Google issuer and stable `sub` identify the external account; email matching is
never used. Only `openid` is requested, without access to Drive, Gmail or other
Google services. State, a browser proof, nonce and PKCE bind the callback.
The official Google ID-token verifier checks signature, issuer, audience and
expiry. An unknown Google account cannot create a Matrix human or gain access.

Unlinking requires a fresh passkey or approved recovery ceremony. It revokes
Google-derived sessions and their descendants while preserving passkey login.
A replacement Google account may be linked after unlinking; the prior mapping
remains recorded and cannot silently transfer to a different human. Link/unlink
history is private operational state, not public home content.

## Adoption and rollback

Services use this existing gateway handoff and identity authority, with exact
registered return origins and their own resource authorization. Homemaker must
authorize its human/pair writes against the resolved identity; login alone does
not authorize design changes. Isolated artifacts can request a trusted parent
sign-in journey but cannot run ceremonies or handle credentials themselves.

The feature is opt-in. Retain the previous release and interpreter during the
reviewed gateway deployment. Rolling back removes shared-login routing while
preserving existing passkeys, publication history, grants and original sessions.
New shared sessions require the successor's parent checks; do not expose them
through a predecessor handler without invalidating those sessions first.
Technical protocol and browser evidence are distinct from human phone acceptance
and a real configured Google exchange.
