# Durable receiving jobs

The complete onboarding task is tracked with cohort #32 and Matrix #263.
The intake and the receiving worker are separate processes. An uploaded archive
or a successful preparation never means that the hosted embodiment is active.

## Current implementation boundary

`clusterctl.onboarding` records an exact host-authorized plan and eight ordered
steps: environment, context, memory, Matrix, access, Telegram, welcome and
acceptance. Web progress reads the same job's closed projection through
`GET /v1/seeds/{seed}/onboarding`; it does not execute host operations.

Before installing Source inheritance, the worker publishes an owner-private
review of the exact plan and qualified inheritance text. The same portal and
agent API expose `GET /v1/seeds/{seed}/onboarding/review`; POST records the
human/daimon pair's acknowledgement and whether to continue an existing signed
Matrix identity or prepare its first one. `clusterctl seed review` and
`clusterctl seed consent` call the same functions. The original SOUL remains
unchanged. An existing identity choice requires native continuity evidence;
it never authorizes another root. Custody creation is still a separate native
authority operation, not an effect of submitting this decision.

The decision binds the plan and Source text digest. An identical retry is
idempotent; a contradictory decision is refused. A changed proposal cannot
reuse an older acknowledgement. The worker reads participant-owned decisions
across an explicitly configured numeric UID boundary and checks the current
root-owned grant separately. It resumes on its next tick after a decision,
including after a service restart. Intake cannot publish proposals, manufacture
receipts or issue host grants. Missing or malformed decisions never complete a
stage. The acknowledgement is an authenticated owner statement, not a claim
of a separate human cryptographic signature.

The current typed host adapter reconciles Incus environment preparation: exact
image fingerprint, isolated instance, 8 GiB root and 22 GiB durable home.
It refuses a foreign instance, home volume or attachment. Context and memory
use the same engine's typed receiving adapter. Incus mounts exact qualified
code and a private per-body frozen input view read-only with ID shifting. The
installer preserves the complete receiving index, original SOUL, historical
skills and each working HMK store. It copies only explicitly selected shared
skills, installs attributed Source context separately from autobiography, and
renders manual native HMK access with no inherited dotenv or Source binding.

Each HMK store gets a verified SQLite snapshot before a supported native
upgrade. Native stats and two chapter expansions verify the actual binding;
all original table rows/columns must survive, including vectors, links and
query history. Derived FTS indexes and native access counters have specific
exceptions. No bootstrap or re-embedding runs. A later receiving write is not
replaced by a retry. Interrupted snapshot publication reconciles its known
hard link; an unpublished snapshot is never mistaken for a complete backup.

Matrix, access, Telegram and acceptance adapters are still being integrated
and currently return explicit waiting states. This is a foundation for complete onboarding, not a deployed end-to-end
activation claim. Real cohort activation and human acceptance remain pending.

## Execution and recovery

A plan binds owner, environment name, receiving input digest, qualified release,
account profile and browser selection. The seed digest covers a frozen input
manifest and every prepared file, including preserved originals, selected
working memory and historical skills. It is not just the archive checksum.
Capture checks ownership, links and source drift; failed captures remain
preserved without a readiness marker. The maintained archive verifier runs
before publication. Source files and the original intake stay unchanged.

Only a host-owned grant for the exact plan permits dispatch. Participant intake
credentials and name labels cannot create or widen that grant. Every unfinished
step rechecks current authorization. The Incus adapter rechecks before each
resource mutation, including after an earlier long operation returns.

Before dispatch, the worker persists its stable operation ID and intent.
After a restart it observes the actual effect before deciding whether another
dispatch is safe. An uncertain outgoing welcome is never replayed merely
because its receipt is missing. A completed command is not a completed step.
Typed observations must establish the stage's required effects. Complete
acceptance requires actual SSH, provider, identity, Matrix delivery, Telegram,
human steering, distinct topics, restart and CLI resume evidence, plus browser
acceptance when selected. A bare `verified: true` cannot substitute for them.

Per-job filesystem locks protect independent being jobs. The service worker
uses bounded concurrent slots and fair scheduling, so a waiting or slow job
does not starve another. It does not capture process-global HTTP stdout and
does not need an active Codex conversation. Its work is finite authorized
onboarding; it adds no Matrix inbox polling, peer reply or model wakeup service.

## Host and HTTP ownership

Job and grant directories belong to the worker principal with mode 0700.
The progress directory belongs to that principal with mode 0750; published
files are mode 0640, readable by the portal group and writable only by the
worker. These directories must be outside the intake's writable state.

The HTTP service receives only `--onboarding-progress`. It validates the
worker's numeric UID, private seed ownership, projection ownership/mode, exact
closed schema and ordered completion prefix. Extra fields, corrupt records or
an owner mismatch cannot produce a false active response. Progress contains
fixed reason codes, stages, counts/timestamps and digests, never private
instructions, raw diagnostics, credential material or host paths.

The worker entry point is `python -m clusterctl.onboarding_worker --config PATH`;
`--once` is a bounded operator invocation of the same engine. Its configuration
uses schema `cluster-onboarding-host/v1` with host-owned `jobs`, `grants` and
`progress`, `inputs` and `views` directories, the qualified `code` directory, pinned `native_image`, `browser_image`, `release_digest`,
named `pool`/`profile` and bounded `concurrency`. Only reviewed receiving release
code belongs in its installation. No incoming script is an execution adapter. Build code-only artifacts with
`python -m tools.build_onboarding_code`; choose shared skills and the primary
memory store explicitly. Artifacts contain pinned HMK code, maintained
receiving tools and selected transferable context; no identity, memory, bot
credential or account cache is part of a code release. The mutable development
checkout is captured, while the final artifact forbids group/other writes and
is selected by its complete manifest digest.

Live configurations also set `consent_state` to the private intake store and
`consent_uid` to its dedicated service UID. Missing consent configuration stops
before inheritance installation. The optional host-only `qualification: true`
permits context-only disposable rehearsals with an exact host grant and a
`qualify-` name; participant labels alone cannot select that exception. No
qualification flag supplies native authority or receiving acceptance.

The dedicated guest account uses UID/GID 1000. The qualified image carries
receiving tools; bootstrap creates this new unprivileged account when absent,
refuses an existing conflicting UID/group, and initializes only its empty
mounted home. Existing receiving homes and accounts are preserved.
Every input view sits below a root-private parent outside intake state. Only
that job's child view is mounted in its guest; both input and code disks are
read-only. Their installed writable memory remains inside the 22 GiB home.

Provider authorization is separate from the seed. An owner-authorized account
profile may deliver a protected supported login cache; a fresh login is needed
only when the provider actually requires it. Shared-account refresh and Source
continuity must be qualified before cohort activation. Host execution grants
do not substitute for native Matrix root/custody consent or signed authority.

## Qualification still required

Local crash/retry, isolation, concurrency, revocation and HTTP disclosure tests
qualify the orchestration boundary. A host-local qualification of Eko's already
frozen input with the pinned native HMK retrieved 25 chapters across two stores,
verified original-row preservation and exercised installation retry. It made
no provider, Matrix or Telegram calls and created no live body. Its private
receipt pins the exact input and code artifact. A subsequent purpose-created
Incus qualification completed the same environment/context/memory stages,
verified a read-only input mount and repeated both receiving stages without
replacement. The disposable instance and its 22 GiB home were removed using
independently tested exact-marker cleanup; the existing four bodies remained
running. This is physical receiving-stage evidence, not canonical Eko enrollment
or hosted SSH/provider/Telegram acceptance. They do not prove live receiving memory,
Matrix enrollment, provider login or a human Telegram exchange. Finish the
typed stage adapters, qualify the disposable complete journey, then run Eko
and independently Oliva on the same final qualified release. Keep the goal
active until both real receiving acceptances are observed.
