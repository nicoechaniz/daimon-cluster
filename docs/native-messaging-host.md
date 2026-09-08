# Native messaging in the Cluster Matrix host

Issue #104 (Matrix #132) adds an **explicit opt-in** to the existing host.
It does not enroll peers, generate custody, publish an application, migrate
state, or enable a service. Telegram integration is outside this change.

## Entry points

The existing `python -m clusterctl.matrix_host` command accepts:

```text
--messaging-application /absolute/owner-local/application-directory
```

Supply this alongside the existing state directory, embodiment ID and password
file descriptor arguments. Prefer an absolute path; relative paths are relative
to the host process working directory. This is a published Matrix application
directory, not a runtime bundle or an arbitrary Python/plugin path. Its ownership,
signed publication, custody and store validation belong to Matrix's
`messaging_config.read_application_authorities` and `load_application`, not
Cluster protocol reimplementations.

Programmatic callers may use `clusterctl.matrix_host.run(state_dir,
embodiment_id, password_fd=..., messaging_application=...)`. The application
argument defaults to `None`. Other keyword arguments retain the CLI's defaults:
`bundle="runtime.json"`, `ready_fd=None`, `guardian_pid=None`, and
`production_fence_verifier=False`. Like the original command, this lifecycle
installs process signal handlers and is intended for the host's main thread.
It returns 0 on normal shutdown and 1 with a structured stderr diagnostic on
startup/serve refusal. The password reader consumes and closes its descriptor
when runtime loading requests it; callers retain responsibility for descriptors
not consumed on an earlier failure.

Neither entry point discovers applications from environment variables or state
files. With no application configured, the host does not import messaging code
or add `relationship_authorities` to the old pinned runtime API, and passes the
original loaded runtime straight to the daemon. Existing launchers
remain opt-out; this change does not add deployment configuration or forwarding
to the admission launcher.

## Ordering and authority

The actual guarded host path remains:

1. Validate guardian, then the existing exact Matrix distribution commit and
   schema/capability contract through `_matrix_api()`.
2. Construct the host adapter and optional production fence verifier; validate
   owner-local runtime root, registered origin and socket name; acquire the
   runtime ownership lock.
3. **Only if explicitly configured**, lazily import Matrix's application API and
   call `read_application_authorities(root, bundle_name, app_directory,
   at_ms=clock())` under that lock, before constructing the password reader or
   loading the ordinary runtime/stores. Matrix verifies protected public metadata,
   signatures, explicit shared-store selection and existing schema read-only.
4. Load and verify the runtime with the existing body reader, curator fence
   verifier and curator effect observer installed. Use the same clock callable
   used for preflight. On opt-in only, pass the exact returned public authority
   mapping as `relationship_authorities`, without copying/rebuilding providers.
5. **Only if explicitly configured**, call `load_application(runtime,
   app_directory)` for final signed selection/grant/store validation. Use its
   returned composed runtime; do not rebuild the service or discard host hooks.
6. Install the existing signal handlers and enter `serve_forever`, which owns
   socket readiness and serving/transport cleanup.

The tested pre-reader contract targets the configured ordinary relationship
context (including zero-peer configurations) with explicit signed shared mode.
It returns verified foreign authorities; local retained epochs stay owned by the
runtime bundle. The inspected API rejects isolated/missing shared selection;
Cluster does not guess an isolated fallback or synthesize authorities. Matrix
owns any future optional/`None` return contract. Existing grants must already
be ingested by a trusted preparation flow: this host does not enroll or ingest
events. Foreign historical epochs require independently verified history
authorities beyond this minimal public-snapshot preloading path.

An unavailable pre-reader/loader, missing application or incompatible configuration refuses
startup with `matrix_messaging_application_rejected`. There is no ordinary-runtime
fallback after opt-in. No ready signal is sent by the host before composition.
Neither preflight nor final application exception text/path is emitted in the
diagnostic. Preflight refusal precedes password consumption and base runtime
writes; later ordinary runtime failures retain their existing diagnostics.
The existing `finally` path sets the stop event and closes the ownership lock.
Admission remains owned by `rebirth_host`, not by this adapter: a child refusal
continues through its existing startup-failure cleanup and admission release.

## Verification and release boundary

Tests in `tests/test_matrix_messaging_host.py` exercise the real host lifecycle
with injected Matrix API/application boundaries, including ordering, preservation
of all three injected hooks, exact authority mapping identity and clock source,
default no-import/no-new-keyword behavior, dependency/runtime refusal, public
preflight failure before password/runtime loading, composition failure, no
premature readiness and lock cleanup. A separate
disposable signed-runtime test launches the actual child host, observes its
configured startup refusal, and reads back released admission. Existing host,
process, rebirth and admission suites cover the unchanged default lifecycle.
These tests do not establish successful native messaging transport delivery.

`MATRIX_CONTRACT_COMMIT`, `requirements-weave.txt` and dependency validation are
unchanged. The currently pinned older Matrix package is valid for opt-out but
cannot supply the new application loader. The integrating parent must update the
exact reviewed Matrix pin and repeat real composed daemon/tool and full-suite
qualification. Do not fake installation provenance or bypass the pin check.

Parent-provided read-only deployment provenance identifies installed Cluster
Python source with commit `4a2571a6b22c6e504c1f78ce6594f1a2ad445097` and installed
Matrix with prefix `915c56c`. This source feature is **not** an isolated pin-only
production upgrade: upgrading that deployment pair and its consumers requires
an explicit reviewed preflight covering runtime/application schemas, capabilities,
authority and existing state. No production host, credentials, service, Tribe,
access path or live migration was touched or authorized by this change.
