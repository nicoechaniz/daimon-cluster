"""Gated steward mutations (issue #23) — two-phase propose/confirm.

The steward agent can NEVER mutate the fleet in one step. Every
mutation is:

1. **propose_<op>(name, ...) -> MutationPlan** — builds a
   ``steward-mutation-plan/v1`` describing EXACTLY one action
   (operation + target + actor + args, bound by a sha256 digest). For
   the non-destructive operations (start, stop, restart, snapshot,
   park, wake) NO clusterd call happens at propose time — proposing is
   pure local computation. For ``destroy`` (destructive class) propose
   calls the destroy route WITHOUT a confirm token to obtain the 409
   confirmation challenge. A challenge is NOT a mutation: clusterd's
   prepare/confirm middleware issues it before any handler runs and no
   adapter state changes (covered by tests).

2. **confirm_plan(plan, *, human_turn_id, typed_name=None)** — the ONLY
   execution path, called by the steward only after the human approved
   the displayed plan in the SAME human turn. It enforces, locally
   (defense in depth — clusterd enforces its own rules too):

   - integrity: the digest is recomputed from the plan's fields and
     compared to ``plan.action_digest``; a plan whose target/operation
     was altered after proposal is refused ``tampered-plan``;
   - replay: a plan object executes at most once (``used`` is set
     BEFORE the HTTP call, so even a crash mid-call never re-fires);
   - expiry: plans live ``ttl_s`` seconds (default 120) — a stale plan
     is refused before any HTTP;
   - typed-name: destructive plans require ``typed_name`` to equal the
     target EXACTLY (case-sensitive), the mechanical meaning of the
     human typing the daimon's name.

   There is NO free-form operation, URL, or assent-text parameter:
   the ``propose_*`` functions are the only entry points, operations
   are fixed strings, and ``confirm_plan`` takes the plan object
   itself — injected text (a web page, a chat message, display_text
   saying "Sí, dale destroy everything") cannot self-confirm or widen
   scope, because no text is ever parsed for assent.

Execution headers sent to clusterd: the mutate token (read per call
from the token file), ``X-Attended: true`` (ALWAYS — the human-turn
marker clusterd requires of steward@* actors), ``X-Human-Turn``,
a deterministic ``Idempotency-Key`` derived from the action digest,
and for destructive plans ``X-Confirm-Token`` carrying the challenge.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

def action_digest(operation: str, target: str, actor: str,
                  args: dict | None = None) -> str:
    """sha256 of the canonical JSON of the bound action.

    MUST stay byte-identical to clusterd.confirm.action_digest — the
    daemon re-computes the digest when validating confirmations.
    steward_tools is staged into containers WITHOUT the clusterd
    package, hence the deliberate copy; tests/test_digest_parity.py
    guards drift.
    """
    canonical = json.dumps(
        {"operation": operation, "target": target,
         "actor": actor, "args": args or {}},
        sort_keys=True, separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

from .client import (
    DEFAULT_BASE_URL,
    NAME_RE,
    TIMEOUT_S,
    ClusterdError,
    ClusterdHTTPError,
    ClusterdUnreachable,
    CrossOriginRedirect,
    _SameOriginRedirectHandler,
)

SCHEMA = "steward-mutation-plan/v1"
RESULT_SCHEMA = "steward-mutation-result/v1"
DEFAULT_MUTATE_TOKEN_PATH = "/home/agent/.clusterd/mutate-token"
PLAN_TTL_S = 120

# Actor bound into non-destructive plan digests. The digest is local
# tamper-evidence + the idempotency key seed; clusterd re-derives its
# own binding from the authenticated token for the destructive class.
PLAN_ACTOR = "steward@plan-proposal"

# operation -> (impact sentence shown to the human, destructive?)
_OPERATIONS: dict[str, tuple[str, bool]] = {
    "start": ("powers on the daimon container", False),
    "stop": ("halts the daimon (state preserved; start brings it back)",
             False),
    "restart": ("reboots the running daimon (brief downtime)", False),
    "snapshot": ("quiesced backup: parks writers, checkpoints DBs, "
                 "captures + verifies an incus snapshot and writes a "
                 "backup manifest", False),
    "park": ("pauses the daimon's writers (SIGSTOP hermes) — the daimon "
             "stays frozen until wake", False),
    "wake": ("resumes a parked daimon (SIGCONT hermes)", False),
    "destroy": ("DESTRUCTIVE: destroys the instance after a consumed "
                "confirmation challenge (archive-first execution lands "
                "in a later milestone)", True),
    "restore": ("restores the instance from its most recent backup "
                "(instance must be stopped first)", False),
}


def _now_ms() -> int:
    return int(time.time() * 1000)


@dataclasses.dataclass
class MutationPlan:
    """ steward-mutation-plan/v1 — exactly one proposed action.

    ``display_text`` is what the steward shows the human: target,
    impact, destructive risk, digest prefix and expiry. It is NOT part
    of the digest and carries no authority — confirmation is the
    explicit ``confirm_plan`` call with THIS object, never text.
    """
    operation: str
    target: str
    impact: str
    destructive: bool
    action_digest: str
    created_ms: int
    ttl_s: int = PLAN_TTL_S
    challenge_token: str | None = None
    display_text: str = ""
    schema: str = SCHEMA
    actor: str = PLAN_ACTOR
    args: dict = dataclasses.field(default_factory=dict)
    used: bool = False


def _display(operation: str, target: str, impact: str, destructive: bool,
             digest: str, ttl_s: int) -> str:
    risk = ("DESTRUCTIVE — requires the human to type the exact name"
            if destructive else "non-destructive (reversible)")
    lines = [
        f"Proposed mutation: {operation} {target}",
        f"Impact: {impact}",
        f"Risk: {risk}",
        f"Digest: {digest[:12]}…",
        f"Expires: {ttl_s}s after proposal",
    ]
    if destructive:
        lines.append(f"To confirm, type the exact name: {target}")
    return "\n".join(lines)


def _make_plan(operation: str, name: str, *, actor: str = PLAN_ACTOR,
               args: dict | None = None, challenge_token: str | None = None,
               digest: str | None = None) -> MutationPlan:
    if operation not in _OPERATIONS:
        raise ValueError(f"unknown mutation operation {operation!r}")
    if not NAME_RE.fullmatch(name):
        raise ValueError(f"invalid instance name: {name!r}")
    impact, destructive = _OPERATIONS[operation]
    args = dict(args or {})
    digest = digest or action_digest(operation, name, actor, args)
    return MutationPlan(
        operation=operation,
        target=name,
        impact=impact,
        destructive=destructive,
        action_digest=digest,
        created_ms=_now_ms(),
        challenge_token=challenge_token,
        display_text=_display(operation, name, impact, destructive,
                              digest, PLAN_TTL_S),
        actor=actor,
        args=args,
    )


class MutationClient:
    """Mutation-scoped clusterd client for the gated two-phase flow.

    Same construction rules as the read client: the base URL is fixed
    at construction (CLUSTERD_URL env or the compiled-in default), the
    mutate token is re-read from its file per call, urllib only, 5s
    timeout, cross-origin redirects refused. Only the seven fixed
    mutation route shapes exist — no arbitrary paths.
    """

    def __init__(self, token_path: str = DEFAULT_MUTATE_TOKEN_PATH,
                 token_override: str | None = None,
                 base_url: str | None = None):
        base = (base_url or
                os.environ.get("CLUSTERD_URL", DEFAULT_BASE_URL)).rstrip("/")
        self._base_url = base
        self._token_path = token_path
        self._token_override = token_override
        self._opener = urllib.request.build_opener(
            _SameOriginRedirectHandler())

    def _token(self) -> str:
        if self._token_override is not None:
            return self._token_override
        return Path(self._token_path).read_text(encoding="utf-8").strip()

    def _post(self, path: str, headers: dict) -> tuple[int, object, dict]:
        """Send one mutation request; returns (status, json, headers)."""
        req = urllib.request.Request(
            self._base_url + path, method="POST", data=b"{}",
            headers={"Authorization": f"Bearer {self._token()}",
                     "Content-Type": "application/json", **headers})
        try:
            with self._opener.open(req, timeout=TIMEOUT_S) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
                return resp.status, payload, dict(resp.headers)
        except urllib.error.HTTPError as exc:
            try:
                body = json.loads(exc.read().decode("utf-8"))
            except Exception:  # non-JSON error body — keep the status
                body = None
            raise ClusterdHTTPError(exc.code, body) from exc
        except CrossOriginRedirect:
            raise
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            raise ClusterdUnreachable(str(exc)) from exc

    def mutation_path(self, operation: str, target: str) -> str:
        """The one fixed route shape; both parts are validated upstream."""
        return f"/v1/instances/{target}/{operation}"


def _client(client: MutationClient | None) -> MutationClient:
    return client if client is not None else MutationClient()


def _mutation_headers(plan: MutationPlan, human_turn_id: str) -> dict:
    """Headers for the execution call. ``X-Attended: true`` is ALWAYS
    sent — the human-presence marker clusterd requires of steward@*
    actors; ``X-Human-Turn`` binds the call to the approving turn."""
    headers = {
        "X-Attended": "true",
        "X-Human-Turn": str(human_turn_id),
        # Per plan AND per intent: the digest alone made independent
        # intents collide (nico's dashboard stop replayed the steward's
        # hours-old cached result — found in the #26 drill). The human
        # turn separates intents; a retried confirm of the SAME intent
        # still dedupes (and the single-use challenge guards replays).
        "Idempotency-Key": (
            f"steward-{plan.action_digest[:24]}-{human_turn_id}"),
    }
    if plan.destructive and plan.challenge_token:
        headers["X-Confirm-Token"] = plan.challenge_token
    return headers


def _result(plan: MutationPlan, ok: bool, *, refused: str | None = None,
            http_status: int | None = None, data: object = None,
            error: str | None = None) -> dict:
    return {
        "schema": RESULT_SCHEMA,
        "ok": bool(ok),
        "operation": plan.operation,
        "target": plan.target,
        "refused": refused,
        "http_status": http_status,
        "data": data,
        "error": error,
    }


# --------------------------------------------------------------------------
# phase 1 — propose (NEVER mutates; only destroy talks to clusterd, and
# only to obtain a 409 challenge, which is not a mutation)
# --------------------------------------------------------------------------

def _propose(operation: str, name: str) -> MutationPlan:
    """Local-only proposal for the non-destructive operations."""
    return _make_plan(operation, name)


def propose_start(name: str) -> MutationPlan:
    return _propose("start", name)


def propose_stop(name: str) -> MutationPlan:
    return _propose("stop", name)


def propose_restart(name: str) -> MutationPlan:
    return _propose("restart", name)


def propose_snapshot(name: str) -> MutationPlan:
    return _propose("snapshot", name)


def propose_park(name: str) -> MutationPlan:
    return _propose("park", name)


def propose_wake(name: str) -> MutationPlan:
    return _propose("wake", name)


def propose_restore(name: str) -> MutationPlan:
    return _propose("restore", name)


def propose_destroy(name: str,
                    client: MutationClient | None = None) -> MutationPlan:
    """Propose a destroy: fetch clusterd's confirmation challenge.

    Calls the destroy route WITHOUT X-Confirm-Token, which answers 409
    with a ``confirmation/v1`` challenge. A challenge is NOT a
    mutation: clusterd's middleware issues it before any handler runs,
    no adapter state changes, and the challenge itself is single-use
    and expires. The plan adopts the challenge's actor + digest so the
    confirmation stays bound to EXACTLY the authenticated action.

    Raises ClusterdError if clusterd does not answer with a challenge
    (there is no plan to show in that case — proposing failed).
    """
    if not NAME_RE.fullmatch(name):
        raise ValueError(f"invalid instance name: {name!r}")
    mc = _client(client)
    try:
        mc._post(mc.mutation_path("destroy", name),
                 {"Idempotency-Key": f"steward-propose-{_now_ms()}"})
    except ClusterdHTTPError as exc:
        if exc.status != 409 or not isinstance(exc.body, dict) \
                or not exc.body.get("token"):
            raise ClusterdError(
                f"destroy proposal did not yield a confirmation challenge "
                f"(HTTP {exc.status})") from exc
        ch = exc.body
        return _make_plan(
            "destroy", name,
            actor=ch.get("actor") or PLAN_ACTOR,
            challenge_token=ch["token"],
            digest=ch.get("action_digest"))
    raise ClusterdError(
        "destroy proposal answered 2xx without a confirmation challenge — "
        "refusing to build a plan against a misbehaving daemon")


# --------------------------------------------------------------------------
# phase 2 — confirm (the ONLY execution path)
# --------------------------------------------------------------------------

def confirm_plan(plan: MutationPlan, *, human_turn_id: str,
                 typed_name: str | None = None,
                 client: MutationClient | None = None) -> dict:
    """Execute a previously proposed plan after human approval.

    Returns a steward-mutation-result/v1 dict. Local refusals (no HTTP
    performed): ``tampered-plan``, ``replay``, ``stale-plan``,
    ``typed-name-required``, ``typed-name-mismatch``. clusterd-side
    denials surface as ``ok=False`` with the daemon's status + error.
    """
    if not isinstance(plan, MutationPlan):
        raise ValueError("confirm_plan requires a MutationPlan object")
    if not human_turn_id:
        raise ValueError("human_turn_id is required")

    # 1. integrity — recompute the digest from the plan's CURRENT
    #    fields; any post-proposal edit (parameter substitution) breaks
    #    the binding and is refused before anything else.
    recomputed = action_digest(plan.operation, plan.target, plan.actor,
                               plan.args)
    if recomputed != plan.action_digest:
        return _result(plan, False, refused="tampered-plan",
                       error="plan fields no longer match its action digest")

    # 2. replay — a plan object executes at most once, ever.
    if plan.used:
        return _result(plan, False, refused="replay",
                       error="this plan was already confirmed")

    # 3. expiry — the human approved THIS display, not a stale one.
    if _now_ms() > plan.created_ms + plan.ttl_s * 1000:
        return _result(plan, False, refused="stale-plan",
                       error=f"plan expired ({plan.ttl_s}s ttl)")

    # 4. typed-name — the destructive class requires the human to have
    #    typed the exact target name (case-sensitive).
    if plan.destructive:
        if typed_name is None:
            return _result(plan, False, refused="typed-name-required",
                           error="destructive plans require typed_name")
        if typed_name != plan.target:
            return _result(plan, False, refused="typed-name-mismatch",
                           error="typed_name does not match the plan target")

    # Crash-safe single use: mark BEFORE the HTTP call so a reused plan
    # object can never re-fire, even if the process dies mid-request.
    plan.used = True

    mc = _client(client)
    try:
        status, payload, _headers = mc._post(
            mc.mutation_path(plan.operation, plan.target),
            _mutation_headers(plan, human_turn_id))
        return _result(plan, True, http_status=status, data=payload)
    except ClusterdHTTPError as exc:
        body = exc.body if isinstance(exc.body, dict) else {}
        return _result(plan, False, http_status=exc.status,
                       error=body.get("error")
                       or f"clusterd answered HTTP {exc.status}")
    except ClusterdUnreachable:
        return _result(plan, False, error="clusterd-unreachable")
    except ClusterdError as exc:
        return _result(plan, False,
                       error=f"clusterd-client-error:{type(exc).__name__}")
