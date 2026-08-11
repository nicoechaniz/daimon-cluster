# Dashboard design (M6 #24-#26 input)

Status: design v0.1 (2026-08-01). Inputs: PLAN §6 (two surfaces, one API),
clusterd design (M4), ADR D4 (auth: anyVPN + scoped bearer; OIDC only in
product phase).

## 1. Shape

A static web UI (no server-side rendering framework) served by clusterd
itself on the anyVPN interface. The dashboard is a CLIENT of the same
/v1 API the steward agent uses — literally the same endpoints, same auth,
same audit trail. If the dashboard can do it, the API exposes it; if the
API doesn't, the dashboard can't fake it (#24-#25 acceptance by
construction).

```
browser (operator, on anyVPN) ──HTTPS──> clusterd:8785
   ├── GET  /              → static bundle (vanilla JS, no build step)
   ├── GET  /v1/instances  → bounded fleet snapshot page
   └── POST /v1/...        → actions (with the operator's bearer token)
```

## 2. Screens (v1)

1. **Fleet**: one row per daimon — declared, runtime, embodiment,
   incarnation and Matrix-process observations shown separately, plus image,
   budgets and uptime. Polls the first bounded snapshot page from
   GET /v1/instances; truncation is visible and never silently treated as the
   whole fleet.
2. **Health**: host headroom (RAM/disk vs inventory budgets), per-daimon
   sparkline-free numbers (RSS, uptime), backup state per daimon
   (protected/degraded/unprotected from #15).
3. **Activity**: bounded audit snapshot tail (`GET /v1/audit?limit=...`),
   filterable by identity/actor/result. Tail truncation is visible. Denials
   remain visible — the audit is the product.
4. **Actions** (behind per-action confirm dialogs that mirror the API's
   own prepare/confirm): start/stop/restart, snapshot, provision prepare.
   Destroy/update stay CLI-only in v1 — the dashboard shows their state
   but doesn't offer the buttons (conservative; #25 covers the safe set).

## 3. Auth in the browser

The operator pastes their scoped bearer token once; it lives in
sessionStorage (never localStorage, never cookies — no CSRF surface).
Read-only tokens get screens 1-3; action tokens unlock screen 4 per
scope. The token's scopes are displayed so the operator always knows what
their session can do (#26 drill: watch an operator attempt an
out-of-scope action and see the denial in the activity feed — that IS
the failure-state drill).

## 4. v1 non-goals

No websockets (polling is fine at this scale), no multi-host, no dark
patterns of "one click = irreversible", no metrics database (numbers
come from clusterctl status + audit; if it isn't in the API, it isn't
in the dashboard).
