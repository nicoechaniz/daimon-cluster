# DM-034 HMK executor contract

Status: normative for Cluster H5.

## Authority and route

Matrix is the sole authority for the being, memory lane, policy decision,
review and canonical curator result. HMK is a disposable retrieval projection.
Cluster owns only physical HMK custody, a resource fence, crash recovery and
fresh effect observation.

There is one route and no wildcard:

```text
adapter            cluster-dm034-hmk/v1
work kind          memory-projection
resource namespace hmk
```

The concrete `resource_ref` is constructor-fixed per embodiment, for example
`hmk:personal-memory:peer-a`. A queue item cannot select another namespace,
checkout, filesystem base, SQLite database, executable, environment variable
or operation.

## Exact dependency line

Cluster's current Matrix pin
`915c56c8899fd53d683bd7c7c81c3465b600bed9` contains the audited DM-034 line.
Startup now checks the exact profile, intent, receipt, reconciliation,
rebuild-plan and rebuild-receipt schemas plus HMK commit
`f10fd5c3089c0962920314c97e14bc024feffa7a`, API `1.0.0`, schema `1` and
projector `matrix:personal-memory-projector@1.0.0`. A mismatch disables the
whole Matrix host boundary; Cluster has no compatibility parser.

## Current intent and preview

`dm.cluster.dm034-execution-intent/v1` is closed and payload-free. It binds:

- project or rebuild, target and decision event UUIDs;
- exact source event ID/hash, or exact rebuild request and DM-034 plan hash;
- idempotency key, fixed resource and exact profile hash;
- deterministic preview hash;
- current Cluster actor with automated `daimon` effect authority; and
- an optional fresh independent Matrix source-review reference.

For projection, the target is the exact current source event. For rebuild, the
executor recomputes the non-mutating DM-034 library plan and requires the queued
plan hash before applying it. Statement bytes may occur transiently inside the
Matrix library/closed HMK request, but never in the curator item, Cluster intent,
outer receipt, public evidence or logs.

Before effect, after effect and on cached retry the executor resolves the
current intent again. `input_ref`, `input_hash`, `effect_intent_hash`, actor,
required authority and exact route must agree. Changed source, preview, plan,
review, actor, route or profile refuses execution.

## Fence, crash and replay

Every item uses DM-031 `resource-fence` coordination. The exact claim position
must equal fresh production fence evidence verified against Cluster's current
registry/high-water state. The check runs before HMK, after HMK and before a
cached receipt returns. Changed holder, incarnation, epoch, proof, expiry or
observer availability fails closed.

The owner-only SQLite journal has three states:

```text
pending -> effect-applied -> completed
```

It reserves a stable effect UUID and start time before dispatch. DM-034's inner
journal and HMK idempotency recover a crash or response loss before staging.
The outer journal then freezes the exact inner receipt, payload-free observed
postcondition and completion time before constructing the content-addressed
Cluster effect receipt. An exact retry returns the same receipt only after
fresh Matrix/HMK/fence reconciliation. Different item, claim, intent or
postcondition cannot rewrite a historical row.

Matrix alone appends or retains the canonical curator result. Cluster neither
signs as the being nor offers a generic receipt/tool fallback.

## Effect observation

Projection observation runs DM-034 receipt validation and reconciliation, then
fresh `inspect`. The outer postcondition contains only namespace/projection/
memory IDs, current head IDs/hashes, statement hash and active state. Rebuild
observation runs fresh namespace `verify` and binds namespace ID, generation,
manifest and Matrix checkpoint hashes.

The route returns exactly current intent, observed postcondition and fresh
fence evidence. An absent/throwing route or unavailable inner observer becomes
`effect_truth_unverifiable` at the existing router.

## Disposable storage and rollback

The HMK subprocess runs the exact clean checkout, fixed script and fixed base
with umask 077 and a minimal environment. SQLite backup uses its backup API,
checks integrity/foreign keys and reports only byte length and SHA-256. Restore
accepts a verified snapshot and a nonexistent owner-only base. It never edits
Matrix history.

Rollback disables the route/writer and preserves or restores HMK SQLite. A
lost HMK view is rebuilt from current Matrix through the exact non-mutating
plan plus atomic namespace apply. Separate embodiments have separate journal,
base and fence coordinates; damaging one synthetic base must not affect its
peer.
