# H8 rebirth runtime verification receipt

Date: 2026-08-11. Candidate only; not deployed or independently reviewed.

## Exact boundary

- Cluster H7 base: `9acb9b20478ec535252a5ea0bc97522823dac687`
  (draft PR #80).
- Matrix contract: `1452bf6f7cea841ee1f1757f3b001708f8e72c84`
  (Matrix draft PR #116).
- Cluster issue: #81.

## Process gate

The focused suite now exercises 16 scenarios. In addition to every H7 install,
replay, concurrency and crash boundary, it proves that the foreground H8
supervisor:

- resolves the activation from the durable H7 receipt rather than trusting a
  caller or inferring an operational ID from the public runtime;
- admits exactly the root-authorized target incarnation;
- passes the target password only through an inherited descriptor and does not
  expose it through argv, environment or diagnostics;
- waits for the real Matrix child `READY`, then authenticates integrity,
  manifest, being, local origin, running body and active `/we` membership;
- restarts the process over the same completed start receipt with one start
  audit event; and
- retains a resumable `runtime-dispatching` journal after a wrong-password
  child refusal, then completes with the correct custody without minting a new
  incarnation.

The three-process journey copies no private custody between embodiments. It
starts both original daemons from their own encrypted roots plus the fresh
target from its separate custody. A fresh-origin event is imported by an old
peer, an old-origin event is imported by the target, an exact peer-pull request
replays without a second effect, and both imported events remain `pending`.

```text
ruff: clean
mypy: clean
pytest tests/test_rebirth.py: 16 passed
complete Cluster suite: 452 passed, 2 skipped
```

The four-version CI and isolated remote journey remain gates for this branch.
No live service, production state root, Incus instance, authority manifest or
custody was changed by this receipt.
