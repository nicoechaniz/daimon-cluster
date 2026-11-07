# Children's host: storage and resource layout

Observed 2026-11-07 after Nicolas confirmed Debian 13 reinstallation of the
selected former Source VPS. Do not repeat that completed destructive operation.
The host's current role/name is lordoftheflies. Existing living CompAII, Eko and
Oliva bodies remain on ITACA, MEDUSA and the ITACA KVM respectively.

## Measured storage selection

The receiving VPS reports six CPUs, 12,250,865,664 bytes of RAM, a 100 GiB
primary virtual disk and a 200 GiB secondary virtual disk. Both report QEMU;
physical media, provider throttling and contention underneath remain unknown.
Provider reinstallation left the secondary's old Btrfs filesystem present;
its reuse was explicitly authorized and independently selected by disk serial,
size, root exclusion and absence of mounts/holders before formatting.

A finite comparison tested fresh Btrfs, Btrfs with Zstd level 1, ext4 and XFS.
Fio used direct I/O, four synchronous workers, 4 KiB random mixed reads/writes
(70/30), a bounded 512 MiB payload and twelve-second sampling. It observed
roughly 305–364 aggregate IOPS on the secondary versus 28,892 on the primary.
These are short samples, not a provider SLA or proof of a particular throttle.

A separate create/write/rename/stat/read/unlink workload used 1,600 files of
4 KiB across four workers, syncing every 32 files. Two five-run batches changed
the filesystem order. Combined median elapsed times were:

| Secondary filesystem | Median seconds (10 runs) |
| --- | ---: |
| XFS | 0.794 |
| ext4 | 1.590 |
| Btrfs, Zstd level 1 | 1.771 |

Results varied between runs; an initial single ext4 run was faster than its
repeated median. XFS was selected using the repeated measurements and its
supported project quotas. This does not establish that Btrfs caused the entire
historical slowdown: raw random I/O remained slow across formats.

The secondary is now fresh XFS, mounted with `noatime,prjquota`; project
accounting and enforcement are observed ON. Incus uses it as a directory pool.
The primary retains ext4 and an Incus-managed 70 GiB Btrfs loop pool, preserving
copy-on-write base-image sharing and per-volume quotas without repartitioning
the host. Current pools/profile are prepared; recipient provisioning and real
quota/isolation exercises remain distinct acceptance steps.

## Exact new-plan resources

The existing onboarding plan optionally includes an exact `resources` object:
`root_gib`, `home_gib`, `cold_gib`, `cpu`, and `memory_gib`. All fields are bounded
integers. The protected intake policy selects this object; the browser/seed
cannot widen it. It participates in the plan digest and owner review/grant.
Older plans keep their original 8 GiB root plus 22 GiB home behavior and bytes.

The selected four-companion layout is 8 GiB root plus 8 GiB hot home in the fast
pool, 48 GiB cold storage per companion on XFS, three shared CPUs and a 4 GiB RAM
cap. RAM/CPU limits are shared maxima, not physical reservations. The host keeps
at least 15 GiB root headroom in planning, a separate cold metadata/headroom
reserve and a bounded swap allocation. Install/exercise the actual memory policy
before admitting the four workloads; a prepared profile alone proves no cgroup
or concurrent-workload acceptance.

`cold_pool` is an optional protected HostConfig selector distinct from the fast
pool. A resource plan waits before mutation if it is unavailable. The adapter
checks exact image, plan marker, volume sizes, CPU/memory values and attachments;
foreign cold volumes are refused before instance creation. Partial effects
reconcile under the same job/operation. Only the owned hot-home and cold mount roots are changed
to the guest agent's UID/GID and mode 0700, without recursively changing user data.
A first actual guest exposed the missing hot-home ownership initialization;
new-layout readiness now checks both mounts before declaring completion.
Real filesystem quotas, guest permissions and cgroup values require target-side
checks before reporting the environment ready.

## Storage purpose and retention

Keep active source, worktrees, compilation, native history and memory databases
on fast storage. The slow volume is for colder files. Worthwhile heavy project
material that must persist or be shared goes to institutional Drive through its
maintained adapter, project map and selected audience. Private child records stay
separate; a shared provider account does not pool autobiographies or Matrix keys.
Do not upload disposable caches, duplicate archives or unused experiments.

The comparison retained only small summaries and its launcher/source, capped at
1 MiB; disposable payloads were removed before production formatting. Image
transfer is separately capped at one 1 GiB base image and its metadata, removed
after successful receiving import/fingerprint verification. Preserve uncertain
operations. No daily full-environment archive or migration restore drill is added.

Daily resource/security automation remains a separate delivery: reuse the
maintained Shared Resources `children-host-security.md` handoff and actual
Alerts/housekeeping contracts. Do not claim installation or exercised coverage
from this plan, the XFS timer installed incidentally by its package, or unit files
alone. That incidental timer was disabled pending the integrated selected policy.
