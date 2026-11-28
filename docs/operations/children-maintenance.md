# Maintenance for a managed guest fleet

Keep the receiver inventory and its operational evidence in the authorized
operations register. The public tools consume the selected inventory from
operator-owned configuration.

The daily inventory consumes a `cluster-children-daily/v1` JSON configuration.
The `targets` array names the host first with a null `instance`, followed by
four guests with distinct IDs and Incus instance names. An application-unit
selection must cover exactly those IDs. Include browser components for guest
targets only. Pass `--config` to `tools/children_daily.py` and use the selected
scanner and helper hashes from the receiving deployment.

The package coordinator uses the same root-owned, private inventory when
running `tools/children_package_maintenance.py --fleet`. An alternate
`--fleet-config` is available for a deployment with a different inventory path.
Maintain the deployment's existing systemd confinement and its state
directory. Package transactions select reviewed versions and reconcile durable
intent before considering another install. Daily inventory and package
receipts identify separate effects.

Treat stale observations, incomplete coverage and confirmed applicability as
separate states. Check package and application receipts at the receiver before
claiming a fix. Keep paired human access, signed identity, and paused work
under their existing owning controls.
