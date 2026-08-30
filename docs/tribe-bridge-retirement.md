# Tribe Bridge retirement boundary

Tribe Bridge was an experimental transport. V0.1.0 stable does not migrate its
messages, queues, directory, identities, keys or host state and provides no
compatibility, downgrade, dual-run or fallback path.

This Cluster successor removes the active dependencies:

- no Bridge distribution or module is installed by native birth;
- no Cluster command creates Bridge identity or directory material;
- no `tribe-base` image builder, pin set or manifest is shipped;
- active defaults use `daimon-base/latest` and `daimon-agent`;
- the firewall template has no Bridge broker port; and
- park/handoff does not inspect or override a Bridge outbox.

Matrix's native tribe and relationship governance is not the Bridge product
and remains part of the being model. Historical RC tools and dated runbooks
may name the Bridge because they reproduce or explain the already published
three-repository RC; they are not stable runtime or cutover inputs.

This source change has no live effect. Stopping/disabling the existing Bridge
service and deleting its exact disposable operational state require a
separate reviewed deletion inventory and matching GO. Stable publication and
the final source-only Tribe release/archive are separately gated as well.
