"""clusterd — thin HTTP API over clusterctl (issue #17).

Design: ``docs/design/clusterd.md``. clusterd duplicates NO business
logic: every route adapts a ``clusterctl.cli.run`` invocation (same
code path as the CLI) or reads the same state files clusterctl writes.
"""

__version__ = "0.1.0"
