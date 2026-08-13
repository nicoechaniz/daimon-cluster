"""clusterd — authenticated HTTP API over clusterctl (issue #17).

Design: ``docs/design/clusterd.md``. Mutations keep clusterctl as the sole
business-logic boundary. Read routes add owner scoping, redaction, explicit
observation models, and bounded snapshot pagination.
"""

__version__ = "0.1.0"
