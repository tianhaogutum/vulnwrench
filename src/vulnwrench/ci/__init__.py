"""``vulnwrench ci``: one CI gate over existing scanner reports.

Fuses Trivy/Grype/OSV-Scanner reports (``fuse``), drops findings already in a saved
baseline merge, applies and audits exception files (``ignores``) and gates what is left
on local EPSS/KEV snapshots (``exploit``). Reads local files only; writes nothing.
"""
from .. import __version__

SCHEMA = "vulnwrench.ci/v1"

__all__ = ["SCHEMA", "__version__"]
