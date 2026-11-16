"""Layer attribution: independent, offline Trivy/OCI report processing."""

from .core import InputError, explain
from .comparison import compare

__all__ = ["InputError", "explain", "compare"]
__version__ = "0.1.0"
