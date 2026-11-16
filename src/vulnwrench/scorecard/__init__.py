"""Offline CycloneDX / Scorecard evidence joins. No scanners or network calls."""

from .core import InputError, check, gate_exit_code, normalize_repository, render_markdown
from .mapping_lint import lint_mappings
from .comparison import compare

__all__ = ["InputError", "check", "compare", "gate_exit_code", "lint_mappings", "normalize_repository", "render_markdown"]
__version__ = "0.1.0"
