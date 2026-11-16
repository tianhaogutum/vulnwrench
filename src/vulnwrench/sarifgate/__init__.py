"""Offline, explainable SARIF CI gate."""

from .baseline import compare_bytes
from .core import InputError, Policy, check_bytes, dumps, evaluate, markdown_summary, parse_document

__version__ = "0.1.0"
__all__ = ["compare_bytes", "InputError", "Policy", "check_bytes", "dumps", "evaluate", "markdown_summary", "parse_document"]
