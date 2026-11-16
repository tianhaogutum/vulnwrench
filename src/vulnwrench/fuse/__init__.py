"""Offline vulnerability report integration; no scanners or network access."""

from .core import CoverageManifest, InputError, Report, dumps, merge_reports, read_coverage_manifest, read_report, render_markdown, validate_coverage, validate_input
from .explain import explain_finding
from .explain_markdown import render_explanation_markdown
from .saved import compare_saved_input_coverage, list_saved_finding_coverage, read_merged, validate_merged, validate_saved_coverage, validate_saved_finding_coverage

__version__ = "0.1.0"
__all__ = ["CoverageManifest", "InputError", "Report", "compare_saved_input_coverage", "dumps", "explain_finding", "list_saved_finding_coverage", "merge_reports", "read_coverage_manifest", "read_merged", "read_report", "render_explanation_markdown", "render_markdown", "validate_coverage", "validate_input", "validate_merged", "validate_saved_coverage", "validate_saved_finding_coverage"]
