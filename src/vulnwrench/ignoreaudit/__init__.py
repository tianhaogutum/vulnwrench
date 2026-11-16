"""Independent, stdlib-only exception audit library."""
from .audit import audit, match_indexed, match_reference
from .explain import explain
from .inputs import load_aliases, load_report, load_rules
from .model import CoverageGap, Finding, InputError, Report, ReportAliasHint, Rule, UnboundReportAliasHint

__version__ = "0.1.0"
__all__ = ["audit", "explain", "match_indexed", "match_reference", "load_aliases", "load_report", "load_rules", "CoverageGap", "Finding", "InputError", "Report", "ReportAliasHint", "Rule", "UnboundReportAliasHint"]
