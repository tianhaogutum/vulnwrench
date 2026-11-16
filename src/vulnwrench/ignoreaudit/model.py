"""Small immutable audit model; no scanner or suppression writer."""
from dataclasses import dataclass
from datetime import date


class InputError(ValueError):
    """Safe-to-display error; never includes input values."""


@dataclass(frozen=True)
class Rule:
    key: str
    advisory: str
    expires: date | None = None
    reason: str | None = None
    owner: str | None = None
    # Exact, case-sensitive selectors for callers of the library.
    package: str | None = None
    path: str | None = None
    ecosystem: str | None = None
    version: str | None = None
    # OSV local config applies to source files in this directory, not descendants.
    source_dir: str | None = None


@dataclass(frozen=True)
class ReportAliasHint:
    """A report declaration for review only; never matching equivalence."""
    aliases: tuple[str, ...]
    locator: str


@dataclass(frozen=True)
class UnboundReportAliasHint:
    """A group declaration with no same-package observation to attach to."""
    ids: tuple[str, ...]
    aliases: tuple[str, ...]
    locator: str
    reason: str


@dataclass(frozen=True)
class Finding:
    advisory: str
    package: str | None
    path: str | None
    ecosystem: str | None = None
    version: str | None = None
    locator: str = ""
    alias_hints: tuple[ReportAliasHint, ...] = ()


@dataclass(frozen=True)
class CoverageGap:
    """An absent/null collection, separate from observed findings."""
    locator: str
    state: str  # absent or null


@dataclass(frozen=True)
class Report:
    findings: tuple[Finding, ...]
    coverage: str  # asserted_unfiltered or unknown
    notes: tuple[str, ...] = ()
    uninterpreted_fields: tuple[str, ...] = ()
    unbound_alias_hints: tuple[UnboundReportAliasHint, ...] = ()
    coverage_gaps: tuple[CoverageGap, ...] = ()
