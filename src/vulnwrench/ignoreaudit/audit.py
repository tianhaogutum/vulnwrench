"""Reference and indexed matching; expired rules are still counted for auditing."""
from collections import Counter, defaultdict
from datetime import date
from pathlib import PurePosixPath

from .inputs import advisory, exact_path, string
from .model import InputError


def validate_rules(rules):
    keys = set()
    for rule in rules:
        string(rule.key, "rule locator")
        if rule.key in keys:
            raise InputError("duplicate rule locator")
        keys.add(rule.key)
        advisory(rule.advisory, "rule ID")
        if rule.expires is not None and type(rule.expires) is not date:
            raise InputError("rule expiry must be a date")
        for field in ("package", "ecosystem", "version"):
            value = getattr(rule, field)
            if value is not None and (not isinstance(value, str) or not value.strip() or any(c in value for c in "*?[]{}")):
                raise InputError("only exact nonempty package/ecosystem/version selectors supported")
        for field in ("path", "source_dir"):
            value = getattr(rule, field)
            if value is not None and exact_path(value, "rule path selector") != value:
                raise InputError("library path selectors must already be normalized POSIX paths")


def validate_findings_and_aliases(findings, aliases):
    for finding in findings:
        advisory(finding.advisory, "finding ID")
        for field in ("package", "path", "ecosystem", "version"):
            value = getattr(finding, field)
            if value is not None:
                string(value, "finding " + field)
    if not isinstance(aliases, dict):
        raise InputError("aliases must be an explicit mapping from each ID to its complete group")
    seen = set()
    for ident, group in aliases.items():
        advisory(ident, "alias ID")
        if not isinstance(group, (set, frozenset)) or ident not in group or len(group) < 2:
            raise InputError("aliases must be complete groups of at least two IDs, including their own key")
        frozen = frozenset(group)
        if frozen in seen:
            continue
        seen.add(frozen)
        for member in group:
            advisory(member, "alias ID")
            if aliases.get(member) != group:
                raise InputError("alias groups must be disjoint and symmetric for every member")


def selector_value(finding, field):
    """The observed value used by both matching and explanation checks."""
    value = finding.path if field == "source_dir" else getattr(finding, field)
    if value is not None and field in ("path", "source_dir"):
        value = str(PurePosixPath(value).parent) if field == "source_dir" else str(PurePosixPath(value))
    return value


def relation(rule, finding, aliases):
    """True=match, False=no match, None=missing selector evidence."""
    if finding.advisory not in aliases.get(rule.advisory, {rule.advisory}):
        return False
    unknown = False
    for field in ("package", "path", "ecosystem", "version", "source_dir"):
        wanted = getattr(rule, field)
        if wanted is None:
            continue
        value = selector_value(finding, field)
        if value is None:
            unknown = True
        else:
            if wanted != value:
                return False
    return None if unknown else True


def match_reference(rules, findings, aliases=None):
    """Straight rule-by-finding baseline. Return matches, unknowns, comparisons."""
    rules, findings = tuple(rules), tuple(findings)
    validate_rules(rules)
    aliases = {} if aliases is None else aliases
    validate_findings_and_aliases(findings, aliases)
    matches, unknowns, operations = [], [], 0
    for rule in rules:
        match, unknown = [], []
        for index, finding in enumerate(findings):
            operations += 1
            result = relation(rule, finding, aliases)
            if result is True:
                match.append(index)
            elif result is None:
                unknown.append(index)
        matches.append(match)
        unknowns.append(unknown)
    return matches, unknowns, operations


def match_indexed(rules, findings, aliases=None):
    """Build ID postings once; selectors refine only candidate observations."""
    rules, findings = tuple(rules), tuple(findings)
    validate_rules(rules)
    aliases = {} if aliases is None else aliases
    validate_findings_and_aliases(findings, aliases)
    index = defaultdict(list)
    operations = 0
    for position, finding in enumerate(findings):
        index[finding.advisory].append(position)
        operations += 1
    matches, unknowns = [], []
    for rule in rules:
        match, unknown = [], []
        candidates = sorted({position for ident in aliases.get(rule.advisory, {rule.advisory})
                             for position in index.get(ident, ())})
        for position in candidates:
            operations += 1
            result = relation(rule, findings[position], aliases)
            if result is True:
                match.append(position)
            elif result is None:
                unknown.append(position)
        matches.append(match)
        unknowns.append(unknown)
    return matches, unknowns, operations


def audit(rules, report, *, as_of, report_unfiltered=False, soon_days=30, aliases=None, matcher="indexed"):
    if not report_unfiltered:
        raise InputError("report_unfiltered acknowledgment is required")
    if type(as_of) is not date:
        raise InputError("as_of must be a date")
    if type(soon_days) is not int or soon_days < 0:
        raise InputError("soon_days must be a nonnegative integer")
    if report.coverage not in {"unknown", "asserted_unfiltered"}:
        raise InputError("unsupported report coverage")
    if matcher not in {"indexed", "reference"}:
        raise InputError("unsupported matcher")
    rules = list(rules)
    fn = match_indexed if matcher == "indexed" else match_reference
    matches, unknowns, operations = fn(rules, report.findings, aliases)
    # Duplicate identity is matching semantics, independent of metadata and expiry.
    signatures = defaultdict(list)
    for rule in rules:
        signature = (tuple(sorted((aliases or {}).get(rule.advisory, {rule.advisory}))),
                     rule.package, rule.path, rule.ecosystem, rule.version, rule.source_dir)
        signatures[signature].append(rule.key)
    rows = []
    for i, rule in enumerate(rules):
        matched = [report.findings[position] for position in matches[i]]
        packages = sorted({(f.ecosystem or "", f.package) for f in matched if f.package is not None})
        missing_package = any(f.package is None for f in matched)
        status = []
        if not matches[i]:
            status.append("orphan_candidate" if report.coverage == "asserted_unfiltered" and not unknowns[i]
                          else "coverage_unknown")
        if unknowns[i]:
            status.append("selector_evidence_unknown")
        signature = (tuple(sorted((aliases or {}).get(rule.advisory, {rule.advisory}))),
                     rule.package, rule.path, rule.ecosystem, rule.version, rule.source_dir)
        duplicates = [key for key in signatures[signature] if key != rule.key]
        if duplicates:
            status.append("duplicate")
        days = (rule.expires - as_of).days if rule.expires else None
        if days is not None:
            if days < 0:
                status.append("expired")
            elif days <= soon_days:
                status.append("soon_expiring")
        if not rule.reason:
            status.append("missing_reason")
        if not rule.owner:
            status.append("missing_owner")
        if len(packages) > 1:
            status.append("overly_broad")
        if missing_package:
            status.append("package_breadth_unknown")
        rows.append({"key": rule.key, "rule": rule.advisory, "expires": rule.expires.isoformat() if rule.expires else None,
                     "daysUntilExpiry": days, "hasReason": bool(rule.reason), "hasOwner": bool(rule.owner),
                     "selectors": {field: getattr(rule, field) for field in ("package", "path", "ecosystem", "version", "source_dir")
                                   if getattr(rule, field) is not None},
                     "status": status, "matchCount": len(matches[i]), "unknownMatchCount": len(unknowns[i]),
                     "matchedFindings": [f.locator or f"finding:{pos}" for f, pos in zip(matched, matches[i])],
                     "matchedPackages": [{"ecosystem": eco or None, "name": name} for eco, name in packages],
                     "duplicateOf": duplicates})
    counts = Counter(status for row in rows for status in row["status"])
    return {"schemaVersion": 1, "tool": "ignore-audit", "asOf": as_of.isoformat(), "soonDays": soon_days,
            "expiryConvention": "date-inclusive; expired when expiry < asOf (UTC calendar dates)",
            "coverage": report.coverage, "reportUnfilteredAcknowledged": True,
            "notes": list(report.notes), "uninterpretedFields": list(report.uninterpreted_fields),
            "summary": {"ruleCount": len(rules), "findingCount": len(report.findings), "statusCounts": dict(sorted(counts.items()))},
            "rules": rows, "matcher": {"name": matcher, "operations": operations}}


def markdown(result):
    def cell(value):
        return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("|", "&#124;").replace("`", "&#96;").replace("\n", " ")
    lines = ["# Ignore audit", "", f"As of {result['asOf']} (UTC). Coverage: {result['coverage']}.", "",
             "Orphans are candidates within this report, never certified unused rules.", "",
             "| Locator | Advisory | Matches | Unknown | Expiry | Status |", "| --- | --- | ---: | ---: | --- | --- |"]
    for row in result["rules"]:
        lines.append("| " + " | ".join(cell(v) for v in [row["key"], row["rule"], row["matchCount"], row["unknownMatchCount"],
                                                        row["expires"] or "—", ", ".join(row["status"]) or "ok"]) + " |")
    lines.extend(["", "## Evidence", "", "```json", __import__("json").dumps(result.get("provenance", {}), indent=2, sort_keys=True), "```", ""])
    lines.extend(["- " + cell(note) for note in result["notes"]])
    lines.extend(["", "Uninterpreted descriptive fields: " + cell(", ".join(result["uninterpretedFields"]) or "none"), ""])
    return "\n".join(lines)
