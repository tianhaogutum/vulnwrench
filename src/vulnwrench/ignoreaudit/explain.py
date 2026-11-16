"""Deterministic per-observation evidence for one selected rule."""
from .audit import audit, relation, selector_value
from .inputs import string
from .model import InputError


def explain(rules, report, rule_key, *, as_of, report_unfiltered=False, soon_days=30, aliases=None):
    """Explain every observation, including definite mismatches and missing evidence.

    Evidence IDs are report-order coordinates, qualified by reportSha256 in CLI
    provenance. They distinguish duplicate observations and are stable for fixed
    inputs, not identities across reordered or modified reports.
    """
    rules = list(rules)
    string(rule_key, "selected rule locator")
    result = audit(rules, report, as_of=as_of, report_unfiltered=report_unfiltered,
                   soon_days=soon_days, aliases=aliases)
    selected = next((i for i, rule in enumerate(rules) if rule.key == rule_key), None)
    if selected is None:
        raise InputError("selected rule locator not found")
    rule = rules[selected]
    row = result["rules"][selected]
    aliases = {} if aliases is None else aliases
    accepted_ids = sorted(aliases.get(rule.advisory, {rule.advisory}))
    evidence, matched_ids, unknown_ids = [], [], []
    for index, finding in enumerate(report.findings):
        ident_outcome = ("exact_id" if finding.advisory == rule.advisory else
                         "explicit_alias" if finding.advisory in accepted_ids else "mismatch")
        checks = [{"selector": "advisory", "expected": rule.advisory, "actual": finding.advisory,
                   "acceptedIds": accepted_ids, "outcome": ident_outcome}]
        for field in ("package", "path", "ecosystem", "version", "source_dir"):
            expected, actual = getattr(rule, field), selector_value(finding, field)
            outcome = ("unrestricted" if expected is None else "unknown" if actual is None else
                       "match" if expected == actual else "mismatch")
            checks.append({"selector": field, "expected": expected, "actual": actual, "outcome": outcome})
        verdict = relation(rule, finding, aliases)
        decision = "match" if verdict is True else "no_match" if verdict is False else "unknown"
        if decision == "no_match":
            reasons = [check["selector"] + "_mismatch" for check in checks if check["outcome"] == "mismatch"]
        elif decision == "unknown":
            reasons = [check["selector"] + "_evidence_unknown" for check in checks if check["outcome"] == "unknown"]
        else:
            reasons = ["advisory_and_scope_match"]
        evidence_id = f"finding:{index}"
        if verdict is True:
            matched_ids.append(evidence_id)
        elif verdict is None:
            unknown_ids.append(evidence_id)
        evidence.append({"evidenceId": evidence_id, "locator": finding.locator or None,
                         "finding": {field: getattr(finding, field) for field in
                                     ("advisory", "package", "path", "ecosystem", "version")},
                         "decision": decision, "reasons": reasons, "checks": checks,
                         "reportAliasHints": [
                             {"aliases": list(hint.aliases), "locator": hint.locator, "trust": "untrusted",
                              "affectsMatching": False, "ruleAdvisoryListed": rule.advisory in hint.aliases}
                             for hint in finding.alias_hints]})
    days = row["daysUntilExpiry"]
    expiry_state = ("no_expiry" if days is None else "expired" if days < 0 else
                    "soon_expiring" if days <= soon_days else "active")
    output = {key: result[key] for key in ("schemaVersion", "tool", "asOf", "soonDays", "expiryConvention",
                                          "coverage", "reportUnfilteredAcknowledged", "notes", "uninterpretedFields")}
    output.update(command="explain", rule=row,
                  scope={"mode": "local_config_directory" if rule.source_dir is not None else "global",
                         "selectors": row["selectors"],
                         "directoryMatching": "exact_parent_nonrecursive" if rule.source_dir is not None else "unrestricted",
                         "selectorCombination": "AND; definite mismatches override missing evidence"},
                  expiry={"expires": row["expires"], "daysUntilExpiry": days, "state": expiry_state,
                          "affectsAuditMatching": False, "nativeSuppressionActivity": "not_evaluated"},
                  coverageAssumptions=[
                      "Unfiltered coverage is a caller assertion, not scanner attestation.",
                      "Absent/null OSV vulnerability collections make report coverage unknown, even with groups present.",
                      "Only supplied observations are evaluated; unknown coverage cannot justify an orphan candidate.",
                      "Aliases require explicit local groups; report-provided aliases are descriptive only.",
                      "Report alias hints are untrusted declarations; bound hints attach only to source observations and unbound group hints remain at report level. Neither changes checks, counts, coverage or orphan status.",
                      "Expiry is an inclusive UTC date-level audit convention; expired rules still match for auditing.",
                      "Global scope has no directory restriction; other exact selectors still apply. Local OSV scope is not recursive.",
                      "Evidence IDs follow report observation order; retain the original report and its CLI provenance digest.",
                      "No result certifies an unused rule across targets, scanner databases, versions or time."],
                  unusedRuleAssertionAllowed=False, matchedEvidenceIds=matched_ids, unknownEvidenceIds=unknown_ids,
                  coverageGaps=[{"locator": gap.locator, "state": gap.state} for gap in report.coverage_gaps],
                  unboundReportAliasHints=[
                      {"ids": list(hint.ids), "aliases": list(hint.aliases), "locator": hint.locator,
                       "reason": hint.reason, "trust": "untrusted", "affectsMatching": False,
                       "ruleAdvisoryListed": rule.advisory in hint.aliases}
                      for hint in report.unbound_alias_hints],
                  evidence=evidence)
    return output
