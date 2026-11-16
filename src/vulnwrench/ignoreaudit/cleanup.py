"""Review-only cleanup suggestions derived from an already validated audit."""
from html import escape
import json

from .inputs import digest


# Each group has an independent trigger. A rule can require several manual reviews.
SUGGESTIONS = (
    ("expired", "expired",
     "Ask the exception owner to reassess the expiry; manually remove or renew only after checking current policy and scan evidence.",
     "Expiry is the inclusive UTC audit-date convention; expired rules still match and native suppression activity is not evaluated."),
    ("ownerless", "missing_owner",
     "Identify an accountable owner and record it in the hash-bound metadata sidecar before deciding whether to retain the exception.",
     "No owner is recorded in the supplied metadata; this does not establish that the organization has no owner."),
    ("broad", "overly_broad",
     "Review the matched packages with the owner; if the scope is unintended, manually narrow it using supported native scanner configuration.",
     "More than one distinct known (ecosystem, package name) pair matched; breadth alone does not establish incorrect policy and unknown names are not counted."),
    ("report_local_orphans", "orphan_candidate",
     "Verify report scope, alias equivalence and coverage with the owner; consider manual removal only if independent evidence confirms the exception is no longer needed.",
     "No supplied observation matches and no required selector evidence is unknown; acknowledged unfiltered coverage is a caller assertion, not scanner attestation."),
)


def cleanup_plan(result, raw_rules, rule_format):
    """Project CLI audit output; source references resolve against retained bytes.

    Reference the entire exact document plus a native locator instead of
    reserializing rules (which would lose comments, whitespace and TOML spelling,
    or disclose private reasons). No TOML source-span parser is implied.
    """
    source = {"rulesSha256": digest(raw_rules), "rulesByteLength": len(raw_rules), "format": rule_format,
              "locatorConvention": "utf8_splitlines_1_based" if rule_format == "trivy" else "toml_IgnoredVulns_index_0_based"}
    assumptions = [
        "Only this supplied report, audit date and configured scope are considered; other targets, versions, scanner databases and times are not covered.",
        "Advisory equivalence uses exact IDs or the explicit local alias map only; report-declared aliases are descriptive, so validate native alias behavior before any removal.",
        "Retain the complete original rules bytes and report; verify their provenance hashes before resolving locators or taking manual action.",
    ]
    groups = {group: [] for group, *_ in SUGGESTIONS}
    excluded, candidate_keys = [], set()
    for row in result["rules"]:
        reference = {**source, "locator": row["key"]}
        for group, trigger, action, assumption in SUGGESTIONS:
            if trigger in row["status"]:
                groups[group].append({"rule": row, "sourceReference": reference,
                                      "suggestedManualAction": action, "assumptions": [assumption, *assumptions],
                                      "definiteRemovalRecommended": False})
                candidate_keys.add(row["key"])
        if row["matchCount"] == 0 and "orphan_candidate" not in row["status"]:
            excluded.append({"key": row["key"], "sourceReference": reference,
                             "reasons": [flag for flag in row["status"] if flag in {"coverage_unknown", "selector_evidence_unknown"}],
                             "suggestedManualAction": "Obtain complete unfiltered scan coverage and required selector evidence before considering report-local orphan review.",
                             "assumptions": ["Missing observations or selector evidence cannot establish absence of matches.", *assumptions],
                             "definiteRemovalRecommended": False})
    output = {key: result[key] for key in ("schemaVersion", "tool", "asOf", "soonDays", "expiryConvention", "coverage",
                                          "reportUnfilteredAcknowledged", "notes", "uninterpretedFields", "provenance")}
    output.update(command="cleanup-plan", reviewOnly=True, automaticChangesAllowed=False, unusedRuleAssertionAllowed=False,
                  sourceResolution="Retain the complete --rules file unchanged. Verify rulesSha256 and rulesByteLength against its raw bytes. Resolve line:N using UTF-8 splitlines()[N-1], or IgnoredVulns:N using the parsed TOML IgnoredVulns[N]. References bind the full original document, not reconstructed rule text or isolated byte spans.",
                  summary={**result["summary"], "candidateRuleCount": len(candidate_keys),
                           "groupCounts": {group: len(candidates) for group, candidates in groups.items()},
                           "orphanReviewExcludedCount": len(excluded)},
                  groups=groups, excludedFromOrphanReview=excluded)
    return output


def cleanup_markdown(plan):
    """Render the same plan, retaining evidence and all manual-review caveats."""
    def text(value):
        return "".join(f"&#{ord(char)};" if char in "\\`*_[]()#|~" else
                       " " if char in "\r\n" else escape(char, quote=False) for char in str(value))

    def evidence(value):
        # Keep valid, reversible JSON while preventing input strings from closing
        # a Markdown fence or introducing raw HTML in downstream renderers.
        encoded = json.dumps(value, indent=2, ensure_ascii=True, sort_keys=True)
        for char in "`<>&":
            encoded = encoded.replace(char, f"\\u{ord(char):04x}")
        return ["```json", encoded, "```", ""]

    def entry(candidate, excluded=False):
        ref = candidate["sourceReference"]
        heading = candidate["key"] if excluded else candidate["rule"]["key"] + " — " + candidate["rule"]["rule"]
        lines = [f"### {text(heading)}", "",
                 f"- Source reference: sha256:{ref['rulesSha256']}#{text(ref['locator'])} "
                 f"({ref['rulesByteLength']} bytes; format: {text(ref['format'])}; "
                 f"locator convention: {text(ref['locatorConvention'])}).",
                 "- Suggested manual action: " + text(candidate["suggestedManualAction"]),
                 "- definiteRemovalRecommended: " + str(candidate["definiteRemovalRecommended"]).lower()]
        if excluded:
            lines.append("- Reasons: " + text(", ".join(candidate["reasons"])))
        lines.extend(["", "Assumptions:", "", *["- " + text(a) for a in candidate["assumptions"]], ""])
        if not excluded:
            lines.extend(["Audit rule evidence:", "", *evidence(candidate["rule"])])
        return lines

    context = {key: value for key, value in plan.items()
               if key not in {"groups", "excludedFromOrphanReview", "sourceResolution"}}
    lines = ["# Ignore cleanup plan", "",
             "Manual review only. Orphans are report-local candidates, never certified unused rules.", "",
             "## Context", "", *evidence(context),
             "## Source resolution", "", text(plan["sourceResolution"]), ""]
    for group, candidates in plan["groups"].items():
        lines.extend([f"## {group} ({len(candidates)})", ""])
        for candidate in candidates:
            lines.extend(entry(candidate))
        if not candidates:
            lines.extend(["None.", ""])
    excluded = plan["excludedFromOrphanReview"]
    lines.extend([f"## excludedFromOrphanReview ({len(excluded)})", ""])
    for candidate in excluded:
        lines.extend(entry(candidate, excluded=True))
    if not excluded:
        lines.extend(["None.", ""])
    return "\n".join(lines)
