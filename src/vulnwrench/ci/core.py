"""The ``ci`` pipeline: fuse -> baseline -> exceptions -> exploitability.

Every decision is made by an existing library: ``fuse.merge_reports`` dedupes and joins
aliases (current and baseline reports are merged together, so a baseline finding joins a
current one through the same alias graph), ``ignoreaudit.audit`` matches and audits the
exception files, and ``exploitgate.evaluate_findings`` applies the EPSS/KEV policy. This
module only routes findings between them and counts what each stage removed.
"""
from __future__ import annotations

from datetime import date
import json

from ..exploitgate.adapters import Finding as ExploitFinding
from ..exploitgate.core import evaluate_findings
from ..fuse import Report, merge_reports, read_merged, read_report
from ..ignoreaudit import Finding as RuleFinding, Report as RuleReport, audit, load_rules
from ..ignoreaudit.inputs import ID as RULE_ID, read_bytes

BASELINE = "baseline:"  # input-name prefix that marks baseline sources inside the joint merge
DEFAULT_POLICY = {"epssThreshold": 0.1, "blockKev": True, "maxAgeDays": 7, "missing": "unknown"}
STALE = ("expired", "orphan_candidate", "soon_expiring", "overly_broad", "duplicate")
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE")
FAIL_ON = {"exploitable": {"action"}, "unknown": {"action", "unknown"},
           "new": {"action", "unknown", "low"}, "none": set()}


def load_current(inputs: list[tuple[str, str]]) -> list[Report]:
    """(scanner, path) pairs -> fuse Reports, read with fuse's strict bounded reader."""
    return [read_report(scanner, path) for scanner, path in inputs]


def load_baseline(path: str | None) -> list[Report]:
    """A saved ``vulnwrench fuse merge`` file -> its embedded raw reports, tagged as baseline."""
    if path is None:
        return []
    merged = read_merged(path)  # full consistency check against the embedded evidence
    return [Report(s["scanner"], s["rawReport"], BASELINE + s["input"], s["sha256"], s["byteCount"],
                   s["digestKind"]) for s in merged["inputs"]]


def exception_format(path: str) -> str:
    return "osv" if path.endswith(".toml") else "trivy"


def load_exceptions(paths: list[str]) -> list[tuple[str, str, list]]:
    return [(path, exception_format(path), load_rules(read_bytes(path), exception_format(path))) for path in paths]


def _primary(ids: list[str]) -> str:
    cves = [i for i in ids if i.upper().startswith("CVE-")]
    return (cves or ids)[0]


def _severity(values: list[str]) -> str | None:
    return next((s for s in SEVERITY_ORDER if s in values), None)


def _rows(merged: dict) -> tuple[list[dict], list[dict]]:
    side = {s["sourceId"]: "baseline" if s["input"].startswith(BASELINE) else "current" for s in merged["inputs"]}
    current, gone = [], []
    for f in merged["findings"]:
        now = [o for o in f["observations"] if side[o["sourceId"]] == "current"]
        before = any(side[o["sourceId"]] == "baseline" for o in f["observations"])
        package = f["package"]
        row = {"findingId": f["findingId"], "package": package["identity"] or f"{package['reportedName']}@{package['version']}",
               "packageKnown": package["identity"] is not None, "advisory": _primary(f["ids"]), "ids": f["ids"],
               "scanners": sorted({o["scanner"] for o in now}), "observations": len(now),
               # Relative paths (lockfiles, targets) first: they are what a reviewer recognises.
               "paths": sorted({p for o in now for p in o["paths"]}, key=lambda p: (p.startswith("/"), p)),
               "severity": _severity(f["severityValues"]), "severityValues": f["severityValues"],
               "fixVersions": f["fixVersions"], "fixConflict": f["fixConflict"],
               "baseline": "known" if before else "new", "_obs": now}
        (current if now else gone).append(row)
    return current, gone


def _apply_exceptions(rows, exceptions, *, as_of, unfiltered, soon_days, report_for):
    """Run ignoreaudit.audit per exception file over the current observations."""
    findings, owner = [], {}
    for row in rows:
        for o in row["_obs"]:
            if not RULE_ID.fullmatch(o["originalId"]):
                continue  # no rule can name an ID outside ignoreaudit's exact-ID grammar
            locator = o["observationId"]
            owner[locator] = row["findingId"]
            pkg = o["package"]
            findings.append(RuleFinding(o["originalId"], pkg["reportedName"] or pkg["name"], None,
                                        pkg["reportedEcosystem"], pkg["version"], locator))
    report = RuleReport(tuple(findings), "asserted_unfiltered" if unfiltered else "unknown")
    suppressed, expired_on, stale, hygiene = {}, {}, [], {"rules": 0, "missingReason": 0, "missingOwner": 0, "unverifiedOrphans": 0}
    for path, fmt, rules in exceptions:
        result = audit(rules, report, as_of=as_of, report_unfiltered=True, soon_days=soon_days)
        for rule in result["rules"]:
            hygiene["rules"] += 1
            hygiene["missingReason"] += "missing_reason" in rule["status"]
            hygiene["missingOwner"] += "missing_owner" in rule["status"]
            matched = sorted({owner[locator] for locator in rule["matchedFindings"]})
            label = f"{path}:{rule['key']}"
            active = rule["daysUntilExpiry"] is None or rule["daysUntilExpiry"] >= 0
            for finding_id in matched:
                (suppressed if active else expired_on).setdefault(finding_id, []).append(label)
            status = [s for s in rule["status"] if s in STALE]
            hygiene["unverifiedOrphans"] += "coverage_unknown" in rule["status"]
            if not status:
                continue
            report_path = report_for.get(fmt)
            verb = "cleanup-plan" if "orphan_candidate" in status else "explain"
            command = None
            if report_path is not None:
                command = ["vulnwrench", "ignores", verb, "--format", fmt, "--rules", path, "--report", report_path,
                           "--report-unfiltered", "--as-of", as_of.isoformat()]
                command += ["--rule-key", rule["key"]] if verb == "explain" else ["--output-format", "markdown"]
            stale.append({"file": path, "format": fmt, "key": rule["key"], "rule": rule["rule"],
                          "expires": rule["expires"], "daysUntilExpiry": rule["daysUntilExpiry"], "status": status,
                          "matches": matched, "command": command})
    return suppressed, expired_on, stale, hygiene


def _exploit(rows, *, epss, kev, as_of, policy, aliases):
    findings = [ExploitFinding(row["advisory"], tuple(i for i in row["ids"] if i != row["advisory"]),
                               {"name": row["package"]}, (row["paths"] or [None])[0], row["findingId"])
                for row in rows]
    raw = None if policy else json.dumps(DEFAULT_POLICY).encode()
    result = evaluate_findings(findings, epss=epss, kev=kev, as_of=as_of.isoformat(), policy=policy or "default",
                               policy_raw=raw, aliases=aliases, source_format="vulnwrench-fuse")
    return result, {f["sourcePointer"]: f for f in result["findings"]}


def run(current: list[Report], baseline: list[Report], exceptions: list, *, as_of: date,
        scanner_args: list[tuple[str, str]], unfiltered: bool = False, soon_days: int = 30,
        epss: str | None = None, kev: str | None = None, policy: str | None = None,
        aliases: str | None = None, fail_on: str = "exploitable") -> dict:
    merged = merge_reports([*current, *baseline])
    rows, gone = _rows(merged)
    report_for = {}
    for scanner, path in scanner_args:
        report_for.setdefault(scanner, path)
    suppressed, expired_on, stale, hygiene = _apply_exceptions(
        rows, exceptions, as_of=as_of, unfiltered=unfiltered, soon_days=soon_days, report_for=report_for)
    exploit = decisions = None
    if epss is not None and kev is not None:
        exploit, decisions = _exploit(rows, epss=epss, kev=kev, as_of=as_of, policy=policy, aliases=aliases)
    flags = [arg for scanner, path in scanner_args for arg in (f"--{scanner}", path)]
    for row in rows:
        row.pop("_obs")
        row["suppressedBy"] = suppressed.get(row["findingId"], [])
        row["expiredExceptions"] = expired_on.get(row["findingId"], [])
        evidence = decisions.get(row["findingId"]) if decisions else None
        row["exploit"] = None if evidence is None else {
            "decision": evidence["decision"], "reasons": evidence["reasons"], "matchedCves": evidence["matchedCves"],
            "epss": max((m["epss"] for m in evidence["matches"] if m["epss"] is not None), default=None),
            "kev": any(m["kev"] for m in evidence["matches"])}
        if row["baseline"] == "known":
            row["outcome"] = "baseline"
        elif row["suppressedBy"]:
            row["outcome"] = "suppressed"
        elif evidence is None:
            row["outcome"] = "action"  # no EPSS/KEV supplied: fail closed, every new finding counts
        else:
            row["outcome"] = {"block": "action", "unknown": "unknown", "pass": "low"}[evidence["decision"]]
        row["command"] = ["vulnwrench", "fuse", "explain", *flags, "--advisory", row["advisory"],
                          *(["--package", row["package"]] if row["packageKnown"] else [])]
    for row in gone:
        row.pop("_obs")
    count = lambda outcome: sum(r["outcome"] == outcome for r in rows)  # noqa: E731
    new = [r for r in rows if r["outcome"] != "baseline"]
    funnel = {"rawFindings": sum(r["observations"] for r in rows), "scanners": sorted({r.scanner for r in current}),
              "reports": len(current), "fused": len(rows), "new": len(new),
              "unsuppressed": len(new) - count("suppressed"), "needAction": count("action"),
              "unknown": count("unknown"), "low": count("low"), "suppressed": count("suppressed"),
              "baselineKnown": count("baseline"), "baselineGone": len(gone)}
    # A stale or future-dated EPSS/KEV snapshot turns decisions into "unknown"; never let that pass quietly.
    stale_snapshots = sorted(name for name, snap in (exploit["provenance"]["snapshots"] if exploit else {}).items()
                             if snap["status"] != "fresh")
    gated = FAIL_ON[fail_on] | ({"unknown"} if stale_snapshots and fail_on != "none" else set())
    failing = sum(r["outcome"] in gated for r in rows)
    order = {"action": 0, "unknown": 1, "low": 2, "suppressed": 3, "baseline": 4}
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    rows.sort(key=lambda r: (order[r["outcome"]], not (r["exploit"] or {}).get("kev"),
                             -((r["exploit"] or {}).get("epss") or 0),
                             rank.get(r["severity"], 9), r["package"], r["advisory"]))
    return {"funnel": funnel, "findings": rows, "baselineGone": gone, "staleExceptions": stale,
            "exceptionHygiene": hygiene, "noticeNotFixed": merged["notice"],
            "exploit": None if exploit is None else {"policy": exploit["policy"],
                                                      "snapshots": exploit["provenance"]["snapshots"]},
            "gate": {"failOn": fail_on, "failing": failing, "staleSnapshots": stale_snapshots, "status": "failed" if failing else "passed",
                     "exitCode": int(bool(failing))}}
