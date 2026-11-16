"""Conservative comparisons of caller-declared, byte-bound scan coverage.

These declarations are unverified assertions. Compatible metadata never proves
that an absent vulnerability was fixed or that scanner databases are equivalent.
"""

from datetime import datetime, timezone
import re

from .identity import InputError, text

_TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})")


def _timestamp(value):
    # A bounded RFC3339 profile: no naive dates, leap seconds or silent truncation.
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        raise InputError("coverage: expected RFC3339 database timestamp with timezone")
    try:
        offset = value[-6:] if not value.endswith("Z") else "+00:00"
        if int(offset[1:3]) > 23 or int(offset[4:]) > 59 or offset == "-00:00":
            raise ValueError
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, OverflowError):
        raise InputError("coverage: invalid database timestamp") from None


def manifest_entries(document, reports):
    """Validate the complete manifest before merging; reject stale/unused entries."""
    if (not isinstance(document, dict) or set(document) != {"schemaVersion", "inputs"}
            or document["schemaVersion"] != "vulnfuse-coverage-1" or not isinstance(document["inputs"], list)):
        raise InputError("coverage: unsupported manifest schema")
    report_keys = {(r.scanner, r.input_name, r.sha256) for r in reports}
    entries = {}
    required = {"scanner", "input", "sha256"}
    allowed = required | {"targetIdentity", "scanComplete", "databaseTimestamp", "scanPolicyIdentity", "databaseIdentity"}
    for index, entry in enumerate(document["inputs"]):
        if not isinstance(entry, dict) or not required <= set(entry) or set(entry) - allowed:
            raise InputError("coverage: invalid manifest entry fields")
        scanner, name, digest = (text(entry[k]) for k in ("scanner", "input", "sha256"))
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise InputError("coverage: invalid SHA-256")
        key = (scanner, name, digest)
        if key not in report_keys:
            raise InputError("coverage: entry does not match a supplied input and its SHA-256")
        if key in entries:
            raise InputError("coverage: duplicate input entry")
        target, complete, timestamp = (entry.get(k) for k in ("targetIdentity", "scanComplete", "databaseTimestamp"))
        if target is not None:
            text(target)
        if entry.get("scanPolicyIdentity") is not None:
            text(entry["scanPolicyIdentity"])
        if entry.get("databaseIdentity") is not None:
            text(entry["databaseIdentity"])
        if complete is not None and not isinstance(complete, bool):
            raise InputError("coverage: scanComplete must be boolean or null")
        if timestamp is not None:
            _timestamp(timestamp)
        entries[key] = (f"/inputs/{index}", entry)
    return entries


def source_coverage(report, entries):
    declaration = None if entries is None else entries.get((report.scanner, report.input_name, report.sha256))
    pointer, entry = declaration if declaration is not None else (None, {})
    target, complete, timestamp = (entry.get(k) for k in ("targetIdentity", "scanComplete", "databaseTimestamp"))
    policy = entry.get("scanPolicyIdentity")
    database = entry.get("databaseIdentity")
    reasons = []
    if declaration is None:
        reasons.append("manifest-not-supplied" if entries is None else "manifest-entry-missing")
    else:
        if target is None:
            reasons.append("target-identity-missing")
        if complete is not True:
            reasons.append("scan-incomplete" if complete is False else "scan-completion-unknown")
        if timestamp is None:
            reasons.append("database-timestamp-missing")
        if policy is None:
            reasons.append("scan-policy-identity-missing")
        if database is None:
            reasons.append("database-identity-missing")
    return {"status": "unknown" if declaration is None else "declared", "reasonCodes": sorted(reasons),
            "targetIdentity": target, "scanComplete": complete, "databaseTimestamp": timestamp,
            "scanPolicyIdentity": policy, "databaseIdentity": database,
            "manifestPointer": pointer}


def _pair(left, right):
    reasons = set(left["reasonCodes"]) | set(right["reasonCodes"])
    if left["targetIdentity"] is not None and right["targetIdentity"] is not None and left["targetIdentity"] != right["targetIdentity"]:
        reasons.add("target-mismatch")
    if (left["databaseTimestamp"] is not None and right["databaseTimestamp"] is not None
            and _timestamp(left["databaseTimestamp"]) != _timestamp(right["databaseTimestamp"])):
        reasons.add("database-timestamp-mismatch")
    if (left["scanPolicyIdentity"] is not None and right["scanPolicyIdentity"] is not None
            and left["scanPolicyIdentity"] != right["scanPolicyIdentity"]):
        reasons.add("scan-policy-mismatch")
    if (left["databaseIdentity"] is not None and right["databaseIdentity"] is not None
            and left["databaseIdentity"] != right["databaseIdentity"]):
        reasons.add("database-identity-mismatch")
    return {"status": _status(reasons), "reasonCodes": sorted(reasons)}


def _status(reasons):
    if set(reasons) & {"target-mismatch", "scan-incomplete", "database-timestamp-mismatch", "scan-policy-mismatch",
                       "database-identity-mismatch"}:
        return "incomparable"
    return "unknown" if reasons else "comparable"


def coverage_assessment(sources):
    """Surface declared differences even when no findings exist to compare."""
    coverages = [s["coverage"] for s in sources]
    reasons = {r for c in coverages for r in c["reasonCodes"]}
    targets = {c["targetIdentity"] for c in coverages if c["targetIdentity"] is not None}
    dates = {_timestamp(c["databaseTimestamp"]) for c in coverages if c["databaseTimestamp"] is not None}
    policies = {c["scanPolicyIdentity"] for c in coverages if c["scanPolicyIdentity"] is not None}
    databases = {c["databaseIdentity"] for c in coverages if c["databaseIdentity"] is not None}
    if len(targets) > 1:
        reasons.add("target-mismatch")
    if len(dates) > 1:
        reasons.add("database-timestamp-mismatch")
    if len(policies) > 1:
        reasons.add("scan-policy-mismatch")
    if len(databases) > 1:
        reasons.add("database-identity-mismatch")
    return {"status": _status(reasons), "reasonCodes": sorted(reasons)}


def absence_assessments(sources, group):
    observed_ids = {o["sourceId"] for o in group}
    observed = [s for s in sources if s["sourceId"] in observed_ids]
    result = {}
    for source in sources:
        if source["sourceId"] in observed_ids:
            continue
        comparisons = [{"sourceId": other["sourceId"], **_pair(source["coverage"], other["coverage"])} for other in observed]
        reasons = {r for c in comparisons for r in c["reasonCodes"]}
        result[source["sourceId"]] = {"status": _status(reasons), "reasonCodes": sorted(reasons),
                                      "canEstablishFixed": False, "comparedTo": comparisons}
    return result
