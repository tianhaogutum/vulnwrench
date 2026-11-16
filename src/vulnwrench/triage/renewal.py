"""Offline, review-only comparison. Never emits artifacts or applies exception policy."""
from __future__ import annotations

from .compiler import digest, json_bytes
from .model import Decision, _parse_decisions, fail, parse_date
from .report_baseline import report_decision_document


_ACTIONS = {
    "expired": "review_expired_exception",
    "expiring_soon": "review_expiring_exception",
    "owner_missing": "assign_owner_for_review",
    "owner_changed": "confirm_owner_handoff",
    "scope_changed": "reassess_changed_scope",
    "policy_changed": "review_policy_change",
    "source_refs_changed": "review_source_references",
    "added": "review_new_exception",
    "removed": "confirm_removal_and_withdraw_stale_outputs",
}
_UNSET = object()


def preview_renewal(prior: object, *, as_of: str, prior_as_of: str | None = None,
                    prior_format: str = "decisions", current: object = _UNSET,
                    expiring_within_days: int = 30) -> dict:
    """Compare v1 decisions or a validated report baseline by stable decisionId.

    Missing owners and expired decisions in decision documents are findings.
    Reports must be valid at their archived compilation date. Other fields use
    the compile input validation. Returned JSON is a review
    plan, not a decision document or an assertion of exploitability.
    """
    if prior_format not in ("decisions", "conversion-report"):
        fail("E_INPUT", "prior-format must be decisions or conversion-report")
    report_document = None
    if prior_format == "conversion-report":
        report_document = report_decision_document(prior)
        archived_day = prior["parameters"]["asOf"]
        if prior_as_of is not None and parse_date(prior_as_of, "prior-as-of").isoformat() != archived_day:
            fail("E_DATE", "prior-as-of must match the archived report asOf")
        prior_as_of = archived_day
    prior_day = parse_date(prior_as_of, "prior-as-of")
    day = parse_date(as_of, "as-of")
    if day < prior_day:
        fail("E_DATE", "as-of must not precede prior-as-of")
    if type(expiring_within_days) is not int or not 0 <= expiring_within_days <= 3660:
        fail("E_INPUT", "expiring-within-days must be an integer between 0 and 3660")

    def read(document):
        decisions = _parse_decisions(document, require_owner=False)
        if any(d.decision_id is None for d in decisions):
            fail("E_RENEWAL_ID", "renewal preview requires an explicit decisionId on every record")
        sha = digest(json_bytes(document))
        return sha, {d.decision_id: (
            {"canonicalJsonSha256": sha, "decisionIndex": i, "pointer": f"/decisions/{i}"}, d)
            for i, d in enumerate(decisions)}

    prior_sha, previous = read(report_document if report_document is not None else prior)
    sources = {}
    if report_document is not None:
        prior_sha = digest(json_bytes(prior))
        archived_sha = prior["source"]["canonicalJsonSha256"]
        sources["priorArchivedSourceCanonicalJsonSha256"] = archived_sha
        for pos, (source, _) in enumerate(previous.values()):
            index = prior["decisions"][pos]["index"]
            source.update(canonicalJsonSha256=prior_sha, decisionIndex=index,
                          pointer=f"/decisions/{pos}/record",
                          archivedSourceCanonicalJsonSha256=archived_sha,
                          archivedSourcePointer=f"/decisions/{index}")
    current_supplied = current is not _UNSET
    if current_supplied:
        current_sha, candidates = read(current)
    else:
        current_sha, candidates = prior_sha, previous
        if report_document is not None:
            sources["currentArchivedSourceCanonicalJsonSha256"] = archived_sha

    def expiry(decision):
        remaining = (decision.expires_on - day).days
        if remaining <= 0:
            return "expired"
        return "expiring_soon" if remaining <= expiring_within_days else "active"

    def reference(item):
        if item is None:
            return None
        source, decision = item
        return {"source": dict(source), "record": decision.as_record()}

    def policy(decision: Decision):
        return (decision.reason, decision.expires_on, decision.status,
                decision.justification, decision.impact_statement, decision.action_statement)

    entries = []
    # Preserve prior order; append added records in their current document order.
    for decision_id in dict.fromkeys([*previous, *candidates]):
        old_item, new_item = previous.get(decision_id), candidates.get(decision_id)
        old = old_item[1] if old_item else None
        new = new_item[1] if new_item else None
        baseline = old if old is not None else new
        expiry_status = expiry(baseline)
        current_expiry = expiry(new) if new is not None else None
        statuses = []
        if expiry_status != "active":
            statuses.append(expiry_status)
        # A candidate can shorten validity as well as propose an extension.
        if current_expiry not in (None, "active", expiry_status):
            statuses.append("current_" + current_expiry)
        if (new if new is not None else old).owner is None:
            statuses.append("owner_missing")
        if old is not None and new is not None:
            if new.owner is not None and old.owner != new.owner:
                statuses.append("owner_changed")
            if (old.package, old.vulnerabilities) != (new.package, new.vulnerabilities):
                statuses.append("scope_changed")
            if policy(old) != policy(new):
                statuses.append("policy_changed")
            if old.source_refs != new.source_refs:
                statuses.append("source_refs_changed")
        elif old is None:
            statuses.append("added")
        else:
            statuses.append("removed")
        actions = [_ACTIONS[s.removeprefix("current_")] for s in statuses]
        entries.append({
            "decisionId": decision_id, "expiryStatus": expiry_status,
            "currentExpiryStatus": current_expiry, "statuses": statuses or ["unchanged"],
            "reviewRequired": bool(statuses), "actions": list(dict.fromkeys(actions)),
            "prior": reference(old_item), "current": reference(new_item),
        })
    return {
        "schemaVersion": 1, "tool": "triage-bridge", "toolVersion": "0.1.0",
        "mode": "review_only", "automaticActions": [],
        "parameters": {"priorAsOf": prior_day.isoformat(), "asOf": day.isoformat(),
                       "expiringWithinDays": expiring_within_days,
                       "currentSupplied": current_supplied},
        "sources": {"priorCanonicalJsonSha256": prior_sha,
                    "currentCanonicalJsonSha256": current_sha, **sources},
        "counts": {"decisions": len(entries),
                   "reviewRequired": sum(e["reviewRequired"] for e in entries)},
        "decisions": entries,
        "warnings": [
            "Review plan only: no exception was renewed, approved, suppressed or compiled; no OpenVEX assertion was issued.",
            "Expiry uses the first invalid UTC day. A candidate extension does not clear the prior expiry finding.",
            "Decision IDs and source references are supplied by the caller; content digests are not authenticated provenance.",
            "Existing scanner and OpenVEX artifacts are not withdrawn or modified by this preview.",
        ],
    }
