"""Explicit review of a native import, with content-bound decision references."""
from __future__ import annotations

from .compiler import digest, json_bytes
from .import_trivy import import_trivy_ignore
from .model import BridgeError, fail, object_fields, parse_date, parse_decisions, text


def _invalid():
    fail("E_FINALIZE", "invalid or incomplete import review; see finalize-import contract")


def _canonical(value: object) -> bytes:
    try:
        return json_bytes(value)
    except (TypeError, ValueError, UnicodeError, RecursionError):
        _invalid()


def _approved_indices(review: dict, count: int) -> set[int]:
    if "approvedDecisionIndices" in review:
        # Legacy reviews still explicitly approve every original slot.
        indices = review["approvedDecisionIndices"]
        if (not isinstance(indices, list) or any(type(i) is not int for i in indices)
                or sorted(indices) != list(range(count))):
            _invalid()
        return set(indices)
    dispositions = review["decisionDispositions"]
    if not isinstance(dispositions, list) or len(dispositions) != count:
        _invalid()
    seen, approved = set(), set()
    for row in dispositions:
        if not isinstance(row, dict):
            _invalid()
        index, disposition = row.get("decisionIndex"), row.get("disposition")
        if type(index) is not int or not 0 <= index < count or index in seen:
            _invalid()
        seen.add(index)
        if disposition == "approve" and set(row) == {"decisionIndex", "disposition"}:
            approved.add(index)
        elif disposition == "exclude" and set(row) == {"decisionIndex", "disposition", "reason"}:
            try:
                text(row["reason"], "draft exclusion reason")
            except BridgeError:
                _invalid()
        else:
            _invalid()
    return approved


def finalize_import(draft: object, *, source: bytes, review: object, as_of: str) -> dict:
    """Validate an original draft and explicit completed review; perform no I/O.

    Every original record requires approval or reasoned exclusion. Unsupported
    findings require separate exclusions; they never become decisions. Supplied
    native policy is immutable, and excluded slots retain the original draft row.
    Missing native values and explicit status/evidence are supplied by the reviewer.
    Content references identify local inputs, not authenticated authorship or truth.
    """
    original = import_trivy_ignore(source)
    if _canonical(draft) != json_bytes(original):
        fail("E_FINALIZE", "draft does not match the supplied native source")
    fields = {"schemaVersion", "decisionDocument", "unsupportedDispositions"}
    if (not isinstance(review, dict) or set(review) not in (
            fields | {"approvedDecisionIndices"}, fields | {"decisionDispositions"})
            or type(review["schemaVersion"]) is not int or review["schemaVersion"] != 1):
        _invalid()
    review_sha = digest(_canonical(review))
    native_records = original["decisionDocument"]["decisions"]
    approved = _approved_indices(review, len(native_records))
    dispositions = review["unsupportedDispositions"]
    if not isinstance(dispositions, list):
        _invalid()
    pointers = []
    for disposition in dispositions:
        if (not isinstance(disposition, dict)
                or set(disposition) != {"pointer", "disposition", "reason"}
                or not isinstance(disposition["pointer"], str)
                or disposition["disposition"] != "exclude"):
            _invalid()
        # Use the shared text profile but retain a distinct workflow error code.
        try:
            text(disposition["reason"], "unsupported disposition reason")
        except BridgeError:
            _invalid()
        pointers.append(disposition["pointer"])
    if sorted(pointers) != sorted(row["pointer"] for row in original["unsupported"]):
        _invalid()

    document = review["decisionDocument"]
    root = object_fields(document, {"schemaVersion", "decisions"}, {"decisions"}, "document")
    records = root["decisions"]
    if not isinstance(records, list) or len(records) != len(native_records):
        fail("E_FINALIZE", "review must retain every draft record in source order")
    for i, (native, completed) in enumerate(zip(native_records, records)):
        if i not in approved:
            if _canonical(completed) != json_bytes(native):
                fail("E_FINALIZE", "excluded review slots must retain the original draft record")
            continue
        if not isinstance(completed, dict):
            _invalid()
        for key in ("ids", "package", "reason", "expiresOn"):
            if native[key] is not None and _canonical(completed.get(key)) != json_bytes(native[key]):
                fail("E_FINALIZE", "review must preserve supplied native IDs, exact scope, reason and expiry")
    indices = sorted(approved)
    decisions = parse_decisions(root | {"decisions": [records[i] for i in indices]})
    day = parse_date(as_of, "as-of")
    result = []
    for i, decision in zip(indices, decisions):
        if decision.expires_on <= day:
            fail("E_EXPIRED", f"decisions[{i}]: expired at as-of (expiresOn is the first invalid UTC day)")
        row = decision.as_record()
        refs = list(decision.source_refs)
        for ref in (
            f"urn:triage-bridge:trivy-ignore:sha256:{original['source']['rawSha256']}#{original['reviews'][i]['sourcePointer']}",
            f"urn:triage-bridge:import-review:sha256:{review_sha}#/decisionDocument/decisions/{i}",
        ):
            if ref not in refs:
                refs.append(ref)
        row["sourceRefs"] = refs
        result.append(row)
    return {"schemaVersion": 1, "decisions": result}
