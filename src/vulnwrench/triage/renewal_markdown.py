"""Inert Markdown presentation of a completed, validated renewal plan. No I/O."""
import json
import re
import unicodedata


def _cell(value):
    """Code spans with visible JSON escapes; no raw cell/fence/HTML delimiters.

    Escape backslashes first via JSON so literal escape-looking input remains
    distinguishable. Format controls (including bidi) must not affect the report.
    """
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False)
    if isinstance(value, str):
        encoded = encoded[1:-1]
    safe = []
    for char in encoded:
        if char in "|`<>" or unicodedata.category(char) in ("Cc", "Cf", "Zl", "Zp"):
            point = ord(char)
            safe.append(f"\\u{point:04x}" if point <= 0xffff else f"\\U{point:08x}")
        else:
            safe.append(char)
    return "`" + "".join(safe) + "`"


def _table(headers, rows):
    return ["| " + " | ".join(headers) + " |",
            "| " + " | ".join("---" for _ in headers) + " |",
            *("| " + " | ".join(row) + " |" for row in rows), ""]


def render_renewal_markdown(plan: dict) -> str:
    """Render exactly the supplied plan, without validation or policy decisions.

    CLI callers supply the existing plan only after all requested checks succeed.
    The appendix discloses the entire plan, including copied source record data.
    """
    lines = ["# Renewal review plan", "",
             "Review only. No exception is approved or renewed by this report.", ""]
    metadata = {"mode": plan["mode"], **plan["parameters"], **plan["counts"],
                "automaticActions": plan["automaticActions"]}
    lines += _table(("Field", "Value"),
                    [(key, _cell(value)) for key, value in sorted(metadata.items())])
    lines += ["## Decisions", "",
              "Prior and current expiry are independent. An absent side has no expiry; "
              "an added entry's plan expiryStatus describes its current record.", ""]

    def expiry(entry, side):
        if entry[side] is None:
            return _cell("absent")
        status = entry["expiryStatus" if side == "prior" else "currentExpiryStatus"]
        return _cell(f"{entry[side]['record']['expiresOn']} ({status})")

    def items(values):
        return ", ".join(_cell(value) for value in values) if values else _cell([])

    lines += _table(("Decision ID", "Prior expiry", "Current expiry", "Findings / status",
                     "Human review actions", "Review required"), [
        (_cell(entry["decisionId"]), expiry(entry, "prior"), expiry(entry, "current"),
         items(entry["statuses"]), items(entry["actions"]), _cell(entry["reviewRequired"]))
        for entry in plan["decisions"]])
    lines += ["## Source evidence", "",
              "References are opaque caller-supplied text. They are not fetched or linked. "
              "Digests identify content, not authenticated authorship.", ""]
    lines += _table(("Plan source field", "Value"),
                    [(key, _cell(value)) for key, value in sorted(plan["sources"].items())])
    evidence = []
    for entry in plan["decisions"]:
        for side in ("prior", "current"):
            reference = entry[side]
            fields = {"presence": "absent"} if reference is None else {
                **reference["source"], "sourceRefs": reference["record"].get("sourceRefs", [])}
            for key, value in sorted(fields.items()):
                evidence.append((_cell(entry["decisionId"]), side, key, _cell(value)))
    lines += _table(("Decision ID", "Side", "Source field", "Value"), evidence)
    lines += ["## Verification", ""]
    lines += _table(("Check", "Result"), [
        (name, _cell(plan.get(name, "not requested")))
        for name in ("sourceVerification", "artifactVerification")])
    lines += ["## Warnings", ""]
    lines += ["- " + _cell(warning) for warning in plan["warnings"]]
    lines += ["", "## Full plan (JSON)", "",
              "Disclosure: this lossless appendix includes all prior/current records, owners, "
              "policy and evidence text, opaque references, source digests/pointers and "
              "requested verification results. It is not redacted. Control who receives it.", ""]
    # ASCII JSON makes all control/format characters visible and remains lossless.
    payload = json.dumps(plan, ensure_ascii=True, sort_keys=True, indent=2, allow_nan=False)
    fence = "`" * max(3, 1 + max((len(run) for run in re.findall(r"`+", payload)), default=0))
    lines += [fence + "json", payload, fence, ""]
    return "\n".join(lines)
