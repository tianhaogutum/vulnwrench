"""Inert presentation of one completed native import report. No validation or I/O."""
import json
import re

from .renewal_markdown import _cell, _table


def render_import_markdown(draft: dict) -> str:
    """Render the validated report without changing policy or resolving review.

    CLI callers complete the existing import before rendering. The appendix is
    the entire report, including copied source text; it is deliberately unredacted.
    """
    lines = ["# Trivy import review draft", "",
             "Review only. No draft is approved. Resolve every required field and "
             "review package scope before finalization or compilation.", ""]
    metadata = {key: draft[key] for key in ("schemaVersion", "kind", "mode", "automaticActions")}
    lines += _table(("Field", "Value"),
                    [(key, _cell(value)) for key, value in metadata.items()])
    lines += _table(("Count", "Value"),
                    [(key, _cell(value)) for key, value in draft["counts"].items()])
    lines += ["## Source", "",
              "The raw-byte digest identifies content, not authenticated provenance. "
              "Pointers are opaque source references; they are not fetched or linked.", ""]
    lines += _table(("Field", "Value"),
                    [(key, _cell(value)) for key, value in draft["source"].items()])
    lines += ["## Draft decisions", "",
              "Original order and zero-based indices are retained. Null owner/status "
              "and other unresolved fields remain null. An exact PURL chosen for "
              "all-package native scope narrows that scope and requires human review.", ""]
    if not draft["reviews"]:
        lines += ["No supported drafts.", ""]
    for review in draft["reviews"]:
        index = review["decisionIndex"]
        record = draft["decisionDocument"]["decisions"][index]
        lines += [f"### Draft {index}", ""]
        lines += _table(("Field", "Value"), [
            (key, _cell(value)) for key, value in {**record, **review}.items()])
    lines += ["## Unsupported findings", "",
              "Unsupported findings produce no drafts. A partial import must not "
              "replace the original ignore file. The optional gate counts these "
              "findings, not drafts or unresolved review fields.", ""]
    if not draft["unsupported"]:
        lines += ["No unsupported findings. This does not approve any draft.", ""]
    lines += _table(("Finding index", "Source pointer", "Code", "Detail"), [
        tuple(_cell(value) for value in (index, entry["pointer"], entry["code"], entry["detail"]))
        for index, entry in enumerate(draft["unsupported"])])
    lines += ["## Warnings", ""]
    lines += ["- " + _cell(warning) for warning in draft["warnings"]]
    lines += ["", "## Full draft (JSON)", "",
              "Disclosure: this lossless appendix contains the entire import report, "
              "including all copied draft IDs, package scope, reasons and expiry dates, "
              "null fields, review requirements, raw source digest/pointers, unsupported "
              "findings and warnings. It is not redacted. It does not reconstruct "
              "rejected raw source values. Control who receives it. This report is "
              "not an approval or compile input; retain the original native bytes.", ""]
    payload = json.dumps(draft, ensure_ascii=True, sort_keys=True, indent=2, allow_nan=False)
    fence = "`" * max(3, 1 + max((len(run) for run in re.findall(r"`+", payload)), default=0))
    lines += [fence + "json", payload, fence, ""]
    return "\n".join(lines)
