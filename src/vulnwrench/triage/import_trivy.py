"""Conservative native Trivy ignore import. Returns drafts, never approvals.

The block reader recognizes only the documented, fixed-indentation profile below,
not general YAML. Anything outside that grammar fails closed. JSON flow-style
YAML (including our compiler output) uses the existing strict JSON decoder.
"""
from __future__ import annotations

import re

from .compiler import digest
from .model import (BridgeError, MAX_DECISIONS, MAX_INPUT_BYTES, decode_document,
                    fail, identifier, parse_date, parse_purl, text)


def _syntax():
    fail("E_IMPORT", "expected supported Trivy JSON-flow or restricted block YAML; see import-trivy documentation")


def _scalar(value: str) -> str | list:
    if value.startswith(('"', '[')):
        result = decode_document(value.encode("utf-8"))
        if not isinstance(result, (str, list)):
            _syntax()
        return result
    if value.startswith("'"):
        if not re.fullmatch(r"'(?:[^']|'')*'", value):
            _syntax()
        return value[1:-1].replace("''", "'")
    # Plain scalars must be unambiguously strings in YAML 1.1 and 1.2, except
    # date-only expiry values which are explicitly converted to date strings.
    if (not value or value[0] in '-?:,[]{}#&*!|>\'"%@`'
            or any(c in value for c in '[]{}#') or ': ' in value or value.endswith(':')
            or value.lower() in {"null", "~", "true", "false", "y", "n", "yes", "no", "on", "off",
                                 ".nan", ".inf", "+.inf", "-.inf"}
            or (value[0] in '+.0123456789' and not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value))):
        _syntax()
    return value


def _block_yaml(source: str) -> dict:
    """Root sections; two-space records; four-space fields; six-space lists.

    Only single-line scalar values, full-line comments, and JSON inline arrays.
    No anchors, tags, merges, implicit booleans/numbers, multiline strings,
    inline comments, directives, or multiple documents.
    """
    document = {}
    section = record = items = None

    def finish_list():
        # A bare `purls:` is YAML null, not an empty sequence. Only explicit
        # [] or a nonempty block sequence is within this reader's profile.
        if items is not None and not items:
            _syntax()

    def field(line):
        match = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*):(?: (.+))?", line)
        if not match or match[1] in record:
            _syntax()
        key, value = match.groups()
        if value is None:
            record[key] = []
            return record[key]
        record[key] = _scalar(value)
        return None

    for line in source.split("\n"):
        line = line.removesuffix("\r").rstrip(" ")
        if any(ord(c) < 32 or ord(c) == 127 or c in '\u0085\u2028\u2029' for c in line):
            _syntax()
        if not line or line.lstrip(" ").startswith("#"):
            continue
        if not line.startswith(" "):
            finish_list()
            if section is not None and not section:
                _syntax()
            match = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*):(?: (\[\]))?", line)
            if not match or match[1] in document:
                _syntax()
            section = []
            document[match[1]] = section
            # An explicitly empty section cannot take following records.
            if match[2] is not None:
                section = None
            record = items = None
        elif line.startswith("  - ") and section is not None:
            finish_list()
            record = {}
            section.append(record)
            items = field(line[4:])
        elif line.startswith("      - ") and items is not None:
            value = _scalar(line[8:])
            if not isinstance(value, str):
                _syntax()
            items.append(value)
        elif line.startswith("    ") and not line.startswith("     ") and record is not None:
            finish_list()
            items = field(line[4:])
        else:
            _syntax()
    finish_list()
    if section is not None and not section:
        _syntax()
    return document


def _decode_native(raw: bytes) -> dict:
    if not isinstance(raw, bytes) or len(raw) > MAX_INPUT_BYTES:
        _syntax()
    try:
        source = raw.decode("utf-8")
        document = decode_document(raw) if source.lstrip().startswith("{") else _block_yaml(source)
        if not isinstance(document, dict) or not document:
            _syntax()
        total = 0
        for key, entries in document.items():
            key.encode("utf-8")  # JSON escapes may otherwise conceal an unpaired surrogate.
            if not isinstance(entries, list) or any(not isinstance(row, dict) for row in entries):
                _syntax()
            total += len(entries)
        if total > MAX_DECISIONS:
            _syntax()
        return document
    except (BridgeError, UnicodeError, RecursionError, ValueError):
        _syntax()


def import_trivy_ignore(raw: bytes) -> dict:
    """Import <=2 MiB of native YAML bytes into an explicitly review-only draft.

    Unsupported entries are reported without producing decisions for them. Known
    exact PURLs expand to separate records; all-package ignores have null package
    scope, requiring a deliberate human scope decision. No VEX status is inferred.
    """
    document = _decode_native(raw)
    decisions, reviews, unsupported = [], [], []

    def reject(pointer, code, detail):
        unsupported.append({"pointer": pointer, "code": code, "detail": detail})

    for section in document:
        if section != "vulnerabilities":
            pointer = "/" + section.replace("~", "~0").replace("/", "~1")
            reject(pointer, "unsupported_section", "Only vulnerability ignores can become decision drafts.")

    entries = document.get("vulnerabilities", [])
    for i, entry in enumerate(entries):
        pointer = f"/vulnerabilities/{i}"
        if "paths" in entry:
            reject(pointer + "/paths", "unsupported_paths", "Path selectors cannot be represented; the entire entry was blocked.")
            continue
        if set(entry) - {"id", "purls", "statement", "expired_at"}:
            reject(pointer, "unsupported_field", "Unknown entry fields cannot be represented; the entire entry was blocked.")
            continue
        try:
            id_ = identifier(entry.get("id"), "native id")
            reason = text(entry["statement"], "native statement") if "statement" in entry else None
            expires = parse_date(entry["expired_at"], "native expiry").isoformat() if "expired_at" in entry else None
            purls = entry.get("purls", [])
            if not isinstance(purls, list):
                fail("E_INPUT", "native purls must be an array")
            # Check the expansion bound before validating/allocating all PURLs.
            if len(decisions) + max(1, len(purls)) > MAX_DECISIONS:
                _syntax()
            packages = [parse_purl(purl) for purl in purls] if purls else [None]
        except BridgeError as exc:
            if exc.code == "E_IMPORT":
                raise
            code = "unsupported_purl" if exc.code == "E_PURL" else "invalid_entry"
            reject(pointer, code, "An invalid or unsupported native value blocked the entire entry; no repair was attempted.")
            continue
        for package in packages:
            record = {"ids": [id_], "package": package, "owner": None, "reason": reason,
                      "expiresOn": expires, "status": None}
            reviews.append({"decisionIndex": len(decisions), "sourcePointer": pointer,
                            "nativeScope": "all_packages" if package is None else "exact_purls",
                            "requiredFields": [key for key, value in record.items() if value is None],
                            "reviewFields": ["package"], "reviewRequired": True})
            decisions.append(record)
    return {
        "schemaVersion": 1, "kind": "trivy_import_draft", "mode": "review_only", "automaticActions": [],
        "source": {"format": "trivy-ignore-yaml", "rawSha256": digest(raw)},
        "counts": {"nativeEntries": sum(len(rows) for rows in document.values()),
                   "draftDecisions": len(decisions), "unsupported": len(unsupported)},
        "decisionDocument": {"schemaVersion": 1, "decisions": decisions},
        "reviews": reviews, "unsupported": unsupported,
        "warnings": [
            "Drafts only: assign every required field and review package scope before extracting decisionDocument for compilation.",
            "Native ignores provide no owner or VEX status/evidence. No accepted_risk or not_affected status was inferred.",
            "All-package native scope cannot be compiled directly: selecting an exact versioned PURL narrows that scope and requires human review.",
            "IDs, reasons and expiry dates are copied without alias inference or date extension; compile rechecks evidence, overlap and expiry.",
            "Unsupported entries produce no drafts. A partial import is not a replacement for the original ignore file.",
            "Source digest is reproducible content identification, not authenticated provenance. No scanner was executed.",
        ],
    }
