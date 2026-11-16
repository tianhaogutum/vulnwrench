"""Strict, offline decision model. No scanner or network operations."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timezone
import json
import re
from urllib.parse import unquote


VEX_STATUSES = frozenset({"not_affected", "affected", "fixed", "under_investigation"})
STATUSES = VEX_STATUSES | {"accepted_risk"}
JUSTIFICATIONS = frozenset({
    "component_not_present", "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
})
MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_DECISIONS = 10_000


class BridgeError(ValueError):
    """A safe diagnostic: never contains user-supplied values or paths."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


def fail(code: str, message: str):
    raise BridgeError(code, message)


def text(value: object, where: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        fail("E_INPUT", f"{where}: expected nonempty text without edge whitespace")
    if len(value) > 16384 or any(
        (ord(c) < 32 and c not in "\n\t") or 0xD800 <= ord(c) <= 0xDFFF
        or ord(c) == 127 for c in value
    ):
        fail("E_INPUT", f"{where}: unsupported text characters or length")
    return value


def identifier(value: object, where: str) -> str:
    value = text(value, where)
    # Public and internal IDs, not URLs, patterns, whitespace, or commands.
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:+-]{0,255}", value):
        fail("E_INPUT", f"{where}: unsupported vulnerability identifier syntax")
    return value


def parse_date(value: object, where: str) -> date:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value):
        fail("E_DATE", f"{where}: expected YYYY-MM-DD")
    try:
        return date.fromisoformat(value)
    except ValueError:
        fail("E_DATE", f"{where}: invalid calendar date")


def parse_timestamp(value: object) -> str:
    value = text(value, "timestamp")
    # Deliberately narrow RFC3339 profile: seconds, optional <=6 digit fraction,
    # explicit timezone; canonical output is UTC. No leap seconds.
    if not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
        r"(?:\.[0-9]{1,6})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])", value
    ):
        fail("E_DATE", "timestamp: expected RFC3339 with an explicit timezone")
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, OverflowError):
        fail("E_DATE", "timestamp: invalid calendar date or time")
    return stamp.isoformat().replace("+00:00", "Z")


def _purl_piece(value: str) -> bool:
    if not value or re.search(r"%(?![0-9A-F]{2})", value):
        return False
    # A conservative ASCII PURL profile. Structural delimiters must be encoded.
    if not re.fullmatch(r"[A-Za-z0-9._~+:%-]+", value):
        return False
    try:
        decoded = unquote(value, errors="strict")
    except UnicodeError:
        return False
    return decoded not in {".", ".."} and not any(
        c.isspace() or ord(c) < 32 or ord(c) == 127 or c in "/*?\\#" for c in decoded
    )


def parse_purl(value: object) -> str:
    value = text(value, "package")
    # Exact, versioned packages only. No fragment/subpath or glob matching.
    match = re.fullmatch(r"pkg:([a-z][a-z0-9.+-]*)/([^?#]+)(?:\?([^#]+))?", value)
    if not match:
        fail("E_PURL", "package: expected supported versioned pkg: PURL")
    path, sep, version = match[2].rpartition("@")
    if not sep or "@" in path or not _purl_piece(version):
        fail("E_PURL", "package: an exact name and version are required")
    if not all(_purl_piece(part) for part in path.split("/")):
        fail("E_PURL", "package: invalid or unsupported PURL path")
    if match[3] is not None:
        keys = []
        for pair in match[3].split("&"):
            key, sep, val = pair.partition("=")
            if not sep or not re.fullmatch(r"[a-z][a-z0-9._-]*", key) or not _purl_piece(val):
                fail("E_PURL", "package: invalid or unsupported qualifier")
            keys.append(key)
        if keys != sorted(set(keys)):
            fail("E_PURL", "package: qualifier keys must be unique and sorted")
    return value


def product_identifier(value: object) -> str:
    value = text(value, "product ID")
    if (not re.match(r"[A-Za-z][A-Za-z0-9+.-]*:.+", value)
            or any(c.isspace() or ord(c) < 32 or c in '<>"{}|\\^`' for c in value)
            or re.search(r"%(?![0-9a-fA-F]{2})", value)):
        fail("E_INPUT", "product ID: expected an absolute IRI without whitespace")
    return value


def object_fields(value: object, allowed: set[str], required: set[str], where: str) -> dict:
    if not isinstance(value, dict):
        fail("E_INPUT", f"{where}: expected an object")
    if set(value) - allowed:
        fail("E_INPUT", f"{where}: unknown fields are unsupported")
    if required - set(value):
        fail("E_INPUT", f"{where}: required fields are missing")
    return value


def id_list(value: object, where: str, *, nonempty: bool = True) -> tuple[str, ...]:
    if not isinstance(value, list) or (nonempty and not value):
        fail("E_INPUT", f"{where}: expected a nonempty identifier array")
    values = tuple(identifier(v, where) for v in value)
    if len(set(values)) != len(values):
        fail("E_CONFLICT", f"{where}: duplicate identifiers")
    return tuple(sorted(values))


@dataclass(frozen=True)
class Vulnerability:
    id: str
    aliases: tuple[str, ...] = ()

    @property
    def expanded_ids(self) -> tuple[str, ...]:
        return (self.id, *self.aliases)


@dataclass(frozen=True)
class Decision:
    vulnerabilities: tuple[Vulnerability, ...]
    package: str
    owner: str | None
    reason: str
    expires_on: date
    status: str
    justification: str | None = None
    impact_statement: str | None = None
    action_statement: str | None = None
    decision_id: str | None = None
    source_refs: tuple[str, ...] = ()

    def as_record(self) -> dict:
        result = {
            "ids": [v.id for v in self.vulnerabilities],
            "aliases": {v.id: list(v.aliases) for v in self.vulnerabilities if v.aliases},
            "package": self.package, "owner": self.owner, "reason": self.reason,
            "expiresOn": self.expires_on.isoformat(), "status": self.status,
        }
        for key in ("justification", "impact_statement", "action_statement"):
            if getattr(self, key) is not None:
                result[key] = getattr(self, key)
        if self.owner is None:
            del result["owner"]
        if self.decision_id is not None:
            result["decisionId"] = self.decision_id
        if self.source_refs:
            result["sourceRefs"] = list(self.source_refs)
        return result


def parse_decisions(document: object) -> tuple[Decision, ...]:
    return _parse_decisions(document, require_owner=True)


def _parse_decisions(document: object, *, require_owner: bool) -> tuple[Decision, ...]:
    """Only the review preview may retain missing owners for human follow-up."""
    root = object_fields(document, {"schemaVersion", "decisions"}, {"decisions"}, "document")
    version = root.get("schemaVersion", 1)
    if type(version) is not int or version != 1:
        fail("E_INPUT", "document: only schemaVersion 1 is supported")
    records = root["decisions"]
    if not isinstance(records, list) or not 1 <= len(records) <= MAX_DECISIONS:
        fail("E_INPUT", "decisions: expected between 1 and 10000 records")
    required = {"ids", "package", "owner", "reason", "expiresOn", "status"}
    optional = {"aliases", "justification", "impact_statement", "action_statement",
                "decisionId", "sourceRefs"}
    decisions = []
    seen: set[tuple[str, str]] = set()
    canonical_for: dict[str, str] = {}
    seen_decision_ids: set[str] = set()
    for i, record in enumerate(records):
        where = f"decisions[{i}]"
        rec = object_fields(record, required | optional,
                            required if require_owner else required - {"owner"}, where)
        decision_id = None
        if "decisionId" in rec:
            decision_id = identifier(rec["decisionId"], where + ".decisionId")
            if decision_id in seen_decision_ids:
                fail("E_CONFLICT", f"{where}: duplicate decisionId")
            seen_decision_ids.add(decision_id)
        refs = rec.get("sourceRefs", [])
        if not isinstance(refs, list):
            fail("E_INPUT", f"{where}.sourceRefs: expected an array of reference strings")
        refs = tuple(text(ref, where + ".sourceRefs") for ref in refs)
        if len(set(refs)) != len(refs):
            fail("E_INPUT", f"{where}.sourceRefs: duplicate references")
        ids = id_list(rec["ids"], where + ".ids")
        aliases = rec.get("aliases", {})
        if not isinstance(aliases, dict) or set(aliases) - set(ids):
            fail("E_INPUT", f"{where}.aliases: expected a map keyed by supplied primary IDs")
        vulns = tuple(Vulnerability(id_, id_list(aliases.get(id_, []), where + ".aliases", nonempty=False))
                      for id_ in ids)
        package = parse_purl(rec["package"])
        for vuln in vulns:
            for id_ in vuln.expanded_ids:
                previous = canonical_for.setdefault(id_, vuln.id)
                if previous != vuln.id:
                    fail("E_CONFLICT", f"{where}: identifiers have ambiguous primary/alias assignments")
                key = (id_, package)
                if key in seen:
                    fail("E_CONFLICT", f"{where}: overlapping decisions for the same identifier and package")
                seen.add(key)
        owner = rec.get("owner")
        if not require_owner and (owner is None or isinstance(owner, str)
                                  and len(owner) <= 16384 and not owner.strip(" \t\n")):
            owner = None
        else:
            owner = text(owner, where + ".owner")
        reason = text(rec["reason"], where + ".reason")
        expires = parse_date(rec["expiresOn"], where + ".expiresOn")
        status = text(rec["status"], where + ".status")
        if status not in STATUSES:
            fail("E_STATUS", f"{where}: unsupported decision status")
        extra = {key: text(rec[key], where + "." + key)
                 for key in ("justification", "impact_statement", "action_statement") if key in rec}
        if "justification" in extra and extra["justification"] not in JUSTIFICATIONS:
            fail("E_STATUS", f"{where}: unsupported VEX justification")
        if status == "not_affected":
            if not (extra.get("justification") or extra.get("impact_statement")):
                fail("E_STATUS", f"{where}: not_affected requires justification or impact_statement")
        elif "justification" in extra or "impact_statement" in extra:
            fail("E_STATUS", f"{where}: justification/impact_statement require not_affected")
        if status == "affected" and "action_statement" not in extra:
            fail("E_STATUS", f"{where}: affected requires action_statement")
        if status != "affected" and "action_statement" in extra:
            fail("E_STATUS", f"{where}: action_statement requires affected")
        decisions.append(Decision(vulns, package, owner, reason, expires, status,
                                  decision_id=decision_id, source_refs=refs, **extra))
    return tuple(decisions)


def decode_document(raw: bytes) -> object:
    if len(raw) > MAX_INPUT_BYTES:
        fail("E_INPUT", "input exceeds the 2 MiB limit")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                fail("E_INPUT", "JSON object has duplicate keys")
            result[key] = value
        return result

    def constant(_value):
        fail("E_INPUT", "JSON non-finite numbers are unsupported")

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        if isinstance(exc, BridgeError):
            raise
        fail("E_INPUT", "input must be a valid UTF-8 JSON document")
