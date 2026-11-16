"""Offline redacted Gitleaks review ledger. No scanner or subprocess execution."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
from collections import Counter, deque
from pathlib import Path

SCHEMA = "secret-ledger/v1"
COMPARISON_SCHEMA = "secret-ledger-comparison/v1"
PROVENANCE = {
    "source_format": "gitleaks-json-array",
    "coverage": "caller-declared-full-report",
    "content_policy": "hmac-sha256-secret-only;redacted-is-unknown",
}
MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_PRIVACY_STATES = 250_000
HEX = re.compile(r"[0-9a-f]{64}\Z")
RULE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}\Z")
COMMIT = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})?\Z")
REPORT_FIELDS = {
    "RuleID", "File", "StartLine", "Commit", "Secret", "Match", "Fingerprint",
    "Description", "EndLine", "StartColumn", "EndColumn", "Line", "SymlinkFile",
    "Entropy", "Author", "Email", "Date", "Message", "Tags",
}
CLASSIFICATIONS = (
    "unchanged", "same_secret_moved", "new_content_same_location", "new_content",
    "absent", "uncomparable",
)


class LedgerError(ValueError):
    """A deliberately value-free error safe for the CLI to display."""


def fail(message: str) -> None:
    raise LedgerError(message)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail("duplicate JSON object member")
        result[key] = value
    return result


def _constant(_):
    fail("non-finite JSON number")


def _read_input(path, label):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            fail(label + " input must be a regular file")
        raw = stream.read(MAX_JSON_BYTES + 1)
    if len(raw) > MAX_JSON_BYTES:
        fail(label + " input exceeds 64 MiB limit")
    return raw


def load_json(path: str | Path):
    try:
        raw = _read_input(path, "JSON")
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                          parse_constant=_constant)
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, LedgerError):
            raise
        raise LedgerError("cannot read valid UTF-8 JSON input") from None


def load_renames(path: str | Path, *, allow_non_renames: bool = False) -> list[dict]:
    """Read supplied name-status bytes; optionally filter validated A/M/D/T records."""
    try:
        return import_renames(_read_input(path, "name-status"), allow_non_renames=allow_non_renames)
    except OSError:
        raise LedgerError("cannot read name-status input") from None


def import_renames(raw: bytes, *, allow_non_renames: bool = False) -> list[dict]:
    """Convert R<000..100> NUL old NUL new NUL triples to a sorted path map.

    By explicit opt-in, A/M/D/T NUL path NUL pairs are validated then discarded.
    Empty or no-rename input yields an empty map. No other statuses or text/quoted
    formats are accepted. Comparison must still check privacy and prior collisions.
    """
    if not isinstance(raw, bytes):
        fail("name-status input must be bytes")
    if len(raw) > MAX_JSON_BYTES:
        fail("name-status input exceeds 64 MiB limit")
    if not raw:
        return []
    if not raw.endswith(b"\0"):
        fail("name-status input requires a final NUL")
    try:
        fields = raw[:-1].decode("utf-8").split("\0")
    except UnicodeError:
        fail("name-status input must be valid UTF-8")
    entries = []
    i = 0
    while i < len(fields):
        status = fields[i]
        if re.fullmatch(r"R(?:0[0-9]{2}|100)", status):
            path_count = 2
        elif allow_non_renames and status in {"A", "M", "D", "T"}:
            path_count = 1
        else:
            fail("unsupported name-status record; expected R000 through R100 or opted-in A/M/D/T")
        i += 1
        if len(fields) - i < path_count:
            fail("name-status input requires complete records")
        paths = []
        for path in fields[i:i + path_count]:
            # Git backslashes are literal, whereas the ledger treats them as
            # separators. Reject this ambiguity even in records being ignored.
            if "\\" in path:
                fail("literal backslashes in Git paths are unsupported")
            paths.append(normalize_path(path))
        if path_count == 2:
            entries.append({"old_path": paths[0], "new_path": paths[1]})
        # Consume exactly this record's paths; never guess a recovery boundary.
        i += path_count
    forward = _normalize_path_map(entries)
    return [{"old_path": old, "new_path": new} for old, new in sorted(forward.items())]


def read_key(path: str | Path) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                fail("key must be a regular file")
            if os.name == "posix":
                if stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid():
                    fail("key must be owned by current user with mode 0600")
            key = stream.read(33)
        if len(key) != 32:
            fail("key must contain exactly 32 raw bytes")
        return key
    except OSError:
        raise LedgerError("cannot securely read key file") from None


def init_key(path: str | Path) -> None:
    """Explicit key creation; add a local ignore entry before creating the key."""
    path = Path(path)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", path.name):
        fail("key filename must use letters, digits, dots, underscores or hyphens")
    if path.exists() or path.is_symlink():
        fail("key file already exists")
    ignore = path.parent / ".gitignore"
    try:
        fd = os.open(ignore, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_NONBLOCK", 0), 0o644)
        with os.fdopen(fd, "r+b") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                fail("local ignore file must be regular")
            existing = stream.read(MAX_JSON_BYTES + 1)
            if len(existing) > MAX_JSON_BYTES:
                fail("local ignore file is too large")
            entry = ("/" + path.name).encode("ascii")
            # Last matching entry wins, including an existing negation.
            if not existing.endswith(entry + b"\n"):
                stream.write((b"\n" if existing and not existing.endswith(b"\n") else b"")
                             + entry + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(os.urandom(32))
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        raise LedgerError("cannot create key and local Git ignore entry") from None


def key_id(key: bytes) -> str:
    if not isinstance(key, bytes) or len(key) != 32:
        fail("key must contain exactly 32 raw bytes")
    return hashlib.sha256(b"secret-ledger-key-id-v1\0" + key).hexdigest()


def _text(value, label: str, *, empty=False, maximum=4096) -> str:
    if not isinstance(value, str) or len(value) > maximum or (not value and not empty):
        fail("invalid " + label)
    if any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value):
        fail("unsafe characters in " + label)
    return value


def normalize_path(value) -> str:
    value = _text(value, "relative finding path").replace("\\", "/")
    if value.startswith("/") or re.match(r"^[A-Za-z]:", value):
        fail("absolute finding paths are unsupported")
    parts = value.split("/")
    if ".." in parts:
        fail("parent traversal in finding path")
    parts = [p for p in parts if p not in ("", ".")]
    if not parts or any("!" in p or ":" in p for p in parts):
        fail("archive or special finding paths are unsupported")
    return "/".join(parts)


def _line(value) -> int:
    if type(value) is not int or not 1 <= value <= 2**31 - 1:
        fail("StartLine must be a positive 32-bit integer")
    return value


def _rule(value) -> str:
    if not isinstance(value, str) or not RULE.fullmatch(value):
        fail("unsupported rule identifier")
    return value


def _commit(value) -> str:
    if not isinstance(value, str) or not COMMIT.fullmatch(value):
        fail("Commit must be empty or a full hexadecimal Git object ID")
    return value


def _fingerprint(value, rule: str, path: str, line: int, commit: str) -> str:
    value = _text(value, "fingerprint", maximum=8192)
    parts = value.rsplit(":", 2)
    if len(parts) != 3 or parts[1] != rule or parts[2] != str(line):
        fail("unsupported or inconsistent native fingerprint")
    prefix = parts[0]
    if commit and prefix.startswith(commit + ":"):
        prefix = prefix[len(commit) + 1:]
    elif not commit and prefix.startswith(":"):
        prefix = prefix[1:]
    if normalize_path(prefix) != path:
        fail("fingerprint path does not match finding path")
    return value


def is_unknown(secret) -> bool:
    if secret is None or secret == "":
        return True
    if not isinstance(secret, str):
        fail("Secret must be a string or null")
    # Conservative: partial redaction and common placeholders never get hashes.
    stripped = secret.strip()
    return (not stripped or "redact" in stripped.casefold() or "*" in stripped
            or stripped.casefold() in {"[removed]", "<removed>", "[masked]", "<masked>",
                                      "[hidden]", "<hidden>", "<secret>", "[secret]"})


def _occ_sort(o):
    return (o["start_line"], o["commit"], o["fingerprint"])


def _group_sort(g):
    return (g["rule_id"], g["path"], g["content_hmac"] or "")


def _summary(groups):
    return {"groups": len(groups), "occurrences": sum(len(g["occurrences"]) for g in groups),
            "uncomparable_occurrences": sum(len(g["occurrences"]) for g in groups
                                             if g["content_hmac"] is None)}


class _SensitiveMatcher:
    """Exact Unicode substring search, with bounded direct work for tiny sets.

    Larger sets use a sparse Aho-Corasick trie. Failure links inherit a boolean
    terminal flag: we need existence, never lists of matches or raw diagnostics.
    State resets for every field, so matches cannot span metadata boundaries.
    """
    def __init__(self, sensitive):
        # No retained field can exceed the fingerprint's 8192-character limit.
        # Longer content cannot occur in any field, and need not be indexed.
        patterns = {raw for raw in sensitive if 0 < len(raw) <= 8192}
        self.direct = tuple(patterns) if len(patterns) <= 16 else None
        if self.direct is not None:
            return
        self.edges, self.failure, self.terminal = [{}], [0], [False]
        for raw in sorted(patterns):
            state = 0
            for char in raw:
                child = self.edges[state].get(char)
                if child is None:
                    if len(self.edges) >= MAX_PRIVACY_STATES:
                        fail(f"metadata privacy index exceeds {MAX_PRIVACY_STATES} states; "
                             "reduce the complete scan scope consistently for both snapshots "
                             "and rebuild the prior ledger")
                    child = len(self.edges)
                    self.edges[state][char] = child
                    self.edges.append({})
                    self.failure.append(0)
                    self.terminal.append(False)
                state = child
            self.terminal[state] = True
        pending = deque(self.edges[0].values())
        while pending:
            state = pending.popleft()
            for char, child in self.edges[state].items():
                fallback = self.failure[state]
                while fallback and char not in self.edges[fallback]:
                    fallback = self.failure[fallback]
                self.failure[child] = self.edges[fallback].get(char, 0)
                self.terminal[child] |= self.terminal[self.failure[child]]
                pending.append(child)

    def overlaps(self, value):
        if self.direct is not None:
            return any(raw in value for raw in self.direct)
        state = 0
        for char in value:
            while state and char not in self.edges[state]:
                state = self.failure[state]
            state = self.edges[state].get(char, 0)
            if self.terminal[state]:
                return True
        return False


def snapshot(report, key: bytes, *, redacted: bool = False) -> dict:
    return _snapshot(report, key, redacted=redacted)[0]


def _snapshot(report, key: bytes, *, redacted: bool = False):
    """Return the ledger and report-local matcher for reuse by compare."""
    kid = key_id(key)
    if not isinstance(report, list):
        fail("report must be a complete Gitleaks JSON array")
    groups = {}
    sensitive = set()
    for row in report:
        if not isinstance(row, dict) or not set(row) <= REPORT_FIELDS:
            fail("unsupported finding object or fields")
        if not {"RuleID", "File", "StartLine", "Commit", "Fingerprint"} <= set(row):
            fail("finding is missing required fields")
        secret = row.get("Secret")
        unknown = is_unknown(secret) or redacted
        match = row.get("Match")
        if match is not None and not isinstance(match, str):
            fail("Match must be a string or null")
        # Check metadata across the whole report, including cross-row injection.
        sensitive.update(v for v in (secret, match) if isinstance(v, str) and v)
        rule = _rule(row["RuleID"])
        path = normalize_path(row["File"])
        line = _line(row["StartLine"])
        commit = _commit(row["Commit"])
        occurrence = {"start_line": line, "commit": commit,
                      "fingerprint": _fingerprint(row["Fingerprint"], rule, path, line, commit)}
        digest = None
        if not unknown:
            try:
                digest = hmac.new(key, secret.encode("utf-8"), hashlib.sha256).hexdigest()
            except UnicodeError:
                fail("Secret must be valid Unicode")
        ident = (rule, path, digest)
        if ident not in groups:
            groups[ident] = {"rule_id": rule, "path": path, "content_hmac": digest,
                             "comparability": "uncomparable" if unknown else "comparable",
                             "occurrences": []}
        groups[ident]["occurrences"].append(occurrence)
    ordered = sorted(groups.values(), key=_group_sort)
    for group in ordered:
        group["occurrences"].sort(key=_occ_sort)
    matcher = _SensitiveMatcher(sensitive)
    _check_metadata(ordered, matcher)
    return ({"schema": SCHEMA, "key_id": kid, "provenance": dict(PROVENANCE),
             "groups": ordered, "summary": _summary(ordered)}, matcher)


def _check_metadata(groups, matcher):
    for group in groups:
        if matcher.overlaps(group["rule_id"]) or matcher.overlaps(group["path"]):
            fail("finding metadata overlaps sensitive content; refusing to emit")
        for occurrence in group["occurrences"]:
            if matcher.overlaps(occurrence["commit"]) or matcher.overlaps(occurrence["fingerprint"]):
                fail("finding metadata overlaps sensitive content; refusing to emit")


def validate_ledger(ledger, expected_key_id: str) -> dict:
    if not isinstance(ledger, dict) or set(ledger) != {"schema", "key_id", "provenance", "groups", "summary"}:
        fail("unsupported ledger schema")
    if ledger["schema"] != SCHEMA or ledger["provenance"] != PROVENANCE:
        fail("unsupported ledger version or provenance")
    if ledger["key_id"] != expected_key_id:
        fail("ledger key ID mismatch; mixed keys cannot compare")
    if not isinstance(ledger["groups"], list):
        fail("invalid ledger groups")
    seen = set()
    for g in ledger["groups"]:
        if not isinstance(g, dict) or set(g) != {"rule_id", "path", "content_hmac", "comparability", "occurrences"}:
            fail("invalid ledger group")
        _rule(g["rule_id"])
        if normalize_path(g["path"]) != g["path"]:
            fail("ledger path must already be normalized")
        digest = g["content_hmac"]
        if digest is not None and (not isinstance(digest, str) or not HEX.fullmatch(digest)):
            fail("invalid ledger content HMAC")
        if g["comparability"] != ("uncomparable" if digest is None else "comparable"):
            fail("invalid ledger comparability")
        ident = _group_sort(g)
        if ident in seen:
            fail("duplicate ledger group")
        seen.add(ident)
        if not isinstance(g["occurrences"], list) or not g["occurrences"]:
            fail("ledger group must contain occurrences")
        for o in g["occurrences"]:
            if not isinstance(o, dict) or set(o) != {"start_line", "commit", "fingerprint"}:
                fail("invalid ledger occurrence")
            _line(o["start_line"])
            _commit(o["commit"])
            _fingerprint(o["fingerprint"], g["rule_id"], g["path"], o["start_line"], o["commit"])
    if (not isinstance(ledger["summary"], dict)
            or any(type(v) is not int for v in ledger["summary"].values())
            or ledger["summary"] != _summary(ledger["groups"])):
        fail("invalid ledger summary")
    return ledger


def _normalize_path_map(path_map):
    """Shared structural/path validation for comparisons and offline imports."""
    if not isinstance(path_map, list):
        fail("path map must be an array of old_path/new_path objects")
    forward, targets = {}, set()
    for entry in path_map:
        if not isinstance(entry, dict) or set(entry) != {"old_path", "new_path"}:
            fail("invalid path map entry")
        old, new = normalize_path(entry["old_path"]), normalize_path(entry["new_path"])
        if old in forward or new in targets:
            fail("path map must be bijective; duplicate source or destination")
        forward[old] = new
        targets.add(new)
    return forward


def _path_mapping(path_map, previous, matcher):
    """Validate a simultaneous bijection, including implicit prior identities."""
    forward = _normalize_path_map(path_map)
    for old, new in forward.items():
        if matcher.overlaps(old) or matcher.overlaps(new):
            fail("path map overlaps sensitive content; refusing to emit")
    # An unmapped old file stays at its path. It must not be merged into a
    # renamed file, even when their rules/content differ or one target is absent.
    sources = {g["path"] for g in previous} | set(forward)
    if len({forward.get(path, path) for path in sources}) != len(sources):
        fail("path map collision with an unmapped prior path")
    return forward


def compare(before, report, key: bytes, *, redacted: bool = False,
            path_map=None) -> tuple[dict, dict]:
    """Compare full reports; optional explicit renames never equate unknown content.

    path_map is a list of {old_path, new_path} objects. None retains path-bound
    comparison; even [] enables conservative handling of unmappable paths.
    """
    before = validate_ledger(before, key_id(key))
    current, matcher = _snapshot(report, key, redacted=redacted)
    previous = before["groups"]
    _check_metadata(previous, matcher)
    forward = _path_mapping(path_map, previous, matcher) if path_map is not None else {}
    old_paths = {g["path"] for g in previous}
    new_paths = {g["path"] for g in current["groups"]}
    shared_paths = (old_paths & new_paths) - set(forward)
    comparable_old_paths = set(forward) | shared_paths
    comparable_new_paths = set(forward.values()) | shared_paths

    def prior_ident(g):
        return (g["rule_id"], forward.get(g["path"], g["path"]), g["content_hmac"] or "")

    by_ident = {prior_ident(g): g for g in previous if g["content_hmac"] is not None}
    current_ids = {_group_sort(g) for g in current["groups"] if g["content_hmac"] is not None}
    unknown_by_path = {}
    for g in previous:
        if g["content_hmac"] is None:
            unknown_by_path.setdefault(prior_ident(g)[:2], []).append(g)
    # Only unmatched known current identities can reach replacement lookup.
    # Unknown prior content and unmapped paths short-circuit it as well. Select
    # buckets first. Retain group references, not line memberships, until the
    # first query; discard each line index immediately after its final query.
    remaining = Counter(ident[:2] for ident in current_ids
                        if ident not in by_ident and ident[:2] not in unknown_by_path
                        and (path_map is None or ident[1] in comparable_new_paths))
    needed_groups = {}
    if remaining:
        for index, g in enumerate(previous):
            path_ident = prior_ident(g)[:2]
            if path_ident in remaining:
                needed_groups.setdefault(path_ident, []).append(index)
    # Empty candidate buckets need neither query-line collection nor lookup
    # line sets. Count queries only for buckets with actual prior groups.
    remaining = {path_ident: remaining[path_ident] for path_ident in needed_groups}
    # _snapshot sorts groups by rule/path/HMAC, so queries for each bucket are
    # contiguous. Only one line index can be live, even across many buckets.
    candidates = None
    changes = []
    for current_index, g in enumerate(current["groups"]):
        prior = by_ident.get(_group_sort(g)) if g["content_hmac"] is not None else None
        path_ident = (g["rule_id"], g["path"])
        evidence = []
        if g["content_hmac"] is None:
            classification, reason = "uncomparable", "current_content_unavailable"
        elif path_map is not None and g["path"] not in comparable_new_paths:
            classification, reason = "uncomparable", "current_path_unmapped"
        elif prior is not None:
            renamed = prior["path"] != g["path"]
            # _snapshot already sorts current occurrences. Caller-supplied prior
            # lists may be unsorted; compare their multiset without mutating it.
            classification = ("unchanged" if not renamed and g["occurrences"]
                              == sorted(prior["occurrences"], key=_occ_sort) else "same_secret_moved")
            reason = "same_content_rule_and_mapped_path" if renamed else "same_content_rule_and_path"
            evidence = [prior]
        elif path_ident in unknown_by_path:
            classification, reason = "uncomparable", "prior_content_unavailable"
            evidence = unknown_by_path[path_ident].copy()
        elif path_ident not in remaining:
            classification, reason = "new_content", "no_prior_content_identity"
        else:
            if candidates is None:
                # Snapshot order makes this bucket contiguous. Collect only
                # unmatched known query lines, once per bucket, without a slice
                # or a full-ledger scan. Exact/unknown groups request no lines.
                requested_lines = set()
                query_index = current_index
                while query_index < len(current["groups"]):
                    query = current["groups"][query_index]
                    if (query["rule_id"], query["path"]) != path_ident:
                        break
                    if query["content_hmac"] is not None and _group_sort(query) not in by_ident:
                        requested_lines.update(o["start_line"] for o in query["occurrences"])
                    query_index += 1
                candidates = {}
                for index in needed_groups.pop(path_ident):
                    # Deduplicate memberships, preserving original evidence.
                    for line in {o["start_line"] for o in previous[index]["occurrences"]
                                 if o["start_line"] in requested_lines}:
                        candidates.setdefault(line, []).append(index)
                del requested_lines
            # A built but empty index proves every query in this bucket misses.
            # Keep it until the last query, without building lookup line sets.
            if candidates:
                # Misses cannot contribute evidence. Retain only indexed lines,
                # deduplicating hits within the same single occurrence pass.
                lines = {o["start_line"] for o in g["occurrences"]
                         if o["start_line"] in candidates}
                # Each candidate list already contains each prior group once.
                # Only multiple hit lines need a union to deduplicate overlap.
                indexes = (candidates[next(iter(lines))] if len(lines) == 1 else
                           {index for line in lines for index in candidates[line]})
                # Cardinality is known after deduplication. Fill the final list
                # without comprehension spare capacity or a second reference list.
                evidence = [None] * len(indexes)
                for position, index in enumerate(indexes):
                    evidence[position] = previous[index]
                del lines, indexes
            classification = "new_content_same_location" if evidence else "new_content"
            reason = "different_content_at_prior_location" if evidence else "no_prior_content_identity"
            remaining[path_ident] -= 1
            if not remaining[path_ident]:
                candidates = None
                del remaining[path_ident]
        # Evidence lists are comparison-owned, never caller or candidate lists.
        # Sort the output list itself instead of retaining an unsorted copy.
        if len(evidence) > 1:
            evidence.sort(key=_group_sort)
        changes.append({"classification": classification, "reason": reason,
                        "current": g, "previous": evidence})
    unknown_paths = {(g["rule_id"], g["path"]) for g in current["groups"] if g["content_hmac"] is None}
    for g in sorted(previous, key=_group_sort):
        if g["content_hmac"] is not None and prior_ident(g) in current_ids:
            continue
        unmapped = path_map is not None and g["path"] not in comparable_old_paths
        uncertain = g["content_hmac"] is None or prior_ident(g)[:2] in unknown_paths or unmapped
        reason = "content_unavailable_cannot_prove_absence" if uncertain else "not_in_current_full_report"
        if unmapped and g["content_hmac"] is not None:
            reason = "prior_path_unmapped"
        changes.append({"classification": "uncomparable" if uncertain else "absent",
                        "reason": reason,
                        "current": None, "previous": [g]})
    summary = {c: 0 for c in CLASSIFICATIONS}
    summary.update(Counter(c["classification"] for c in changes))
    result = {"schema": COMPARISON_SCHEMA, "key_id": current["key_id"],
              "provenance": dict(PROVENANCE), "summary": summary, "changes": changes}
    if path_map is not None:
        result["path_map"] = [{"old_path": old, "new_path": new} for old, new in sorted(forward.items())]
    return result, current


def dumps(value) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n"


def markdown(comparison: dict) -> str:
    """All dynamic prose is escaped; no report bodies or author metadata."""
    def escape(s):
        return "".join(c if c.isalnum() or c in " /._-" else f"&#{ord(c)};" for c in s)
    lines = ["# Secret ledger comparison", "", "Key ID: " + comparison["key_id"], "",
             "Counts describe content groups, not a security verdict.", "",
             "| Classification | Groups |", "| --- | ---: |"]
    lines += [f"| {name} | {comparison['summary'][name]} |" for name in CLASSIFICATIONS]
    if "path_map" in comparison:
        lines += ["", "Explicit path mapping; unmatched paths are uncomparable.",
                  "", "| Old path | New path |", "| --- | --- |"]
        lines += [f"| {escape(e['old_path'])} | {escape(e['new_path'])} |" for e in comparison["path_map"]]
    lines += ["", "| Classification | Rule | Relative path | Current lines |", "| --- | --- | --- | --- |"]
    for change in comparison["changes"]:
        g = change["current"] or change["previous"][0]
        positions = ", ".join(str(o["start_line"]) for o in change["current"]["occurrences"]) if change["current"] else "absent/unknown"
        lines.append(f"| {change['classification']} | {escape(g['rule_id'])} | {escape(g['path'])} | {positions} |")
    return "\n".join(lines) + "\n"
