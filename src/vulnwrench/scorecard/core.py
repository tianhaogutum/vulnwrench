"""Independent parsers, explicit repository joins, and three-valued policy evaluation."""

from __future__ import annotations

import hashlib
import html
import json
import math
import re
from datetime import datetime, time, timezone
from pathlib import Path
from urllib.parse import urlsplit

MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
# Names documented in the checked-in Scorecard check documentation. Future names
# in evidence are preserved; policy typos must never silently disable a check.
KNOWN_CHECKS = frozenset({
    "Binary-Artifacts", "Branch-Protection", "CI-Tests", "CII-Best-Practices",
    "Code-Review", "Contributors", "Dangerous-Workflow", "Dependency-Update-Tool",
    "Fuzzing", "License", "Maintained", "Packaging", "Pinned-Dependencies", "SAST",
    "SBOM", "Security-Policy", "Signed-Releases", "Token-Permissions",
    "Vulnerabilities", "Webhooks",
})


class InputError(ValueError):
    """Invalid/unsupported input; messages deliberately contain no input values."""


def _need(condition: bool, message: str) -> None:
    if not condition:
        raise InputError(message)


def _object(value, label: str) -> dict:
    _need(isinstance(value, dict), f"{label} must be a JSON object")
    return value


def _text(value) -> bool:
    return isinstance(value, str) and bool(value) and not any(ord(c) < 32 for c in value)


def _number(value) -> bool:
    return type(value) in (int, float) and math.isfinite(value)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        _need(key not in result, "duplicate JSON key (possibly contradictory mapping)")
        result[key] = value
    return result


class _ObjectPairs(list):
    """JSON object entries, retaining repeated keys for mapping lint only."""


def _constant(_value):
    raise InputError("non-finite JSON number is unsupported")


def _float(value):
    result = float(value)
    _need(math.isfinite(result), "non-finite JSON number is unsupported")
    return result


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                      separators=(",", ":")).encode("utf-8")


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _read(path: Path, label: str, budget: list[int], *, preserve_pairs=False):
    try:
        _need(path.is_file(), f"{label} input must be a regular file")
        with path.open("rb") as stream:
            raw = stream.read(MAX_FILE_BYTES + 1)
        _need(len(raw) <= MAX_FILE_BYTES, "input exceeds the 16 MiB per-file limit")
        budget[0] += len(raw)
        _need(budget[0] <= MAX_TOTAL_BYTES, "inputs exceed the 128 MiB total limit")
        document = json.loads(raw.decode("utf-8-sig"),
                              object_pairs_hook=_ObjectPairs if preserve_pairs else _pairs,
                              parse_constant=_constant, parse_float=_float)
        if preserve_pairs:
            _need(isinstance(document, _ObjectPairs), f"{label} must be a JSON object")
        else:
            _object(document, label)
        # Reject unpaired surrogates, including in unknown fields.
        json.dumps(document, ensure_ascii=False).encode("utf-8")
    except InputError:
        raise
    except (OSError, UnicodeError, ValueError, RecursionError):
        raise InputError(f"cannot read valid UTF-8 JSON {label}") from None
    return document, {"sha256": _digest(raw), "document": document}


def normalize_repository(value: str) -> str:
    """Normalize an explicit HTTPS or host/path repository identifier, without I/O.

    GitHub paths are case insensitive. Paths on other hosts retain their case.
    Credentials, ports, URL query/fragment data and percent escapes are rejected.
    """
    message = "repository must be an explicit HTTPS host/owner/repository URL without credentials, port, query or fragment"
    _need(_text(value) and not any(c.isspace() for c in value), message)
    _need("?" not in value and "#" not in value and "\\" not in value, message)
    try:
        parsed = urlsplit(value if "://" in value else "https://" + value)
        host = parsed.hostname
        _need(parsed.scheme == "https" and host is not None
              and parsed.username is None and parsed.password is None
              and parsed.port is None, message)
    except ValueError:
        raise InputError(message) from None
    _need(re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host) is not None
          and "." in host and all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", x)
                                  for x in host.split(".")), message)
    _need(parsed.netloc.lower() == host, message)
    path = parsed.path.removesuffix("/")
    if host == "github.com":
        path = path.lower()
    path = path.removesuffix(".git")
    segments = path.split("/")[1:]
    _need(len(segments) >= 2 and (host != "github.com" or len(segments) == 2)
          and all(re.fullmatch(r"[A-Za-z0-9._~-]+", x) and x not in (".", "..")
                  for x in segments), message)
    return "https://" + host + "/" + "/".join(segments)


def _purl(value):
    # PURLs are opaque join keys: no version, qualifier, escape or case rewriting.
    _need(_text(value) and re.fullmatch(r"pkg:[a-z][a-z0-9.+-]*/[^\s]+", value) is not None,
          "PURL must have pkg:type/name form without whitespace")
    return value


def _timestamp(value, *, as_of=False) -> datetime:
    label = "as-of" if as_of else "Scorecard date"
    _need(isinstance(value, str), f"{label} must be an ISO date or timezone-aware RFC3339 timestamp")
    try:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
            parsed = datetime.strptime(value, "%Y-%m-%d")
            if as_of:
                parsed = datetime.combine(parsed.date(), time.max)
            return parsed.replace(tzinfo=timezone.utc)
        _need(re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})", value) is not None,
              f"{label} must be an ISO date or timezone-aware RFC3339 timestamp")
        if value[-1] != "Z":
            _need(int(value[-5:-3]) <= 23 and int(value[-2:]) <= 59,
                  f"{label} has an invalid timezone offset")
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        raise InputError(f"{label} must be a valid ISO date or timezone-aware RFC3339 timestamp") from None


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _policy(document: dict) -> dict:
    _need(set(document) == {"checks", "maxAgeDays", "missing"},
          "policy requires only checks, maxAgeDays and missing fields")
    checks = _object(document["checks"], "policy checks")
    _need(bool(checks), "policy checks must not be empty")
    for name, threshold in checks.items():
        _need(name in KNOWN_CHECKS, "unknown policy check; consult the supported check names")
        _need(_number(threshold) and 0 <= threshold <= 10,
              "policy check thresholds must be finite numbers between 0 and 10")
    _need(type(document["maxAgeDays"]) is int and document["maxAgeDays"] >= 0,
          "policy maxAgeDays must be a nonnegative integer")
    _need(document["missing"] in ("unknown", "fail"), "policy missing must be unknown or fail")
    return document


def _inventory(document: dict) -> list[dict]:
    _need(document.get("bomFormat") == "CycloneDX", "only CycloneDX JSON is supported")
    _need(document.get("specVersion") in ("1.4", "1.5", "1.6"),
          "only CycloneDX specVersion 1.4, 1.5 and 1.6 are supported")
    _need(type(document.get("version")) is int and document["version"] >= 1,
          "CycloneDX version must be a positive integer")
    result = []
    refs = set()

    def component(node, path, role):
        _object(node, "CycloneDX component")
        _need(_text(node.get("name")) and _text(node.get("type")),
              "CycloneDX component requires a name and type")
        purl = _purl(node["purl"]) if "purl" in node else None
        ref = node.get("bom-ref")
        if "bom-ref" in node:
            _need(_text(ref), "component bom-ref must be a nonempty string")
            _need(ref not in refs, "duplicate component bom-ref")
            refs.add(ref)
        result.append({"component": purl or ref or path, "path": path, "role": role,
                       "purl": purl, "bomRef": ref, "name": node["name"],
                       "version": node.get("version")})
        array(node, "components", path, role)
        if "pedigree" in node:
            pedigree = _object(node["pedigree"], "component pedigree")
            for field in ("ancestors", "descendants", "variants"):
                array(pedigree, field, path + "/pedigree", "pedigree")

    def array(parent, key, path, role):
        if key in parent:
            _need(isinstance(parent[key], list), "component collection must be an array")
            for index, node in enumerate(parent[key]):
                component(node, f"{path}/{key}/{index}", role)

    array(document, "components", "", "inventory")
    if "metadata" in document:
        metadata = _object(document["metadata"], "CycloneDX metadata")
        if "component" in metadata:
            component(metadata["component"], "/metadata/component", "subject")
    if "formulation" in document:
        _need(document["specVersion"] != "1.4", "formulation is unsupported in CycloneDX 1.4")
        _need(isinstance(document["formulation"], list), "CycloneDX formulation must be an array")
        for index, formula in enumerate(document["formulation"]):
            _object(formula, "CycloneDX formula")
            array(formula, "components", f"/formulation/{index}", "formulation")
    return result


def _scorecard(document: dict) -> tuple[str, datetime]:
    repo = _object(document.get("repo"), "Scorecard repo")
    repository = normalize_repository(repo.get("name"))
    _need(_text(repo.get("commit")), "Scorecard repo.commit must be a nonempty string")
    timestamp = _timestamp(document.get("date"))
    checks = document.get("checks")
    _need(isinstance(checks, list), "Scorecard checks must be an array")
    names = set()
    for item in checks:
        _object(item, "Scorecard check")
        _need(_text(item.get("name")), "Scorecard check name must be a nonempty string")
        _need(item["name"] not in names, "duplicate Scorecard check name")
        names.add(item["name"])
        if item.get("score") is not None:
            _need(type(item["score"]) is int and -1 <= item["score"] <= 10,
                  "Scorecard check score must be an integer from -1 to 10, null or absent")
    if "score" in document:
        _need(_number(document["score"]) and -1 <= document["score"] <= 10,
              "Scorecard aggregate score must be a finite number from -1 to 10")
    return repository, timestamp


def _snapshot_paths(path: Path) -> list[Path]:
    try:
        if path.is_file():
            return [path]
        _need(path.is_dir(), "scorecards must be a JSON file or directory")
        entries = sorted(path.iterdir(), key=lambda item: item.name)
        _need(all(item.is_file() and not item.is_symlink() and item.suffix == ".json"
                  for item in entries),
              "scorecard directory must contain only regular .json files (no subdirectories or symlinks)")
        return entries
    except OSError:
        raise InputError("cannot list scorecard inputs") from None


def _load_snapshots(scorecards_path: Path, instant: datetime, budget: list[int]):
    """Validate a complete bundle and select evidence without consulting the clock."""
    snapshots = {}
    by_repo = {}
    for path in _snapshot_paths(scorecards_path):
        document, source = _read(path, "Scorecard document", budget)
        repository, timestamp = _scorecard(document)
        identifier = _digest(_canonical(document))
        if identifier not in snapshots:
            snapshots[identifier] = {"id": identifier, "repository": repository,
                                     "recordedDate": document["date"], "timestamp": _iso(timestamp),
                                     "document": document, "sources": []}
            by_repo.setdefault(repository, []).append(identifier)
        snapshots[identifier]["sources"].append({"file": path.name, "sha256": source["sha256"]})
    repo_index = {}
    for repository, identifiers in sorted(by_repo.items()):
        # Compare datetime values, not lexicographic strings with optional fractions.
        identifiers.sort(key=lambda item: (_timestamp(snapshots[item]["timestamp"]), item))
        seen_times = set()
        for identifier in identifiers:
            timestamp = _timestamp(snapshots[identifier]["timestamp"])
            _need(timestamp not in seen_times, "conflicting Scorecard snapshots share a repository and timestamp")
            seen_times.add(timestamp)
        eligible = [item for item in identifiers if _timestamp(snapshots[item]["timestamp"]) <= instant]
        eligible_set = set(eligible)
        repo_index[repository] = {"selectedSnapshot": eligible[-1] if eligible else None,
                                  "availableSnapshots": identifiers,
                                  "futureSnapshots": [item for item in identifiers if item not in eligible_set]}
    return snapshots, repo_index


def _combine(decisions: list[str]) -> str:
    return "fail" if "fail" in decisions else "unknown" if "unknown" in decisions or not decisions else "pass"


def _evaluate(component, repository, selected, policy, as_of, has_future):
    row = dict(component, repository=repository, snapshotId=None, ageDays=None,
               upstreamScore=None, checks=[])
    missing = policy["missing"]
    reason = None
    if repository is None:
        reason = "missing_purl" if component["purl"] is None else "unmapped_component"
    elif selected is None:
        reason = "no_snapshot_as_of" if has_future else "missing_scorecard"
    else:
        document = selected["document"]
        row.update(snapshotId=selected["id"], upstreamScore=document.get("score"),
                   ageDays=(as_of.date() - _timestamp(document["date"]).date()).days)
        if row["ageDays"] > policy["maxAgeDays"]:
            reason = "stale_snapshot"
    evidence_issue = reason
    checks = {item["name"]: item for item in selected["document"]["checks"]} if selected else {}
    for name, threshold in sorted(policy["checks"].items()):
        item = checks.get(name)
        score = item.get("score") if item else None
        observation = ("missing_check" if item is None else "missing_score" if score is None
                       else "negative_score" if score == -1 else "known")
        check_reason = evidence_issue or (observation if observation != "known" else
                                        "threshold_met" if score >= threshold else "below_threshold")
        decision = ("pass" if check_reason == "threshold_met" else "fail"
                    if check_reason == "below_threshold" else missing)
        row["checks"].append({"name": name, "threshold": threshold, "score": score,
                              "observation": observation, "decision": decision, "reason": check_reason})
    row["decision"] = _combine([item["decision"] for item in row["checks"]])
    if reason is None:
        reason = ("check_below_threshold" if any(item["reason"] == "below_threshold" for item in row["checks"])
                  else "unknown_check" if any(item["observation"] != "known" for item in row["checks"])
                  else "checks_passed")
    row["reason"] = reason
    return row


def check(bom_path, mapping_path, scorecards_path, policy_path, as_of: str) -> dict:
    """Read local inputs and return a deterministic, JSON-serializable report.

    Raises InputError for I/O, unsupported formats and ambiguous evidence. No input
    is executed. The given as_of value is required; no wall clock is consulted.
    """
    try:
        return _check(Path(bom_path), Path(mapping_path), Path(scorecards_path), Path(policy_path), as_of)
    except InputError:
        raise
    except (OSError, ValueError, TypeError, RecursionError, OverflowError):
        raise InputError("invalid or excessively nested input") from None


def _check(bom_path, mapping_path, scorecards_path, policy_path, as_of):
    instant = _timestamp(as_of, as_of=True)
    budget = [0]
    bom, bom_source = _read(bom_path, "SBOM", budget)
    inventory = _inventory(bom)
    mapping, mapping_source = _read(mapping_path, "mapping", budget)
    normalized_map = {_purl(purl): normalize_repository(repo) for purl, repo in mapping.items()}
    policy, policy_source = _read(policy_path, "policy", budget)
    _policy(policy)
    snapshots, repo_index = _load_snapshots(scorecards_path, instant, budget)
    rows = []
    for component in inventory:
        repository = normalized_map.get(component["purl"])
        entry = repo_index.get(repository, {})
        selected = snapshots.get(entry.get("selectedSnapshot"))
        rows.append(_evaluate(component, repository, selected, policy, instant,
                              bool(entry.get("futureSnapshots"))))
    counts = {decision: sum(row["decision"] == decision for row in rows)
              for decision in ("pass", "fail", "unknown")}
    summary = {
        "components": len(rows), "mappedComponents": sum(row["repository"] is not None for row in rows),
        "joinedComponents": sum(row["snapshotId"] is not None for row in rows),
        "freshComponents": sum(row["snapshotId"] is not None and row["reason"] != "stale_snapshot" for row in rows),
        "staleComponents": sum(row["reason"] == "stale_snapshot" for row in rows),
        "unmappedComponents": sum(row["repository"] is None for row in rows),
        "selectedRepositories": len({row["repository"] for row in rows if row["snapshotId"]}),
        "unusedMappings": sorted(set(normalized_map) - {row["purl"] for row in rows}),
        **counts,
    }
    decision = _combine([row["decision"] for row in rows])
    return {
        "reportVersion": "1", "tool": {"name": "scorecard-join", "version": "0.1.0"},
        "asOf": _iso(instant), "decision": decision,
        "gate": {"passed": decision == "pass", "exitCode": 0 if decision == "pass" else 1},
        "summary": summary, "components": rows, "repositoryIndex": repo_index,
        "snapshots": [snapshots[item] for item in sorted(snapshots)],
        "inputs": {"bom": bom_source, "mapping": mapping_source, "policy": policy_source},
    }


def gate_exit_code(report: dict) -> int:
    """A gate passes only on positive evidence; both unknown and fail withhold it."""
    return report["gate"]["exitCode"]


def render_markdown(report: dict) -> str:
    """Human summary plus a lossless JSON evidence appendix. Raw HTML is escaped."""
    def cell(value):
        return html.escape(str(value) if value is not None else "—").replace("|", "&#124;").replace("\r", " ").replace("\n", " ")

    lines = ["# Scorecard join", "", f"As of: {cell(report['asOf'])}", "",
             f"Decision: **{report['decision']}**; gate exit code: {gate_exit_code(report)}.", "",
             "Repository health evidence is not a release-commit attestation or a new security score.", "",
             "| Component | Location | Repository | Decision | Reason | Age (days) | Upstream score |",
             "| --- | --- | --- | --- | --- | --- | --- |"]
    for row in report["components"]:
        lines.append("| " + " | ".join(cell(row[key]) for key in
                     ("component", "path", "repository", "decision", "reason", "ageDays", "upstreamScore")) + " |")
    lines.extend(["", "## Evidence and check decisions", "",
                  "The JSON appendix retains every source document, selected check decision and digest.", ""])
    appendix = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False)
    # A longer fence prevents input backticks from escaping the literal appendix.
    fence = "`" * max(3, 1 + max((len(run) for run in re.findall(r"`+", appendix)), default=0))
    # Escape HTML-sensitive characters as JSON unicode escapes; json.loads is lossless.
    appendix = appendix.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    lines.extend([fence + "json", appendix, fence, ""])
    return "\n".join(lines)
