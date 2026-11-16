"""Independent, offline SARIF 2.1.0 gate. No scanner or network integration."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote, urlsplit, urlunsplit

LEVELS = {"none": 0, "note": 1, "warning": 2, "error": 3}
STATUSES = {"accepted", "rejected", "underReview"}
BASELINES = {"new", "unchanged", "updated", "absent"}


class InputError(ValueError):
    """Invalid input; messages contain fixed schema paths, never input values."""


@dataclass(frozen=True)
class Policy:
    level: str = "warning"
    ignore_unchanged: bool = False
    require_execution_success: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.level, str) or self.level not in {"note", "warning", "error"}:
            raise InputError("policy.level: expected note, warning or error")
        if type(self.ignore_unchanged) is not bool or type(self.require_execution_success) is not bool:
            raise InputError("policy: flags must be booleans")


def _obj(value: Any, path: str) -> dict:
    if not isinstance(value, dict):
        raise InputError(f"{path}: expected object")
    return value


def _array(value: Any, path: str) -> list:
    if not isinstance(value, list):
        raise InputError(f"{path}: expected array")
    return value


def _string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value:
        raise InputError(f"{path}: expected nonempty string")
    return value


def _enum(value: Any, choices: Any, path: str) -> str:
    if not isinstance(value, str) or value not in choices:
        raise InputError(f"{path}: unsupported value")
    return value


def _local_uri(value: Any, path: str) -> str:
    """Validate the local, UTF-8 URI subset before urllib can strip controls.

    Work exclusively on strings. Percent escapes stay encoded until display;
    neither escaped separators nor escaped dot segments become resolution steps.
    """
    uri = _string(value, path)
    if (not re.fullmatch(r"[A-Za-z0-9._~!$&'()*+,;=:@/%-]+", uri)
            or re.search(r"%(?![0-9A-Fa-f]{2})", uri)):
        raise InputError(f"{path}: malformed or unsupported local URI")
    try:
        decoded = unquote(uri, encoding="utf-8", errors="strict")
        parts = urlsplit(uri)
    except (ValueError, UnicodeError):
        raise InputError(f"{path}: malformed local URI") from None
    if any(ord(c) < 32 or ord(c) == 127 for c in decoded):
        raise InputError(f"{path}: URI controls are unsupported")
    if parts.scheme:
        if parts.scheme != "file":
            raise InputError(f"{path}: only local file URIs and relative references are supported")
        if parts.netloc.lower() not in {"", "localhost"} or not parts.path.startswith("/"):
            raise InputError(f"{path}: expected absolute local file URI without remote authority")
        if parts.path.startswith("//"):
            raise InputError(f"{path}: network paths are unsupported")
        uri = urlunsplit(("file", "", parts.path, "", ""))
    elif uri.startswith("//"):
        raise InputError(f"{path}: network references are unsupported")
    return re.sub(r"%[0-9A-Fa-f]{2}", lambda m: m[0].upper(), uri)


class _LocationResolver:
    """Run-local URI bases and explicit primary/related artifact lookup; no I/O.

    SARIF 2.1.0 sections 3.4 and 3.14.14. Bases concatenate directory
    references; artifact references expand bases and normalize literal dots
    only. Parent segments may cross symlinks and must remain visible.
    """

    def __init__(self, run: dict, path: str):
        self.run = run
        self.run_path = path
        self.column_kind_consumed = False
        self.path = path + "/originalUriBaseIds"
        bases = _obj(run.get("originalUriBaseIds", {}), self.path)
        entries = {}
        self.resolved: dict[str, str] = {}
        # Base symbols are untrusted values, so diagnostics use a fixed path.
        for key in sorted(bases):
            _string(key, self.path + "/entry")
            uri, parent = self._artifact(bases[key], self.path + "/entry")
            if not uri.endswith("/") or uri.endswith("//") or ".." in urlsplit(uri).path.split("/"):
                raise InputError(f"{self.path}/entry/uri: expected directory URI without parent segments")
            if not uri.startswith("file:"):
                if uri.startswith("/"):
                    raise InputError(f"{self.path}/entry/uri: rooted relative bases are unsupported")
                if parent is None:
                    raise InputError(f"{self.path}/entry/uriBaseId: relative base requires parent")
            entries[key] = (uri, parent)
        # Iterative traversal handles long chains without Python recursion.
        for key in entries:
            chain = []
            visiting = set()
            cursor = key
            while cursor not in self.resolved:
                if cursor in visiting:
                    raise InputError(f"{self.path}: cyclic URI base references")
                if cursor not in entries:
                    raise InputError(f"{self.path}: referenced URI base is missing")
                visiting.add(cursor)
                chain.append(cursor)
                uri, parent = entries[cursor]
                if parent is None:
                    self.resolved[cursor] = uri
                    break
                cursor = parent
            for symbol in reversed(chain):
                uri, parent = entries[symbol]
                if parent is not None:
                    self.resolved[symbol] = self.resolved[parent] + uri

    @staticmethod
    def _artifact(value: Any, path: str, self_index: int | None = None) -> tuple[str, str | None]:
        artifact = _obj(value, path)
        if "index" in artifact:
            if self_index is None:
                raise InputError(f"{path}/index: artifact-index references are unsupported here")
            if type(artifact["index"]) is not int or artifact["index"] != self_index:
                raise InputError(f"{path}/index: expected the containing artifact index")
        uri = _local_uri(artifact.get("uri"), path + "/uri")
        parent = (_string(artifact["uriBaseId"], path + "/uriBaseId")
                  if "uriBaseId" in artifact else None)
        if uri.startswith("file:") and parent is not None:
            raise InputError(f"{path}/uriBaseId: absolute URI must not specify a base")
        return uri, parent

    def location(self, location: dict, path: str) -> list[dict]:
        if "physicalLocation" not in location:
            return []
        physical = _obj(location["physicalLocation"], path + "/physicalLocation")
        if "artifactLocation" not in physical:
            return []
        pointer = path + "/physicalLocation/artifactLocation"
        artifact = _obj(physical["artifactLocation"], pointer)
        if "index" not in artifact:
            uri = self._resolve_uri(artifact, pointer)
            catalog_pointer = None
        else:
            index = artifact["index"]
            if type(index) is not int or index < 0:
                raise InputError(f"{pointer}/index: expected nonnegative integer")
            catalog_path = self.run_path + "/artifacts"
            catalog = _array(self.run.get("artifacts"), catalog_path)
            if index >= len(catalog):
                raise InputError(f"{pointer}/index: artifact index out of range")
            entry_path = f"{catalog_path}/{index}"
            entry = _obj(catalog[index], entry_path)
            for key in ("parentIndex", "offset", "length"):
                if key in entry:
                    raise InputError(f"{entry_path}/{key}: nested-container artifacts are unsupported")
            catalog_pointer = entry_path + "/location"
            # Catalog locations may repeat their own index, but must have an
            # inline URI. Never recurse through a catalog index or container.
            uri = self._resolve_uri(entry.get("location"), catalog_pointer, index)
            if "uri" in artifact:
                # Display and agreement share encoded dot-only resolution;
                # neither parent removal nor display decoding proves identity.
                if self._resolve_uri(artifact, pointer, index) != uri:
                    raise InputError(f"{pointer}: inline URI and artifact index disagree")
            elif "uriBaseId" in artifact:
                raise InputError(f"{pointer}/uriBaseId: base requires an inline URI")
        display = urlsplit(uri).path if uri.startswith("file:") else uri
        resolved = {"sourcePointer": pointer, "resolvedUri": uri,
                    "displayPath": unquote(display, encoding="utf-8", errors="strict")}
        if catalog_pointer is not None:
            resolved["artifactSourcePointer"] = catalog_pointer
        if "region" in physical:
            region_pointer = path + "/physicalLocation/region"
            region = _obj(physical["region"], region_pointer)
            source_lines = {}
            for key in ("startLine", "endLine"):
                if key in region:
                    if type(region[key]) is not int or region[key] <= 0:
                        raise InputError(f"{region_pointer}/{key}: expected positive integer")
                    source_lines[key] = region[key]
            if "endLine" in source_lines:
                if "startLine" not in source_lines:
                    raise InputError(f"{region_pointer}/endLine: requires startLine")
                if source_lines["endLine"] < source_lines["startLine"]:
                    raise InputError(f"{region_pointer}/endLine: must be at least startLine")
            if source_lines:
                resolved["sourceLineRange"] = source_lines
                resolved["regionSourcePointer"] = region_pointer
                # Display only explicit columns of an explicit source-line
                # region. Never derive coordinates from offsets or snippets.
                source_columns = {}
                for key in ("startColumn", "endColumn"):
                    if key in region:
                        if type(region[key]) is not int or region[key] <= 0:
                            raise InputError(f"{region_pointer}/{key}: expected positive integer")
                        source_columns[key] = region[key]
                # SARIF's omitted endLine denotes the start line for ordering
                # only; do not add that default to the reported coordinates.
                if ("startColumn" in source_columns and "endColumn" in source_columns
                        and source_lines.get("endLine", source_lines["startLine"]) == source_lines["startLine"]
                        and source_columns["endColumn"] < source_columns["startColumn"]):
                    raise InputError(f"{region_pointer}/endColumn: must be at least startColumn on the same line")
                if source_columns:
                    resolved["sourceColumnRange"] = source_columns
                    # A run declaration labels only displayed source columns.
                    # Omission never infers SARIF's default or converts values.
                    if "columnKind" in self.run:
                        unit_pointer = self.run_path + "/columnKind"
                        unit = self.run["columnKind"]
                        if not isinstance(unit, str) or unit not in {"utf16CodeUnits", "unicodeCodePoints"}:
                            raise InputError(f"{unit_pointer}: expected one of unicodeCodePoints, utf16CodeUnits")
                        resolved["sourceColumnUnit"] = unit
                        resolved["columnKindSourcePointer"] = unit_pointer
                        self.column_kind_consumed = True
            if "byteOffset" in region:
                offset = region["byteOffset"]
                if type(offset) is not int or offset < -1:
                    raise InputError(f"{region_pointer}/byteOffset: expected integer at least -1")
                # -1 means unknown, not a byte position. Lengths without a
                # known explicit offset stay raw; never fill SARIF defaults.
                if offset >= 0:
                    source_bytes = {"byteOffset": offset}
                    if "byteLength" in region:
                        length = region["byteLength"]
                        if type(length) is not int or length < 0:
                            raise InputError(f"{region_pointer}/byteLength: expected nonnegative integer")
                        source_bytes["byteLength"] = length
                    resolved["sourceByteRange"] = source_bytes
                    resolved["regionSourcePointer"] = region_pointer
            if "charOffset" in region:
                offset = region["charOffset"]
                if type(offset) is not int or offset < -1:
                    raise InputError(f"{region_pointer}/charOffset: expected integer at least -1")
                # -1 means unknown, not a character position. Lengths without a
                # known explicit offset stay raw; never fill SARIF defaults.
                if offset >= 0:
                    source_characters = {"charOffset": offset}
                    if "charLength" in region:
                        length = region["charLength"]
                        if type(length) is not int or length < 0:
                            raise InputError(f"{region_pointer}/charLength: expected nonnegative integer")
                        source_characters["charLength"] = length
                    resolved["sourceCharacterRange"] = source_characters
                    resolved["regionSourcePointer"] = region_pointer
        return [resolved]

    def _resolve_uri(self, value: Any, pointer: str, self_index: int | None = None) -> str:
        """Expand explicit bases without collapsing parents or decoding escapes."""
        uri, parent = self._artifact(value, pointer, self_index)
        if parent is not None:
            if parent not in self.resolved:
                raise InputError(f"{pointer}/uriBaseId: referenced URI base is missing")
            # Bases are absolute local directory URIs. Rooted references
            # replace the path; other references concatenate with the base.
            uri = "file://" + uri if uri.startswith("/") else self.resolved[parent] + uri
        parts = urlsplit(uri)
        segments = parts.path.split("/")
        # A final dot denotes a directory, so preserve its trailing separator.
        if segments[-1] == ".":
            segments[-1] = ""
        path = "/".join(segment for segment in segments if segment != ".")
        if not path:
            path = "./" if parts.path.endswith(("/", "/.")) else "."
        if parts.scheme:
            uri = urlunsplit((parts.scheme, "", path, "", ""))
        else:
            # No base means no CWD guessing. Removing './' must not turn a
            # relative reference into a rooted path or a scheme reference.
            if not parts.path.startswith("/") and (path.startswith("/") or ":" in path.split("/")[0]):
                path = "./" + path
            uri = path
        # Dot removal can expose a leading double slash in a file URI. Keep
        # the resolved value inside the same local subset as the input.
        return _local_uri(uri, pointer + "/uri")


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict:
    out: dict = {}
    for key, value in pairs:
        if key in out:
            raise InputError("JSON: duplicate object key")
        out[key] = value
    return out


def _no_constant(_: str) -> None:
    raise InputError("JSON: non-finite number")


def parse_document(data: bytes) -> dict:
    """Parse one UTF-8 JSON document; reject duplicate keys and non-JSON numbers."""
    try:
        document = json.loads(data.decode("utf-8-sig"), object_pairs_hook=_no_duplicates,
                              parse_constant=_no_constant)
        # Overflowing JSON floats must not become Infinity on output.
        json.dumps(document, allow_nan=False)
    except (UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, InputError):
            raise
        raise InputError("input: invalid UTF-8 JSON or excessive nesting") from None
    return _obj(document, "document")


def dumps(report: dict) -> str:
    """Deterministic JSON safe to embed as text (also escapes HTML metacharacters)."""
    return (json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False)
            .replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026") + "\n")


class _RuleResolver:
    """Inline catalogs only; numeric references never fall back across components."""

    def __init__(self, tool: dict, path: str, fields: Any):
        self.path, self.fields = path, fields
        driver = _obj(tool.get("driver"), path + "/driver")
        extensions = _array(tool.get("extensions", []), path + "/extensions")
        self.components = [driver, *extensions]
        self.catalogs = []
        self.by_ids = []
        for ci, component in enumerate(self.components):
            cp = self.component_path(ci)
            _obj(component, cp)
            _string(component.get("name"), cp + "/name")
            rules = _array(component.get("rules", []), cp + "/rules")
            by_id = {}
            for index, rule in enumerate(rules):
                rulep = f"{cp}/rules/{index}"
                _obj(rule, rulep)
                rule_id = _string(rule.get("id"), rulep + "/id")
                if rule_id in by_id:
                    raise InputError(cp + "/rules: duplicate rule id")
                by_id[rule_id] = index
                config = _obj(rule.get("defaultConfiguration", {}), rulep + "/defaultConfiguration")
                _enum(config.get("level", "warning"), LEVELS, rulep + "/defaultConfiguration/level")
                fields(config, rulep + "/defaultConfiguration", {"level"})
                fields(rule, rulep, {"id", "defaultConfiguration"})
            self.catalogs.append(rules)
            self.by_ids.append(by_id)
            fields(component, cp, {"name", "rules"})
        fields(tool, path, {"driver", "extensions"})

    def component_path(self, ci: int) -> str:
        return self.path + ("/driver" if ci == 0 else f"/extensions/{ci - 1}")

    @staticmethod
    def index(value: Any, size: int, path: str) -> int:
        if type(value) is not int or value < -1 or (value != -1 and value >= size):
            raise InputError(path + ": invalid catalog index")
        return value

    def resolve(self, result: dict, path: str) -> dict:
        reference = _obj(result.get("rule", {}), path + "/rule")
        if "guid" in reference:
            raise InputError(path + "/rule/guid: GUID references are unsupported")
        component_ref = _obj(reference.get("toolComponent", {}), path + "/rule/toolComponent")
        if "guid" in component_ref:
            raise InputError(path + "/rule/toolComponent/guid: GUID references are unsupported")
        ci = self.index(component_ref.get("index", -1), len(self.components) - 1,
                        path + "/rule/toolComponent/index") + 1
        component = self.components[ci]
        cp = self.component_path(ci)
        if "name" in component_ref:
            if _string(component_ref["name"], path + "/rule/toolComponent/name") != component["name"]:
                raise InputError(path + "/rule/toolComponent/name: conflicts with selected component")
        rules = self.catalogs[ci]
        supplied_id = None
        for obj, key, p in ((result, "ruleId", path), (reference, "id", path + "/rule")):
            if key in obj:
                value = _string(obj[key], p + "/" + key)
                if supplied_id is not None and supplied_id != value:
                    raise InputError(path + "/rule/id: conflicts with ruleId")
                supplied_id = value
        legacy_index = self.index(result.get("ruleIndex", -1), len(rules), path + "/ruleIndex")
        index = self.index(reference.get("index", legacy_index), len(rules), path + "/rule/index")
        if "ruleIndex" in result and "index" in reference and index != legacy_index:
            raise InputError(path + "/rule/index: conflicts with ruleIndex")
        resolved = None if index == -1 else index
        if resolved is None:
            if "rule" in result:
                # ID-only descriptor references carry no metadata (3.52.1).
                # Keep legacy result.ruleId lookup, but do not invent an index
                # for new descriptor/component reference objects.
                if ci != 0 or rules or supplied_id is None or "toolComponent" in reference:
                    raise InputError(path + "/rule/index: numeric rule reference required")
            elif supplied_id is not None:
                resolved = self.by_ids[ci].get(supplied_id)
                if resolved is None and rules:
                    raise InputError(path + "/ruleId: not found in nonempty driver catalog")
        rulep = None if resolved is None else f"{cp}/rules/{resolved}"
        descriptor = None if resolved is None else rules[resolved]
        if descriptor is not None and supplied_id is not None:
            catalog_id = descriptor["id"]
            suffix = supplied_id[len(catalog_id):]
            # The optional extra hierarchical component may be empty (3.5.4).
            if supplied_id != catalog_id and not (supplied_id.startswith(catalog_id + "/")
                                                  and suffix.count("/") == 1):
                raise InputError(path + "/ruleId: conflicts with selected rule")
        rule_id = supplied_id if supplied_id is not None else descriptor["id"] if descriptor else None
        if "level" in result:
            level = _enum(result["level"], LEVELS, path + "/level")
            level_source, levelp = "result.level", path + "/level"
        elif descriptor is not None and "level" in descriptor.get("defaultConfiguration", {}):
            level = descriptor["defaultConfiguration"]["level"]
            level_source, levelp = "rule.defaultConfiguration.level", rulep + "/defaultConfiguration/level"
        else:
            level, level_source, levelp = "warning", "sarif_default", None
        if "rule" in result:
            self.fields(reference, path + "/rule", {"id", "index", "toolComponent"})
            if "toolComponent" in reference:
                self.fields(component_ref, path + "/rule/toolComponent", {"name", "index"})
        return {"ruleId": rule_id, "ruleIndex": resolved,
                "ruleResolution": "resolved" if resolved is not None else "unlisted",
                "ruleComponent": {"kind": "driver" if ci == 0 else "extension",
                                  "index": None if ci == 0 else ci - 1,
                                  "name": component["name"], "sourcePointer": cp},
                "ruleSourcePointer": rulep, "level": level, "levelSource": level_source,
                "levelSourcePointer": levelp}


def evaluate(document: dict, policy: Policy | None = None, *, source_sha256: str | None = None) -> dict:
    """Evaluate a JSON-compatible tree without modifying it. All evidence is retained.

    ``source_sha256`` identifies exact input bytes when using ``check_bytes``;
    direct library calls instead receive a canonical-document digest.
    """
    policy = policy or Policy()
    try:
        canonical = json.dumps(document, sort_keys=True, ensure_ascii=True, allow_nan=False).encode()
        # The library takes JSON trees, not Python mappings with coerced keys or
        # tuples. JSON round-trip equality detects those without dropping data.
        if json.loads(canonical) != document:
            raise ValueError
        document = copy.deepcopy(document)
    except (TypeError, ValueError, RecursionError):
        raise InputError("document: expected a finite JSON-compatible tree") from None
    _obj(document, "document")
    if document.get("version") != "2.1.0":
        raise InputError("/version: only SARIF 2.1.0 is supported")
    if "inlineExternalProperties" in document:
        raise InputError("/inlineExternalProperties: externalized SARIF is unsupported")
    runs = _array(document.get("runs"), "/runs")
    uninterpreted: list[str] = []

    def fields(obj: dict, path: str, used: set[str]) -> None:
        for key in sorted(obj.keys() - used):
            token = key.replace("~", "~0").replace("/", "~1")
            uninterpreted.append(f"{path}/{token}")

    fields(document, "", {"version", "runs"})
    traces: list[dict] = []
    run_traces: list[dict] = []
    failures: list[dict] = []
    totals = {"results": 0, "eligible": 0, "actionable": 0, "acceptedSuppressions": 0,
              "baselineExcluded": 0, "belowThreshold": 0, "unlocated": 0,
              "failedInvocations": 0, "errorNotifications": 0,
              "unknownExecutionRuns": 0, "unknownExecutionInvocations": 0}
    for ri, run in enumerate(runs):
        rp = f"/runs/{ri}"
        _obj(run, rp)
        # These features can move findings/rules or change effective defaults.
        for key in ("externalPropertyFileReferences", "inlineExternalProperties"):
            if key in run:
                raise InputError(f"{rp}/{key}: externalized SARIF is unsupported")
        location_resolver = _LocationResolver(run, rp)
        tool = _obj(run.get("tool"), rp + "/tool")
        rule_resolver = _RuleResolver(tool, rp + "/tool", fields)
        name = tool["driver"]["name"]
        invocations = _array(run.get("invocations", []), rp + "/invocations")
        invocation_traces = []
        unknown_execution = not invocations
        run_failed = False
        for ii, invocation in enumerate(invocations):
            ip = f"{rp}/invocations/{ii}"
            _obj(invocation, ip)
            for key in ("ruleConfigurationOverrides", "notificationConfigurationOverrides"):
                if key in invocation:
                    raise InputError(f"{ip}/{key}: configuration overrides are unsupported")
            success = invocation.get("executionSuccessful")
            if "executionSuccessful" in invocation and type(success) is not bool:
                raise InputError(f"{ip}/executionSuccessful: expected boolean")
            reasons = []
            if success is False:
                totals["failedInvocations"] += 1
                reasons.append("execution_unsuccessful")
            if success is None:
                unknown_execution = True
                totals["unknownExecutionInvocations"] += 1
                if policy.require_execution_success:
                    reasons.append("execution_success_unknown")
            notifications = _array(invocation.get("toolExecutionNotifications", []),
                                   ip + "/toolExecutionNotifications")
            notification_traces = []
            for ni, notification in enumerate(notifications):
                np = f"{ip}/toolExecutionNotifications/{ni}"
                _obj(notification, np)
                level = _enum(notification.get("level", "warning"), LEVELS, np + "/level")
                _message(notification.get("message"), np + "/message", fields)
                if level == "error":
                    totals["errorNotifications"] += 1
                    reasons.append("tool_execution_error")
                notification_traces.append({"sourcePointer": np, "level": level})
                fields(notification, np, {"level", "message"})
            if reasons:
                failures.append({"sourcePointer": ip, "reasons": list(dict.fromkeys(reasons))})
                run_failed = True
            invocation_traces.append({"sourcePointer": ip, "executionSuccessful": success,
                                      "notifications": notification_traces, "failed": bool(reasons)})
            fields(invocation, ip, {"executionSuccessful", "toolExecutionNotifications"})
        if not invocations and policy.require_execution_success:
            failures.append({"sourcePointer": rp, "reasons": ["execution_success_unknown"]})
            run_failed = True
        if unknown_execution:
            totals["unknownExecutionRuns"] += 1
        results = _array(run.get("results", []), rp + "/results")
        for rsi, result in enumerate(results):
            p = f"{rp}/results/{rsi}"
            _obj(result, p)
            if result.get("kind", "fail") != "fail":
                raise InputError(f"{p}/kind: only fail results are supported")
            rule_trace = rule_resolver.resolve(result, p)
            level = rule_trace["level"]
            message = _message(result.get("message"), p + "/message", fields)
            suppressions = _array(result.get("suppressions", []), p + "/suppressions")
            suppression_traces = []
            for si, suppression in enumerate(suppressions):
                sp = f"{p}/suppressions/{si}"
                _obj(suppression, sp)
                kind = _enum(suppression.get("kind"), {"inSource", "external"}, sp + "/kind")
                status = (_enum(suppression["status"], STATUSES, sp + "/status")
                          if "status" in suppression else "unspecified")
                suppression_traces.append({"sourcePointer": sp, "kind": kind, "status": status})
                fields(suppression, sp, {"kind", "status"})
            accepted = any(s["status"] == "accepted" for s in suppression_traces)
            baseline = (_enum(result["baselineState"], BASELINES, p + "/baselineState")
                        if "baselineState" in result else "unspecified")
            baseline_excluded = baseline == "absent" or (baseline == "unchanged" and policy.ignore_unchanged)
            locations = _array(result.get("locations", []), p + "/locations")
            resolved_locations = _resolve_locations(locations, p + "/locations", location_resolver, fields)
            related_locations = _array(result.get("relatedLocations", []), p + "/relatedLocations")
            resolved_related_locations = _resolve_locations(
                related_locations, p + "/relatedLocations", location_resolver, fields)
            reasons = []
            if accepted:
                reasons.append("accepted_suppression")
            if baseline_excluded:
                reasons.append("baseline_absent" if baseline == "absent" else "unchanged_ignored")
            eligible = not accepted and not baseline_excluded
            meets_level = LEVELS[level] >= LEVELS[policy.level]
            if not meets_level:
                reasons.append("below_threshold")
            blocking = eligible and meets_level
            if blocking:
                reasons.append("at_or_above_threshold")
            totals["results"] += 1
            totals["eligible"] += int(eligible)
            totals["actionable"] += int(blocking)
            totals["acceptedSuppressions"] += int(accepted)
            totals["baselineExcluded"] += int(baseline_excluded)
            totals["belowThreshold"] += int(not meets_level)
            totals["unlocated"] += int(not locations)
            traces.append({"sourcePointer": p, "runIndex": ri, "resultIndex": rsi,
                           **rule_trace, "message": message,
                           "suppressions": suppression_traces, "baselineState": baseline,
                           "hasLocation": bool(locations), "eligible": eligible,
                           "blocking": blocking, "reasons": reasons})
            if locations:
                traces[-1]["resolvedLocations"] = resolved_locations
            if related_locations:
                traces[-1]["resolvedRelatedLocations"] = resolved_related_locations
            fields(result, p, {"ruleId", "ruleIndex", "rule", "level", "message", "suppressions",
                               "baselineState", "kind"})
        run_traces.append({"sourcePointer": rp, "tool": name, "resultsPresent": "results" in run,
                           "executionStatus": "failed" if run_failed else "unknown" if unknown_execution else "successful",
                           "invocations": invocation_traces})
        fields(run, rp, {"tool", "results", "invocations"} |
               ({"columnKind"} if location_resolver.column_kind_consumed else set()))
    if not runs and policy.require_execution_success:
        failures.append({"sourcePointer": "/runs", "reasons": ["no_runs"]})
    totals["scanFailures"] = len(failures)
    naive = sum(result.get("level") in {"warning", "error"} for run in runs
                for result in run.get("results", []))
    return {"schemaVersion": "sarif-gate/1", "generator": {"name": "sarif-gate", "version": "0.1.0"},
            "policy": {"level": policy.level, "ignoreUnchanged": policy.ignore_unchanged,
                       "requireExecutionSuccess": policy.require_execution_success},
            "decision": "fail" if totals["actionable"] or failures else "pass",
            "actionable": totals["actionable"], "acceptedSuppressions": totals["acceptedSuppressions"],
            "totals": totals, "results": traces, "runs": run_traces, "scanFailures": failures,
            "naive": {"explicitWarningErrorCount": naive, "decision": "fail" if naive else "pass"},
            "evidence": {"sha256": source_sha256 or hashlib.sha256(canonical).hexdigest(),
                         "digestKind": "input_bytes" if source_sha256 else "canonical_json",
                         "document": document, "uninterpretedFields": sorted(uninterpreted),
                         "notice": "Uninterpreted fields are retained, not used in gate policy; no completeness claim."}}


def _resolve_locations(locations: list, path: str, resolver: _LocationResolver, fields: Any) -> list[dict]:
    entries = []
    for index, location in enumerate(locations):
        pointer = f"{path}/{index}"
        resolved = resolver.location(_obj(location, pointer), pointer)
        # Like source lines, consume optional display data only when a path
        # resolves. Pathless messages remain raw evidence in either collection.
        if resolved and "message" in location:
            message_pointer = pointer + "/message"
            literal = _message(location["message"], message_pointer, fields)
            selected = "text" if "text" in location["message"] else "markdown"
            for entry in resolved:
                entry["message"] = literal
                entry["messageSourcePointer"] = message_pointer + "/" + selected
        if resolved:
            # The resolver already validated this physical region. Keep its
            # literal message separate from location/result messages and use
            # selected-field provenance even when no coordinates are supplied.
            region = location["physicalLocation"].get("region", {})
            if "message" in region:
                message_pointer = pointer + "/physicalLocation/region/message"
                literal = _message(region["message"], message_pointer, fields)
                selected = "text" if "text" in region["message"] else "markdown"
                for entry in resolved:
                    entry["regionMessage"] = literal
                    entry["regionMessageSourcePointer"] = message_pointer + "/" + selected
        entries.extend(resolved)
    return entries


def _message(value: Any, path: str, fields: Any) -> str:
    message = _obj(value, path)
    for key in ("text", "markdown", "id"):
        if key in message:
            _string(message[key], path + "/" + key)
    if not ("text" in message or "markdown" in message):
        raise InputError(f"{path}: text or markdown required; id-only messages are unsupported")
    fields(message, path, {"text", "markdown"})
    return message.get("text", message.get("markdown"))


def check_bytes(data: bytes, policy: Policy | None = None) -> dict:
    return evaluate(parse_document(data), policy, source_sha256=hashlib.sha256(data).hexdigest())


def _escape(value: Any) -> str:
    # Encode punctuation too: no links, HTML, tables, images, or terminal controls.
    out = []
    for char in str(value):
        if char.isalnum() or char == " ":
            out.append(char)
        elif char in "\n\r\t":
            out.append(" ")
        else:
            out.append(f"&#{ord(char)};")
    return "".join(out)


def markdown_summary(report: dict) -> str:
    totals = report["totals"]
    lines = ["# SARIF gate", "", f"Decision: **{report['decision']}**", "",
             f"Results: {totals['results']}; blocking: {totals['actionable']}; "
             f"accepted-suppressed results: {totals['acceptedSuppressions']}; "
             f"scan failures: {totals['scanFailures']}; unlocated: {totals['unlocated']}.", "",
             f"Unknown execution runs: {totals['unknownExecutionRuns']}; "
             f"runs: {len(report['runs'])}. A pass is a policy decision, not proof of a complete scan.", "",
             "| Run/result | Rule | Level / source | Blocking | Reasons | Message |",
             "| --- | --- | --- | --- | --- | --- |"]
    for result in report["results"]:
        cells = [f"{result['runIndex']}/{result['resultIndex']}", result["ruleId"] or "(unlisted)",
                 f"{result['level']} / {result['levelSource']}", str(result["blocking"]).lower(),
                 ", ".join(result["reasons"]), result["message"]]
        lines.append("| " + " | ".join(_escape(c) for c in cells) + " |")
    for field, title in (("resolvedLocations", "Locations"),
                         ("resolvedRelatedLocations", "Related locations")):
        if not any(r.get(field) for r in report["results"]):
            continue
        show_messages = any(
            "message" in location for result in report["results"] for location in result.get(field, []))
        show_region_messages = any(
            "regionMessage" in location for result in report["results"] for location in result.get(field, []))
        show_units = any(
            "sourceColumnUnit" in location for result in report["results"] for location in result.get(field, []))
        show_bytes = any(
            "sourceByteRange" in location for result in report["results"] for location in result.get(field, []))
        show_characters = any(
            "sourceCharacterRange" in location for result in report["results"] for location in result.get(field, []))
        columns = ["Run/result", "Path", "Source pointer"]
        if show_units:
            columns.extend(["Column unit", "Unit source pointer"])
        if show_bytes:
            columns.extend(["Byte range", "Byte region source pointer"])
        if show_characters:
            columns.extend(["Character range", "Character region source pointer"])
        if show_messages:
            columns.append("Message")
        if show_region_messages:
            columns.extend(["Region message", "Region message source pointer"])
        lines.extend(["", "## " + title, "",
                      "Paths are report-supplied display text; no artifacts are opened.", "",
                      "| " + " | ".join(columns) + " |", "| " + " | ".join("---" for _ in columns) + " |"])
        for result in report["results"]:
            for location in result.get(field, []):
                display = location["displayPath"]
                if "sourceLineRange" in location:
                    source_lines = location["sourceLineRange"]
                    display += f":{source_lines['startLine']}"
                    if "endLine" in source_lines:
                        display += f"-{source_lines['endLine']}"
                if "sourceColumnRange" in location:
                    # Labels preserve endpoint roles without filling absent
                    # columns/lines or converting the exclusive endColumn.
                    display += " (" + ", ".join(
                        f"{key}={value}" for key, value in location["sourceColumnRange"].items()) + ")"
                cells = [f"{result['runIndex']}/{result['resultIndex']}",
                         display, location["sourcePointer"]]
                if show_units:
                    cells.extend([location.get("sourceColumnUnit", ""), location.get("columnKindSourcePointer", "")])
                if show_bytes:
                    byte_range = location.get("sourceByteRange")
                    cells.extend([", ".join(f"{key}={value}" for key, value in byte_range.items())
                                  if byte_range is not None else "",
                                  location["regionSourcePointer"] if byte_range is not None else ""])
                if show_characters:
                    character_range = location.get("sourceCharacterRange")
                    cells.extend([", ".join(f"{key}={value}" for key, value in character_range.items())
                                  if character_range is not None else "",
                                  location["regionSourcePointer"] if character_range is not None else ""])
                if show_messages:
                    cells.append(location.get("message", ""))
                if show_region_messages:
                    cells.extend([location.get("regionMessage", ""), location.get("regionMessageSourcePointer", "")])
                lines.append("| " + " | ".join(_escape(c) for c in cells) + " |")
    lines.extend(["", "## Scan failures", ""])
    lines.extend("- " + _escape(f"{f['sourcePointer']}: {', '.join(f['reasons'])}")
                 for f in report["scanFailures"])
    if not report["scanFailures"]:
        lines.append("None reported.")
    lines.extend(["", f"Naive explicit warning/error count: {report['naive']['explicitWarningErrorCount']}; "
                  f"naive decision: {report['naive']['decision']}.", "",
                  "Full input evidence and uninterpreted field pointers are retained in the JSON report.", ""])
    if "baselineComparison" in report:
        view = report["baselineComparison"]
        lines.extend(["## Baseline comparison", "", "Status: " + view["status"], "",
                      "Baseline execution: " + view["execution"]["baseline"]["status"] +
                      "; current execution: " + view["execution"]["current"]["status"], "",
                      "; ".join(f"{state}: {count}" for state, count in view["counts"].items()), "",
                      view["notice"], "", "Issues: " + (", ".join(view["issues"]) or "none"), ""])
        columns = ["State", "Tool", "Fingerprint", "Baseline results", "Current results", "Reasons"]
        if "runPairing" in view:
            columns.insert(1, "Pair")
        lines.extend(["| " + " | ".join(columns) + " |", "| " + " | ".join("---" for _ in columns) + " |"])
        for entry in view["entries"]:
            cells = [entry["state"], entry["toolIdentity"]["name"], entry["fingerprint"] or "(missing)",
                     ", ".join(t["sourcePointer"] for t in entry["baseline"]),
                     ", ".join(t["sourcePointer"] for t in entry["current"]), ", ".join(entry["reasons"])]
            if "runPairing" in view:
                cells.insert(1, entry["pairId"] if entry["pairId"] is not None else "(not applied)")
            lines.append("| " + " | ".join(_escape(c) for c in cells) + " |")
        lines.append("")
    return "\n".join(lines)
