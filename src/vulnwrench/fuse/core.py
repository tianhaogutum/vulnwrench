"""Evidence-preserving adapters and deterministic report merger."""

from collections import Counter, defaultdict
from dataclasses import dataclass
import hashlib
import html
import json
import math
from pathlib import Path
import re

from .identity import InputError, package_identity, text
from .coverage import absence_assessments, coverage_assessment, manifest_entries, source_coverage

SCANNERS = ("grype", "osv", "trivy")
MAX_INPUT_BYTES = 32 * 1024 * 1024
SEVERITIES = frozenset({"UNKNOWN", "NEGLIGIBLE", "LOW", "MEDIUM", "HIGH", "CRITICAL"})


def dumps(value):
    """Stable JSON, with a trailing newline and no non-JSON numbers."""
    return json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n"


def _object_pairs(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise InputError("duplicate JSON object keys are unsupported")
        obj[key] = value
    return obj


def _float(value):
    number = float(value)
    if not math.isfinite(number):
        raise InputError("non-finite JSON numbers are unsupported")
    return number


def _bad_constant(_):
    raise InputError("non-finite JSON numbers are unsupported")


@dataclass(frozen=True)
class Report:
    scanner: str
    document: dict
    input_name: str
    sha256: str
    byte_count: int
    digest_kind: str = "file-bytes"

    @classmethod
    def from_document(cls, scanner, document, input_name="memory"):
        """Library helper: digest covers canonical JSON bytes, not an on-disk file."""
        try:
            raw = dumps(document).encode("utf-8")
        except (TypeError, ValueError, RecursionError):
            raise InputError("document is not supported JSON") from None
        # Round-trip to enforce JSON types and detach from caller mutation.
        return cls(scanner, json.loads(raw), text(input_name), hashlib.sha256(raw).hexdigest(), len(raw), "canonical-json-bytes")


def _read_input(scanner, path):
    try:
        with Path(path).open("rb") as stream:
            raw = stream.read(MAX_INPUT_BYTES + 1)
    except (OSError, ValueError):
        raise InputError(f"{scanner}: unable to read input") from None
    if len(raw) > MAX_INPUT_BYTES:
        raise InputError(f"{scanner}: input exceeds 32 MiB limit")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_object_pairs, parse_constant=_bad_constant, parse_float=_float)
    except (ValueError, UnicodeError, RecursionError):
        raise InputError(f"{scanner}: invalid JSON, UTF-8, duplicate keys or nesting") from None
    return Report(scanner, document, str(path), hashlib.sha256(raw).hexdigest(), len(raw))


def read_report(scanner, path, *, expected_sha256=None):
    """Read <=32 MiB of strict UTF-8 JSON, optionally binding exact file bytes.

    The keyword-only expectation is None or 64 lowercase ASCII hex digits.
    Digest and decoded data use the same read. Scanner profiles and coverage
    bindings are still validated by merge_reports; a hash conveys no trust.
    Never include file contents, paths or supplied digests in errors.
    """
    if scanner not in SCANNERS:
        raise InputError("unsupported scanner")
    if expected_sha256 is not None and (not isinstance(expected_sha256, str)
                                       or not re.fullmatch(r'[0-9a-f]{64}', expected_sha256)):
        raise InputError('input: invalid expected SHA-256')
    report = _read_input(scanner, path)
    if expected_sha256 is not None and report.sha256 != expected_sha256:
        raise InputError('input: SHA-256 mismatch')
    return report


def validate_input(scanner, path, *, expected_sha256=None):
    """Summarize one fully validated scanner profile without exposing evidence.

    Reuse read_report's single bounded strict JSON read and optional exact byte
    expectation, then the complete single-report merge validation and grouping.
    A valid profile (including an empty one) establishes neither scan completion,
    coverage, authenticity nor remediation. No input path or raw report is returned.
    """
    report = read_report(scanner, path, expected_sha256=expected_sha256)
    merged = merge_reports([report])
    return {
        "schemaVersion": "vulnfuse-input-validation-1",
        "validation": "profile-valid",
        "scanner": report.scanner,
        "input": {"sha256": report.sha256, "byteCount": report.byte_count,
                  "digestKind": report.digest_kind},
        "observationCount": merged["observationCount"],
        "findingCount": merged["findingCount"],
    }


@dataclass(frozen=True)
class CoverageManifest:
    document: dict
    input_name: str
    sha256: str
    byte_count: int
    digest_kind: str = "file-bytes"

    @classmethod
    def from_document(cls, document, input_name="memory"):
        """Digest canonical JSON bytes; entry validation occurs in merge_reports."""
        return cls._from_report(Report.from_document("coverage", document, input_name))

    @classmethod
    def _from_report(cls, report):
        return cls(report.document, report.input_name, report.sha256, report.byte_count, report.digest_kind)


def read_coverage_manifest(path, *, expected_sha256=None):
    """Read strict bounded JSON, optionally binding the same read's exact bytes.

    Expected digests are exactly 64 lowercase hex digits; syntax is checked
    before I/O. Schema, declarations and report bindings are validated at merge,
    even with a matching digest. Byte binding does not establish authenticity.
    """
    if expected_sha256 is not None and (not isinstance(expected_sha256, str)
                                       or not re.fullmatch(r'[0-9a-f]{64}', expected_sha256)):
        raise InputError('coverage: invalid expected SHA-256')
    report = _read_input("coverage", path)
    if expected_sha256 is not None and report.sha256 != expected_sha256:
        raise InputError('coverage: SHA-256 mismatch')
    return CoverageManifest._from_report(report)


def _input_expectations(inputs, declarations):
    """Share exact scanner/input key and digest rules with scanner-mode CLI."""
    input_keys = set(inputs)
    expected = {}
    try:
        for scanner, name, digest in declarations:
            if (scanner not in SCANNERS or not isinstance(name, (str, Path))
                    or not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest)):
                raise InputError("input: invalid scanner or expected SHA-256")
            key = (scanner, str(name))
            if key not in input_keys:
                raise InputError("input: expectation does not match a supplied scanner/input key")
            if key in expected:
                raise InputError("input: duplicate SHA-256 expectation")
            expected[key] = digest
    except InputError:
        raise
    except (TypeError, ValueError):
        raise InputError("input: invalid SHA-256 expectations") from None
    return expected


def validate_coverage(inputs, *, coverage_manifest, coverage_manifest_sha256=None,
                      expect_input_sha256=()):
    """Validate file inputs and their manifest, returning a compact binding summary.

    Inputs are (scanner, file) pairs; optional byte expectations are
    (scanner, file, expected) triples with exact string file keys. Each occurrence
    is read once, strictly and boundedly, then fully validated by merge_reports.
    Declaration counts count entries; declared/undeclared input counts count
    occurrences, including repeats. No evidence, labels or paths are returned.
    Coverage comparisons retain existing semantics and cannot establish fixed.
    """
    try:
        inputs = list(inputs)
        if any(s not in SCANNERS or not isinstance(p, (str, Path)) for s, p in inputs):
            raise InputError("input: invalid scanner/input pairs")
        inputs = [(s, str(p)) for s, p in inputs]
    except (TypeError, ValueError):
        raise InputError("input: invalid scanner/input pairs") from None
    if not inputs:
        raise InputError("at least one scanner report is required")
    if coverage_manifest is None:
        raise InputError("coverage: manifest is required")
    expected = _input_expectations(inputs, expect_input_sha256)
    manifest = read_coverage_manifest(coverage_manifest, expected_sha256=coverage_manifest_sha256)
    merged = merge_reports((read_report(s, p, expected_sha256=expected.get((s, p)))
                            for s, p in inputs), coverage_manifest=manifest)
    sources = merged["inputs"]
    declared = sum(s["coverage"]["status"] == "declared" for s in sources)
    return {
        "schemaVersion": "vulnfuse-coverage-validation-1",
        "validation": "profile-and-bindings-valid",
        "coverageManifest": {k: merged["coverageManifest"][k]
                             for k in ("sha256", "byteCount", "digestKind")},
        "inputCount": merged["inputCount"],
        "declarationCount": len(manifest.document["inputs"]),
        "declaredInputCount": declared,
        "undeclaredInputCount": len(sources) - declared,
        "observationCount": merged["observationCount"],
        "findingCount": merged["findingCount"],
        "coverageAssessment": merged["coverageAssessment"],
        "canEstablishFixed": False,
        "inputs": [{**{k: s[k] for k in ("sourceId", "scanner", "sha256", "byteCount", "digestKind", "observationCount")},
                    "coverage": {k: s["coverage"][k] for k in ("status", "reasonCodes", "manifestPointer")}}
                   for s in sources],
    }


def _dict(value):
    if not isinstance(value, dict):
        raise InputError("expected a JSON object")
    return value


def _optional_dict(value):
    return {} if value is None else _dict(value)


def _array(value, *, nullable=False):
    if value is None and nullable:
        return []
    if not isinstance(value, list):
        raise InputError("expected a JSON array")
    return value


def _optional_text(value):
    return text(value, optional=True)


def _strings(values, *, nullable=False):
    return [text(v) for v in _array(values, nullable=nullable)]


def _severity(value):
    if value is None:
        return None
    value = text(value).upper()
    if value == "MODERATE":
        value = "MEDIUM"
    # Unknown and vendor-specific values are retained in rawSeverities, not voted on.
    return value if value in SEVERITIES - {"UNKNOWN"} else None


def _fix(versions=None, state=None, *, basis, explicit=False):
    return {"versions": sorted(set(versions or [])), "state": state or "unknown",
            "basis": basis, "explicitVersionSet": explicit}


def _observation(pointer, package, identifier, aliases, paths, severity, raw_severities, fix):
    identifier = text(identifier)
    return {"pointer": pointer, "package": package, "originalId": identifier,
            "ids": sorted(set([identifier, *aliases])), "paths": sorted(set(paths)),
            "severity": severity, "rawSeverities": raw_severities, "fix": fix}


def _trivy(root):
    for ri, result in enumerate(_array(root["Results"], nullable=True)):
        result = _dict(result)
        target = _optional_text(result.get("Target"))
        eco = _optional_text(result.get("Type"))
        for vi, vuln in enumerate(_array(result.get("Vulnerabilities"), nullable=True)):
            vuln = _dict(vuln)
            pointer = f"/Results/{ri}/Vulnerabilities/{vi}"
            pkg_id = _optional_dict(vuln.get("PkgIdentifier"))
            pkg = package_identity(vuln.get("PkgName"), vuln.get("InstalledVersion"), eco, pkg_id.get("PURL"))
            pkg_path = _optional_text(vuln.get("PkgPath"))
            raw_severity = _optional_text(vuln.get("Severity"))
            fixed = vuln.get("FixedVersion")
            if fixed is not None and not isinstance(fixed, str):
                raise InputError("Trivy FixedVersion must be a string")
            versions = []
            if fixed:
                versions = [text(v.strip()) for v in fixed.split(",")]
            yield _observation(pointer, pkg, vuln.get("VulnerabilityID"), [],
                               [p for p in [target, pkg_path] if p], _severity(raw_severity),
                               [] if raw_severity is None else [raw_severity],
                               _fix(versions, "fixed" if versions else "not-reported",
                                    basis="trivy-FixedVersion", explicit=bool(versions)))


def _grype(root):
    for mi, match in enumerate(_array(root["matches"])):
        match = _dict(match)
        artifact = _dict(match.get("artifact"))
        vuln = _dict(match.get("vulnerability"))
        pkg = package_identity(artifact.get("name"), artifact.get("version"),
                               artifact.get("type"), artifact.get("purl"))
        aliases = []
        for related in _array(match.get("relatedVulnerabilities"), nullable=True):
            aliases.append(text(_dict(related).get("id")))
        paths = []
        for loc in _array(artifact.get("locations"), nullable=True):
            loc = _dict(loc)
            # Modern Syft location objects use accessPath; older reports use path.
            for key in ("path", "accessPath", "realPath"):
                value = _optional_text(loc.get(key))
                if value:
                    paths.append(value)
        severity = _optional_text(vuln.get("severity"))
        fix = _optional_dict(vuln.get("fix"))
        versions = _strings(fix.get("versions"), nullable=True)
        state = _optional_text(fix.get("state"))
        explicit = bool(versions) or state in {"not-fixed", "wont-fix"}
        yield _observation(f"/matches/{mi}", pkg, vuln.get("id"), aliases, paths,
                           _severity(severity), [] if severity is None else [severity],
                           _fix(versions, state, basis="grype-vulnerability.fix", explicit=explicit))


def _affected_matches(candidate, observed):
    """Only interpret OSV fix events for an explicitly matching package."""
    p = _dict(candidate)
    if not p.get("purl") and (not p.get("name") or not p.get("ecosystem")):
        return False
    # An affected PURL can specify a version; don't overwrite it to force a match.
    from .identity import parse_purl
    version = observed["version"]
    if p.get("purl"):
        version = parse_purl(p["purl"])["version"] or version
    candidate = package_identity(p.get("name"), version, p.get("ecosystem"), p.get("purl"))
    if observed["known"] and candidate["known"]:
        return observed["identity"] == candidate["identity"]
    return (p.get("name") == observed["reportedName"] and
            p.get("ecosystem") == observed["reportedEcosystem"] and
            version == observed["version"])


def _osv_fix(vuln, observed):
    versions = []
    matched_indices = []
    for ai, affected in enumerate(_array(vuln.get("affected"), nullable=True)):
        affected = _dict(affected)
        package = affected.get("package")
        matched = package is not None and _affected_matches(package, observed)
        if matched:
            matched_indices.append(ai)
        for range_ in _array(affected.get("ranges"), nullable=True):
            range_ = _dict(range_)
            for event in _array(range_.get("events"), nullable=True):
                event = _dict(event)
                if "fixed" in event:
                    fixed = text(event["fixed"])
                    if matched:
                        versions.append(fixed)
    result = _fix(versions, "fixed" if versions else "unknown",
                  basis="osv-matching-affected-fixed-events;no-range-evaluation", explicit=bool(versions))
    result["matchedAffectedIndices"] = matched_indices
    return result


def _osv(root):
    for ri, result in enumerate(_array(root["results"])):
        result = _dict(result)
        source = _optional_dict(result.get("source"))
        path = _optional_text(source.get("path"))
        for pi, package in enumerate(_array(result.get("packages"))):
            package = _dict(package)
            p = _dict(package.get("package"))
            pkg = package_identity(p.get("name"), p.get("version"), p.get("ecosystem"), p.get("purl"))
            for vi, vuln in enumerate(_array(package.get("vulnerabilities"))):
                vuln = _dict(vuln)
                aliases = _strings(vuln.get("aliases"), nullable=True)
                raw_severities = []
                for sev in _array(vuln.get("severity"), nullable=True):
                    sev = _dict(sev)
                    text(sev.get("type"))
                    text(sev.get("score"))
                    raw_severities.append(sev)
                normalized = []
                for key in ("database_specific", "ecosystem_specific"):
                    metadata = _optional_dict(vuln.get(key))
                    if "severity" in metadata:
                        # Nonstandard metadata is retained, but only string labels are normalized.
                        raw_severities.append({key: metadata["severity"]})
                        if isinstance(metadata["severity"], str):
                            value = _severity(metadata["severity"])
                            if value:
                                normalized.append(value)
                obs = _observation(f"/results/{ri}/packages/{pi}/vulnerabilities/{vi}", pkg,
                                   vuln.get("id"), aliases, [path] if path else [],
                                   normalized[0] if len(set(normalized)) == 1 else None,
                                   raw_severities, _osv_fix(vuln, pkg))
                obs["severityValues"] = sorted(set(normalized))
                yield obs


ADAPTERS = {"trivy": ("Results", _trivy), "grype": ("matches", _grype), "osv": ("results", _osv)}


class _Aliases:
    def __init__(self):
        self.parent = {}

    def find(self, value):
        self.parent.setdefault(value, value)
        root = value
        while self.parent[root] != root:
            root = self.parent[root]
        while value != root:
            parent = self.parent[value]
            self.parent[value] = root
            value = parent
        return root

    def union(self, left, right):
        left, right = sorted([self.find(left), self.find(right)])
        self.parent[right] = left


def merge_reports(reports, *, coverage_manifest=None):
    """Merge explicit aliases and exact package identities; preserve every observation.

    Accepts Report objects. Raises InputError for unsupported or malformed inputs.
    Report order does not affect output; repeated inputs remain repeated evidence.
    An optional CoverageManifest declares coverage bound to exact input digests;
    absence assessments compare declarations, never establish remediation.
    """
    reports = list(reports)
    if not reports:
        raise InputError("at least one scanner report is required")
    if any(not isinstance(r, Report) or r.scanner not in SCANNERS for r in reports):
        raise InputError("unsupported report or scanner")
    if coverage_manifest is not None and not isinstance(coverage_manifest, CoverageManifest):
        raise InputError("unsupported coverage manifest")
    entries = None if coverage_manifest is None else manifest_entries(coverage_manifest.document, reports)
    reports.sort(key=lambda r: (r.scanner, r.sha256, r.input_name))
    sources, observations, edges = [], [], []
    aliases = _Aliases()
    for si, report in enumerate(reports, 1):
        source_id = f"s{si:04d}"
        root_key, adapter = ADAPTERS[report.scanner]
        try:
            root = _dict(report.document)
            if root_key not in root or any(k in root for k in {"Results", "matches", "results"} - {root_key}):
                raise InputError("unsupported or ambiguous report root shape")
            parsed = list(adapter(root))
        except InputError as exc:
            raise InputError(f"{report.scanner} {source_id}: {exc}") from None
        for obs in parsed:
            obs["sourceId"] = source_id
            obs["scanner"] = report.scanner
            obs["observationId"] = source_id + "#" + obs["pointer"]
            obs.setdefault("severityValues", [obs["severity"]] if obs["severity"] else [])
            aliases.find(obs["originalId"])
            for alias in obs["ids"]:
                aliases.union(obs["originalId"], alias)
                if alias != obs["originalId"]:
                    edges.append({"from": obs["originalId"], "to": alias,
                                  "observationId": obs["observationId"],
                                  "basis": "osv-aliases" if report.scanner == "osv" else "grype-relatedVulnerabilities"})
        sources.append({"sourceId": source_id, "scanner": report.scanner, "input": report.input_name,
                        "sha256": report.sha256, "byteCount": report.byte_count, "digestKind": report.digest_kind,
                        "observationCount": len(parsed), "rawReport": report.document,
                        "coverage": source_coverage(report, entries)})
        observations.extend(parsed)
    components = defaultdict(list)
    for identifier in sorted(aliases.parent):
        components[aliases.find(identifier)].append(identifier)
    groups = defaultdict(list)
    for obs in observations:
        package_key = obs["package"]["identity"] or "unknown:" + obs["observationId"]
        groups[(package_key, aliases.find(obs["originalId"]))].append(obs)
    findings = []
    supplied = {r.scanner for r in reports}
    for fi, (group_key, group) in enumerate(sorted(groups.items()), 1):
        group.sort(key=lambda o: o["observationId"])
        observed_by = sorted({o["scanner"] for o in group})
        severities = sorted({s for o in group for s in o["severityValues"]})
        fix_sets = {tuple(o["fix"]["versions"]) for o in group if o["fix"]["explicitVersionSet"]}
        fix_states = sorted({o["fix"]["state"] for o in group if o["fix"]["state"] not in {"unknown", "not-reported"}})
        severity_unknown = sum(not o["severityValues"] for o in group)
        severity_conflict = len(severities) > 1
        fix_version_conflict = len(fix_sets) > 1
        fix_state_conflict = len(fix_states) > 1
        findings.append({
            "findingId": f"f{fi:04d}", "package": group[0]["package"], "ids": components[group_key[1]],
            "observedBy": observed_by,
            "scannerPresence": {s: "observed" if s in observed_by else "not_observed" if s in supplied else "not_supplied" for s in SCANNERS},
            "inputPresence": {s["sourceId"]: "observed" if any(o["sourceId"] == s["sourceId"] for o in group) else "not_observed" for s in sources},
            "absenceAssessments": absence_assessments(sources, group),
            "paths": sorted({p for o in group for p in o["paths"]}),
            "severityValues": severities, "severityConflict": severity_conflict,
            "unknownSeverityObservationCount": severity_unknown,
            "severityAssessment": "conflict" if severity_conflict else "unknown" if not severities else "partial" if severity_unknown else "consistent_observed",
            "fixVersions": sorted({v for o in group for v in o["fix"]["versions"]}),
            "fixStates": fix_states, "fixVersionConflict": fix_version_conflict, "fixStateConflict": fix_state_conflict,
            "fixConflict": fix_version_conflict or fix_state_conflict,
            "observationCount": len(group), "observations": group,
        })
    counts = Counter(o["scanner"] for o in observations)
    return {"schemaVersion": "vulnfuse-1", "toolVersion": "0.1.0",
            "notice": "Not observed is not proof of safety. Aliases are input assertions, not independently verified. Fixed versions are reported evidence, not remediation advice.",
            "inputCount": len(sources), "observationCount": len(observations), "findingCount": len(findings),
            "scannerObservationCounts": {s: counts[s] for s in SCANNERS},
            "coverageAssessment": coverage_assessment(sources),
            "coverageManifest": None if coverage_manifest is None else {
                "input": coverage_manifest.input_name, "sha256": coverage_manifest.sha256,
                "byteCount": coverage_manifest.byte_count, "digestKind": coverage_manifest.digest_kind,
                "rawManifest": coverage_manifest.document},
            "inputs": sources, "aliasEdges": sorted(edges, key=lambda e: (e["from"], e["to"], e["observationId"])),
            "findings": findings}


def _md(value):
    # Escape untrusted report text: no raw HTML, Markdown links, pipes or newlines.
    return "".join(
        " " if c in "\r\n" or ord(c) < 32 else
        f"&#{ord(c)};" if c in "\\`*_{}[]()#+!|~" else html.escape(c, quote=True)
        for c in str(value)
    )


def render_markdown(merged):
    """Human summary. The JSON contains the complete evidence archive."""
    lines = ["# vulnwrench fuse report", "", merged["notice"], "",
             f"Inputs: {merged['inputCount']}; observations: {merged['observationCount']}; findings: {merged['findingCount']}.",
             "", _md(f"Coverage: {merged['coverageAssessment']['status']}; reasons: "
                      f"{', '.join(merged['coverageAssessment']['reasonCodes']) or 'none'}. "
                      "Coverage declarations do not establish remediation."),
             "", "Full raw input documents and observation pointers are retained in JSON. This Markdown is a summary.", "",
             "| Finding / package | IDs | Grype | OSV | Trivy | Severity evidence | Fix conflict |",
             "| --- | --- | --- | --- | --- | --- | --- |"]
    for f in merged["findings"]:
        p = f["package"]
        label = p["identity"] or f"unknown identity: {p['reportedName']}@{p['version']}"
        sev = ", ".join(f["severityValues"]) or "unknown"
        sev += f" ({f['severityAssessment']})"
        cells = [f["findingId"] + " / " + label, ", ".join(f["ids"]),
                 *(f["scannerPresence"][s] for s in SCANNERS), sev, str(f["fixConflict"]).lower()]
        lines.append("| " + " | ".join(_md(c) for c in cells) + " |")
    for f in merged["findings"]:
        lines.extend(["", "## " + f["findingId"], ""])
        for source_id, assessment in f["absenceAssessments"].items():
            lines.append("- " + _md(f"Absent in {source_id}; coverage: {assessment['status']}; "
                                     f"reasons: {', '.join(assessment['reasonCodes']) or 'none'}; "
                                     "cannot establish fixed by absence."))
        for o in f["observations"]:
            details = (f"{o['observationId']} — {o['scanner']}; original ID: {o['originalId']}; "
                       f"paths: {', '.join(o['paths']) or 'unknown'}; "
                       f"severity: {', '.join(o['severityValues']) or 'unknown'}; "
                       f"fix state: {o['fix']['state']}; fixed versions: {', '.join(o['fix']['versions']) or 'not reported'}")
            lines.append("- " + _md(details))
    lines.extend(["", "## Input provenance", ""])
    for source in merged["inputs"]:
        lines.append("- " + _md(f"{source['sourceId']}: {source['scanner']}; {source['input']}; SHA-256 {source['sha256']}; observations {source['observationCount']}"))
        coverage = source["coverage"]
        lines.append("  - " + _md(f"Coverage: {coverage['status']}; reasons: {', '.join(coverage['reasonCodes']) or 'none'}; "
                                   f"target: {coverage['targetIdentity']}; scan complete: {coverage['scanComplete']}; "
                                   f"database timestamp: {coverage['databaseTimestamp']}; database identity: {coverage['databaseIdentity']}; "
                                   f"scan policy: {coverage['scanPolicyIdentity']}; "
                                   f"manifest entry: {coverage['manifestPointer']}"))
    manifest = merged["coverageManifest"]
    if manifest is not None:
        lines.extend(["", "## Coverage manifest provenance", "",
                      _md(f"{manifest['input']}; SHA-256 {manifest['sha256']}; declarations are unverified input assertions.")])
    return "\n".join(lines) + "\n"
