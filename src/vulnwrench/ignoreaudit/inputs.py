"""Strict adapters for a documented subset of native scanner formats."""
from dataclasses import replace
from datetime import date
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tomllib

from .model import CoverageGap, Finding, InputError, Report, ReportAliasHint, Rule, UnboundReportAliasHint

ID = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_.:-]*[A-Za-z0-9])?\Z")
DATE = re.compile(r"\d{4}-\d{2}-\d{2}\Z")


def read_bytes(path):
    try:
        return Path(path).read_bytes()
    except OSError:
        raise InputError("cannot read input file") from None


def digest(data):
    return hashlib.sha256(data).hexdigest()


def text(data):
    try:
        return data.decode("utf-8")
    except UnicodeError:
        raise InputError("input must be UTF-8") from None


def obj(value, allowed=None, where="input"):
    if not isinstance(value, dict):
        raise InputError(f"{where}: expected object")
    if allowed is not None and set(value) - set(allowed.split()):
        raise InputError(f"{where}: unsupported field (values withheld)")
    return value


def array(value, where):
    if not isinstance(value, list):
        raise InputError(f"{where}: expected array")
    return value


def optional_array(value, where):
    return [] if value is None else array(value, where)


def string(value, where, optional=False):
    if optional and (value is None or isinstance(value, str) and not value.strip()):
        return None
    if not isinstance(value, str) or not value.strip() or any(ord(c) < 32 for c in value):
        raise InputError(f"{where}: expected nonempty single-line string")
    return value


def advisory(value, where):
    value = string(value, where)
    if not ID.fullmatch(value):
        raise InputError(f"{where}: unsupported advisory ID; only exact single-token IDs supported")
    return value


def parse_date(value, where="date"):
    if type(value) is date:
        return value
    if not isinstance(value, str) or not DATE.fullmatch(value):
        raise InputError(f"{where}: expected YYYY-MM-DD date (no timestamp)")
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise InputError(f"{where}: invalid calendar date") from None


def exact_path(value, where):
    value = string(value, where)
    if any(c in value for c in "*?[]{}\\") or ".." in PurePosixPath(value).parts:
        raise InputError(f"{where}: only exact POSIX paths without globs or traversal are supported")
    return str(PurePosixPath(value))


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputError("JSON: duplicate object key")
        result[key] = value
    return result


def json_data(data):
    try:
        return json.loads(text(data), object_pairs_hook=_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(InputError("JSON: nonfinite number")))
    except (ValueError, RecursionError) as exc:
        if isinstance(exc, InputError):
            raise
        raise InputError("malformed JSON (input details withheld)") from None


def load_rules(data, format, source_dir=None):
    if format == "trivy":
        if source_dir is not None:
            raise InputError("--osv-config-dir is only supported for OSV")
        rules = []
        for line, content in enumerate(text(data).splitlines(), 1):
            content = content.split("#", 1)[0].strip()
            if not content:
                continue
            words = content.split()
            if len(words) > 2 or (len(words) == 2 and not words[1].startswith("exp:")):
                raise InputError(f"rules line {line}: expected ID [exp:YYYY-MM-DD]; YAML/selectors unsupported")
            rules.append(Rule(f"line:{line}", advisory(words[0], f"rules line {line}"),
                              parse_date(words[1][4:], f"rules line {line} expiry") if len(words) == 2 else None))
        return rules
    if format != "osv":
        raise InputError("unsupported format; use trivy text or osv IgnoredVulns TOML; Grype YAML is not supported")
    try:
        root = tomllib.loads(text(data))
    except (tomllib.TOMLDecodeError, RecursionError):
        raise InputError("malformed TOML (input details withheld)") from None
    obj(root, "IgnoredVulns", "OSV config (PackageOverrides and scanner options are unsupported)")
    rules = []
    scope = exact_path(source_dir, "OSV config directory") if source_dir is not None else None
    for i, item in enumerate(array(root.get("IgnoredVulns", []), "IgnoredVulns")):
        where = f"IgnoredVulns[{i}]"
        obj(item, "id effectiveUntil reason", where)
        rules.append(Rule(f"IgnoredVulns:{i}", advisory(item.get("id"), where + " id"),
                          parse_date(item["effectiveUntil"], where + " expiry") if "effectiveUntil" in item else None,
                          string(item.get("reason"), where + " reason", optional=True), source_dir=scope))
    return rules


def apply_metadata(rules, data, rules_sha256):
    root = obj(json_data(data), "schemaVersion rulesSha256 rules", "metadata")
    if type(root.get("schemaVersion")) is not int or root["schemaVersion"] != 1:
        raise InputError("metadata: unsupported schemaVersion")
    if root.get("rulesSha256") != rules_sha256:
        raise InputError("metadata: rulesSha256 mismatch; regenerate sidecar for these exact rule bytes")
    entries = obj(root.get("rules"), where="metadata rules")
    known = {r.key for r in rules}
    if set(entries) - known:
        raise InputError("metadata: unknown rule locator")
    result = []
    for rule in rules:
        entry = obj(entries.get(rule.key, {}), "reason owner", "metadata rule")
        values = {key: string(value, "metadata " + key) for key, value in entry.items()}
        if rule.reason and "reason" in values and values["reason"] != rule.reason:
            raise InputError("metadata: conflicting native and sidecar reason")
        result.append(replace(rule, **values))
    return result


def load_aliases(data):
    root = obj(json_data(data), "schemaVersion groups", "alias map")
    if type(root.get("schemaVersion")) is not int or root["schemaVersion"] != 1:
        raise InputError("alias map: unsupported schemaVersion")
    mapping = {}
    for group in array(root.get("groups"), "alias groups"):
        ids = [advisory(v, "alias ID") for v in array(group, "alias group")]
        if len(ids) < 2 or len(set(ids)) != len(ids):
            raise InputError("alias map: each group needs at least two distinct IDs")
        if set(ids) & mapping.keys():
            raise InputError("alias map: overlapping groups are unsupported; merge them explicitly")
        for ident in ids:
            mapping[ident] = frozenset(ids)
    return mapping


# Known descriptive fields are inventoried as uninterpreted for matching and
# bound by the report digest. Alias declarations may also be shown as hints.
# New fields fail closed at structural levels.
TRIVY_ROOT = "SchemaVersion CreatedAt ArtifactName ArtifactType Metadata Results"
TRIVY_RESULT = "Target Class Type Packages Vulnerabilities Misconfigurations Secrets Licenses CustomResources ExperimentalModifiedFindings MisconfSummary"
TRIVY_VULN = "VulnerabilityID VendorIDs PkgID PkgName PkgPath PkgIdentifier InstalledVersion FixedVersion Status Layer SeveritySource PrimaryURL DataSource Title Description Severity CweIDs CVSS References PublishedDate LastModifiedDate Custom DetectedBy VendorSeverity"
OSV_ROOT = "results experimental_config"
OSV_PACKAGE = "package vulnerabilities groups licenses license_violations dependency_groups"
OSV_VULN = "schema_version id modified published withdrawn aliases related summary details affected references database_specific severity credits"


def report_alias_hint(value, locator):
    """Validate declarations without merging, deduplicating or trusting IDs."""
    ids = tuple(advisory(ident, "report alias ID") for ident in array(value, "report aliases"))
    return (ReportAliasHint(ids, locator),) if ids else ()


def load_report(data, format, *, report_unfiltered=False):
    if not report_unfiltered:
        raise InputError("--report-unfiltered is required; filtered or unknown reports cannot establish orphan candidates")
    root = obj(json_data(data), where="report")
    findings, uninterpreted, unbound_hints = [], set(), []
    missing_collections = []
    coverage_gaps = []

    def record_gap(parent, field, locator):
        if parent.get(field) is None:
            coverage_gaps.append(CoverageGap(locator, "null" if field in parent else "absent"))

    def record(value, used, prefix):
        for key in value:
            if key not in used:
                uninterpreted.add(prefix + "." + key)

    if format == "trivy":
        obj(root, TRIVY_ROOT, "Trivy report")
        if type(root.get("SchemaVersion")) is not int or root["SchemaVersion"] != 2:
            raise InputError("Trivy report: only SchemaVersion 2 is supported")
        record(root, {"SchemaVersion", "Results"}, "report")
        raw_results = root.get("Results")
        record_gap(root, "Results", "Results")
        coverage = "asserted_unfiltered" if raw_results is not None else "unknown"
        for i, result in enumerate(array(raw_results, "Results") if raw_results is not None else []):
            where = f"Results[{i}]"
            obj(result, TRIVY_RESULT, where)
            target = string(result.get("Target"), where + " Target", optional=True)
            if "Class" in result:
                result_class = string(result["Class"], where + " Class")
                if result_class not in {"os-pkgs", "lang-pkgs"}:
                    raise InputError(where + ": only os-pkgs and lang-pkgs vulnerability result classes supported")
            # This MVP audits vulnerabilities only; never drop other finding categories.
            for field in ("Misconfigurations", "Secrets", "Licenses", "CustomResources", "ExperimentalModifiedFindings"):
                if optional_array(result.get(field), where + " " + field):
                    raise InputError(where + ": non-vulnerability or suppressed findings unsupported; provide a vulnerability-only unfiltered report")
            record(result, {"Target", "Vulnerabilities"}, "Results[]")
            for j, vuln in enumerate(optional_array(result.get("Vulnerabilities"), where + " Vulnerabilities")):
                loc = f"{where}.Vulnerabilities[{j}]"
                obj(vuln, TRIVY_VULN, loc)
                ident = advisory(vuln.get("VulnerabilityID"), loc + " ID")
                pkg = string(vuln.get("PkgName"), loc + " package", optional=True)
                version = string(vuln.get("InstalledVersion"), loc + " version", optional=True)
                path = string(vuln.get("PkgPath"), loc + " path", optional=True) or target
                findings.append(Finding(ident, pkg, path, None, version, loc))
                record(vuln, {"VulnerabilityID", "PkgName", "InstalledVersion", "PkgPath"}, "Results[].Vulnerabilities[]")
    elif format == "osv":
        obj(root, OSV_ROOT, "OSV report")
        if "experimental_config" in root:
            obj(root["experimental_config"], where="OSV experimental_config")
            if root["experimental_config"]:
                raise InputError("OSV report: experimental configuration may affect coverage and is unsupported")
        record(root, {"results"}, "report")
        raw_results = root.get("results")
        record_gap(root, "results", "results")
        coverage = "asserted_unfiltered" if raw_results is not None else "unknown"
        for i, result in enumerate(array(raw_results, "results") if raw_results is not None else []):
            where = f"results[{i}]"
            obj(result, "source packages", where)
            source = obj(result.get("source"), "path type", where + " source")
            path = string(source.get("path"), where + " source.path", optional=True)
            if "type" in source:
                string(source["type"], where + " source.type")
            record(source, {"path"}, "results[].source")
            for j, package in enumerate(array(result.get("packages"), where + " packages")):
                loc = f"{where}.packages[{j}]"
                obj(package, OSV_PACKAGE, loc)
                pkg = obj(package.get("package"), "name version ecosystem commit purl", loc + " package")
                name = string(pkg.get("name"), loc + " name", optional=True)
                version = string(pkg.get("version"), loc + " version", optional=True)
                eco = string(pkg.get("ecosystem"), loc + " ecosystem", optional=True)
                record(pkg, {"name", "version", "ecosystem"}, "results[].packages[].package")
                group_hints, group_declarations = {}, []
                for g, group in enumerate(optional_array(package.get("groups"), loc + " groups")):
                    obj(group, "ids aliases experimental_analysis max_severity", loc + " group")
                    ids = [advisory(ident, loc + " group ID")
                           for ident in array(group.get("ids", []), loc + " group IDs")]
                    hints = (report_alias_hint(group["aliases"], f"{loc}.groups[{g}].aliases")
                             if "aliases" in group else ())
                    for hint in hints:
                        group_declarations.append((tuple(ids), hint))
                    # Bind only to observations explicitly named in this package's
                    # group. Never infer a report-wide or transitive alias graph.
                    for ident in dict.fromkeys(ids):
                        group_hints.setdefault(ident, []).extend(hints)
                record(package, {"package", "vulnerabilities"}, "results[].packages[]")
                raw_vulnerabilities = package.get("vulnerabilities")
                if raw_vulnerabilities is None:
                    coverage = "unknown"
                    missing_collections.append(loc + ".vulnerabilities")
                    record_gap(package, "vulnerabilities", loc + ".vulnerabilities")
                observed_ids = set()
                for k, vuln in enumerate(optional_array(raw_vulnerabilities, loc + " vulnerabilities")):
                    vloc = f"{loc}.vulnerabilities[{k}]"
                    obj(vuln, OSV_VULN, vloc)
                    ident = advisory(vuln.get("id"), vloc + " id")
                    observed_ids.add(ident)
                    hints = (report_alias_hint(vuln["aliases"], vloc + ".aliases") if "aliases" in vuln else ())
                    findings.append(Finding(ident, name, path, eco, version, vloc,
                                            hints + tuple(group_hints.get(ident, ()))))
                    record(vuln, {"id"}, "results[].packages[].vulnerabilities[]")
                # Partition declarations by literal same-package IDs only. A
                # partially observed group is already bound; do not repeat it
                # at report level or let an explicit alias map affect binding.
                for ids, hint in group_declarations:
                    if observed_ids.isdisjoint(ids):
                        reason = ("vulnerability_collection_absent_or_null" if raw_vulnerabilities is None else
                                  "no_same_package_id_observation")
                        unbound_hints.append(UnboundReportAliasHint(ids, hint.aliases, hint.locator, reason))
    else:
        raise InputError("unsupported report format; Grype YAML/JSON not supported")
    notes = ["Coverage is a caller assertion, not independently verifiable; candidates are limited to this report.",
             "Matching uses exact advisory IDs unless an explicit local alias map is supplied; unmatched aliases are not proof of unused suppressions."]
    if raw_results is None:
        notes.append("Result collection is absent/null: no orphan candidates can be established.")
    if missing_collections:
        notes.append("OSV vulnerability collections absent/null at: " + ", ".join(missing_collections) +
                     "; coverage is unknown and no orphan candidates can be established.")
    return Report(tuple(findings), coverage, tuple(notes), tuple(sorted(uninterpreted)), tuple(unbound_hints),
                  tuple(coverage_gaps))
