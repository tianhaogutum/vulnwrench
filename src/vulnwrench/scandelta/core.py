"""Offline scan evidence comparison. No scanners or subprocesses are invoked."""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from urllib.parse import unquote


class InputError(ValueError):
    """Safe, value-free diagnostics for invalid or unsupported evidence."""


def require(condition, message):
    if not condition:
        raise InputError(message)


def obj(value, location):
    require(isinstance(value, dict), f"{location}: expected object")
    return value


def array(value, location):
    require(isinstance(value, list), f"{location}: expected array")
    return value


def string(value, location):
    require(isinstance(value, str) and bool(value.strip()), f"{location}: expected nonempty string")
    require(not any(ord(c) < 32 for c in value), f"{location}: control characters unsupported")
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False)


@dataclass(frozen=True, order=True)
class Package:
    ecosystem: str
    name: str
    target: str
    path: str
    qualifiers: tuple
    version: str

    @property
    def scope(self):
        return (self.ecosystem, self.name, self.target, self.path, self.qualifiers)

    def as_dict(self):
        return dict(ecosystem=self.ecosystem, name=self.name, target=self.target,
                    path=self.path, qualifiers=dict(self.qualifiers), version=self.version)


def purl(value, target, path, location):
    value = string(value, location)
    require(value.startswith("pkg:") and "#" not in value, f"{location}: expected supported PURL without subpath")
    base, sep, query = value[4:].partition("?")
    kind, slash, rest = base.partition("/")
    require(kind in {"npm", "pypi"} and slash, f"{location}: supported PURL types are npm and pypi")
    name, at, version = rest.rpartition("@")
    require(at and name and version, f"{location}: PURL requires name and version")
    require(not re.search(r"%(?![0-9A-Fa-f]{2})", value), f"{location}: malformed percent encoding")
    try:
        name, version = unquote(name, errors="strict"), unquote(version, errors="strict")
    except UnicodeError:
        raise InputError(f"{location}: invalid PURL encoding") from None
    string(name, location)
    string(version, location)
    if kind == "pypi":
        require(bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name)), f"{location}: invalid PyPI name")
        name = re.sub(r"[-_.]+", "-", name).lower()
    else:
        require(bool(re.fullmatch(r"(?:@[A-Za-z0-9._~-]+/)?[A-Za-z0-9._~-]+", name)),
                f"{location}: invalid npm name or namespace")
    qualifiers = {}
    if sep:
        require(bool(query), f"{location}: empty PURL qualifiers")
        for item in query.split("&"):
            key, equals, val = item.partition("=")
            require(equals and re.fullmatch(r"[a-z][a-z0-9._-]*", key) and val and key not in qualifiers,
                    f"{location}: invalid or duplicate PURL qualifier")
            try:
                qualifiers[key] = string(unquote(val, errors="strict"), location)
            except UnicodeError:
                raise InputError(f"{location}: invalid PURL encoding") from None
    return Package(kind, name, target, path, tuple(sorted(qualifiers.items())), version)


def normalize_name(name, ecosystem):
    return re.sub(r"[-_.]+", "-", name).lower() if ecosystem == "pypi" else name


@dataclass
class Finding:
    package: Package
    advisory: str
    source: str


TYPES = {"node-pkg": "npm", "python-pkg": "pypi"}


def report(document, side):
    root = obj(document, side + " report")
    require(root.get("SchemaVersion") == 2 and type(root.get("SchemaVersion")) is int,
            side + " report: only Trivy JSON SchemaVersion 2 is supported")
    require(not root.get("Error") and not root.get("Errors"), side + " report: scan error evidence present")
    results = array(root.get("Results"), side + " report Results")
    findings, targets = [], set()
    for i, result in enumerate(results):
        loc = f"{side} report Results[{i}]"
        result = obj(result, loc)
        target = string(result.get("Target"), loc + " Target")
        kind = result.get("Type")
        require(result.get("Class") == "lang-pkgs" and isinstance(kind, str) and kind in TYPES,
                loc + ": only node-pkg/python-pkg lang-pkgs results are supported")
        require((target, kind) not in targets, loc + ": duplicate target/type result")
        targets.add((target, kind))
        for field in ("Secrets", "Misconfigurations", "Licenses", "CustomResources", "Error", "Errors",
                      "ModifiedFindings", "ExperimentalModifiedFindings"):
            require(not result.get(field), loc + ": non-vulnerability results unsupported")
        vulns = result.get("Vulnerabilities")
        vulns = [] if vulns is None else array(vulns, loc + " Vulnerabilities")
        for j, vuln in enumerate(vulns):
            vloc = f"{loc} Vulnerabilities[{j}]"
            vuln = obj(vuln, vloc)
            path = vuln.get("PkgPath", "")
            require(isinstance(path, str), vloc + " PkgPath: expected string")
            if path:
                string(path, vloc + " PkgPath")
            package = purl(obj(vuln.get("PkgIdentifier"), vloc + " PkgIdentifier").get("PURL"),
                           target, path, vloc + " PURL")
            require(package.ecosystem == TYPES[kind], vloc + ": result type/PURL ecosystem mismatch")
            name = string(vuln.get("PkgName"), vloc + " PkgName")
            version = string(vuln.get("InstalledVersion"), vloc + " InstalledVersion")
            require(normalize_name(name, package.ecosystem) == package.name and version == package.version,
                    vloc + ": package identity fields disagree")
            advisory = string(vuln.get("VulnerabilityID"), vloc + " VulnerabilityID")
            findings.append(Finding(package, advisory, f"/{side}_report/Results/{i}/Vulnerabilities/{j}"))
    return findings, targets


def inventory(document, side):
    root = obj(document, side + " inventory")
    require(root.get("bomFormat") == "CycloneDX" and isinstance(root.get("specVersion"), str) and
            root.get("specVersion") in {"1.4", "1.5", "1.6"},
            side + " inventory: only CycloneDX JSON 1.4/1.5/1.6 is supported")
    components = array(root.get("components"), side + " inventory components")
    packages, refs = {}, set()

    def visit(items, prefix):
        for i, component in enumerate(items):
            loc = f"{prefix}/{i}"
            component = obj(component, side + " inventory component")
            require(component.get("type") == "library", side + " inventory: only library components supported")
            ref = string(component.get("bom-ref"), side + " inventory bom-ref")
            require(ref not in refs, side + " inventory: duplicate bom-ref")
            refs.add(ref)
            properties = array(component.get("properties", []), side + " inventory properties")
            props = {}
            for prop in properties:
                prop = obj(prop, side + " inventory property")
                name = string(prop.get("name"), side + " inventory property name")
                if name.startswith("scan-delta:"):
                    require(name in {"scan-delta:target", "scan-delta:package-path"} and name not in props,
                            side + " inventory: unsupported or duplicate scan-delta property")
                    value = prop.get("value")
                    require(isinstance(value, str), side + " inventory property value: expected string")
                    props[name] = value
            target = string(props.get("scan-delta:target"), side + " inventory scan-delta:target")
            path = props.get("scan-delta:package-path", "")
            if path:
                string(path, side + " inventory package path")
            package = purl(component.get("purl"), target, path, side + " inventory purl")
            name = string(component.get("name"), side + " inventory name")
            group = component.get("group", "")
            require(isinstance(group, str), side + " inventory group: expected string")
            fullname = f"{group}/{name}" if group else name
            require(normalize_name(fullname, package.ecosystem) == package.name and
                    string(component.get("version"), side + " inventory version") == package.version,
                    side + " inventory: component identity fields disagree")
            require(package not in packages, side + " inventory: duplicate package/version/path identity")
            packages[package] = loc
            if "components" in component:
                visit(array(component["components"], side + " nested components"), loc + "/components")
    visit(components, f"/{side}_bom/components")
    return packages


def manifest(document):
    root = obj(document, "metadata")
    require(root.get("schema_version") == 1 and type(root.get("schema_version")) is int,
            "metadata: schema_version must be 1")
    require(set(root) <= {"schema_version", "before", "after", "aliases"}, "metadata: unsupported field")
    for side in ("before", "after"):
        item = obj(root.get(side), "metadata " + side)
        fields = {"scanner", "database", "profile", "report_complete", "inventory_complete"}
        require(fields <= set(item) <= fields | {"grype"},
                "metadata " + side + ": invalid fields")
        scanner = obj(item["scanner"], "metadata scanner")
        require(set(scanner) == {"name", "version"} and isinstance(scanner["name"], str)
                and scanner["name"] in {"trivy", "grype"},
                "metadata scanner: only trivy and pinned grype are supported")
        require(("grype" in item) == (scanner["name"] == "grype"),
                "metadata scanner: grype scope configuration required only for grype")
        string(scanner["version"], "metadata scanner version")
        db = obj(item["database"], "metadata database")
        require(set(db) <= {"id"}, "metadata database: unsupported field")
        if db.get("id") is not None:
            string(db["id"], "metadata database id")
        string(item["profile"], "metadata profile")
        for flag in ("report_complete", "inventory_complete"):
            require(type(item[flag]) is bool, "metadata completeness flags must be boolean")
    aliases = obj(root.get("aliases", {}), "metadata aliases")
    parents = {}

    def find(key):
        parents.setdefault(key, key)
        cursor = key
        while parents[cursor] != cursor:
            cursor = parents[cursor]
        while parents[key] != key:
            previous = parents[key]
            parents[key] = cursor
            key = previous
        return cursor

    for key, values in aliases.items():
        string(key, "alias ID")
        for value in array(values, "alias IDs"):
            string(value, "alias ID")
            a, b = find(key), find(value)
            parents[max(a, b)] = min(a, b)
    groups = defaultdict(list)
    for key in sorted(parents):
        groups[find(key)].append(key)
    return root, find, groups


def compare(before, after, before_bom, after_bom, metadata, *, explain_advisory=None,
            explain_side=None, explain_artifact_id=None, explain_reason_code=None, explain_match_index=None,
            explain_reason_codes_all=None, explain_reason_codes_any=None, explain_target=None,
            explain_package_path=None):
    """Return a deterministic JSON-compatible transition matrix and retained evidence.

    Caller-provided documents are never mutated. InputError messages omit input values.
    Completeness/profile/database fields are caller attestations, not cryptographic proof.
    explain_advisory adds per-scope traces for an observed advisory or explicit alias
    and unknown Grype evidence for an exact native advisory ID;
    explain_side and explain_artifact_id together restrict the explanation to
    exact native unknown records, suppressing normalized explanations only;
    explain_reason_code optionally selects whole entries containing that exact
    adapter reason code, and requires the advisory/side/artifact selectors;
    explain_reason_codes_all instead requires every exact code in a nonempty
    list/tuple, deduplicated in request order; mutually exclusive with the scalar;
    explain_reason_codes_any instead requires at least one supported exact code;
    scalar, ALL and ANY selectors are mutually exclusive;
    explain_match_index optionally intersects those selectors with one original
    native matches-array index, retaining the whole entry and all context;
    explain_target selects whole normalized entries at an exact package.target,
    requires an advisory and excludes all native unknown-artifact selectors;
    unknown explanations are omitted, but their complete batch evidence remains;
    explain_package_path refines that selection by exact package.path, requires
    advisory and target, and accepts an empty string only for an existing empty path;
    the complete batch matrix, accounting and evidence remain unchanged.
    """
    if explain_advisory is not None:
        string(explain_advisory, "explain advisory")
    if explain_package_path is not None:
        require(isinstance(explain_package_path, str), "explain package path: expected string")
        if explain_package_path:
            string(explain_package_path, "explain package path")
        require(explain_advisory is not None and explain_target is not None,
                "explain: package path filter requires advisory and target")
    if explain_target is not None:
        string(explain_target, "explain target")
        require(explain_advisory is not None, "explain: target filter requires advisory")
        require(all(value is None for value in (explain_side, explain_artifact_id, explain_reason_code,
                                                explain_match_index, explain_reason_codes_all, explain_reason_codes_any)),
                "explain: target and native unknown selectors are mutually exclusive")
    if any(value is not None for value in (explain_side, explain_artifact_id, explain_reason_code,
                                           explain_match_index, explain_reason_codes_all, explain_reason_codes_any)):
        require(explain_advisory is not None and explain_side is not None and explain_artifact_id is not None,
                "explain: artifact filter requires advisory, side and artifact ID")
        require(isinstance(explain_side, str) and explain_side in ("before", "after"),
                "explain: side must be before or after")
        string(explain_artifact_id, "explain artifact ID")
    if explain_reason_code is not None:
        string(explain_reason_code, "explain reason code")
    if explain_reason_codes_all is not None:
        require(explain_reason_code is None, "explain: scalar and ALL reason selectors are mutually exclusive")
        require(isinstance(explain_reason_codes_all, (list, tuple)) and bool(explain_reason_codes_all),
                "explain: ALL reasons must be a nonempty list or tuple")
        for code in explain_reason_codes_all:
            string(code, "explain ALL reason code")
        explain_reason_codes_all = list(dict.fromkeys(explain_reason_codes_all))
    if explain_reason_codes_any is not None:
        from .grype import UNKNOWN_REASON_CODES
        require(explain_reason_code is None and explain_reason_codes_all is None,
                "explain: scalar, ALL and ANY reason selectors are mutually exclusive")
        require(isinstance(explain_reason_codes_any, (list, tuple)) and bool(explain_reason_codes_any),
                "explain: ANY reasons must be a nonempty list or tuple")
        for code in explain_reason_codes_any:
            string(code, "explain ANY reason code")
            require(code in UNKNOWN_REASON_CODES, "explain: unsupported ANY reason code")
        explain_reason_codes_any = list(dict.fromkeys(explain_reason_codes_any))
    if explain_match_index is not None:
        require(type(explain_match_index) is int and explain_match_index >= 0,
                "explain: match index must be a nonnegative integer")
    meta, alias, aliases = manifest(metadata)
    from .grype import comparison_reasons, grype_report

    unknown, provenance = {}, {}

    def read_report(document, side):
        if meta[side]["scanner"]["name"] == "grype":
            findings, targets, unknown[side], provenance[side] = grype_report(document, side, meta[side])
            return findings, targets
        unknown[side], provenance[side] = [], []
        return report(document, side)

    bf, bt = read_report(before, "before")
    af, at = read_report(after, "after")
    bi, ai = inventory(before_bom, "before"), inventory(after_bom, "after")
    bm, am = meta["before"], meta["after"]
    reasons = []
    if bm["scanner"] != am["scanner"]:
        reasons.append("scanner_identity_changed")
    if not bm["database"].get("id") or not am["database"].get("id"):
        reasons.append("database_identity_missing")
    elif bm["database"]["id"] != am["database"]["id"]:
        reasons.append("database_identity_changed")
    if bm["profile"] != am["profile"]:
        reasons.append("scan_profile_changed")
    if bm["scanner"]["name"] == am["scanner"]["name"] == "grype":
        reasons.extend(comparison_reasons(before, after))
    if not (bm["report_complete"] and am["report_complete"]):
        reasons.append("incomplete_report")
    if not (bm["inventory_complete"] and am["inventory_complete"]):
        reasons.append("incomplete_inventory")
    if bt != at:
        reasons.append("report_target_coverage_changed")
    identity_unknown = bool(unknown["before"] or unknown["after"])
    if identity_unknown:
        reasons.append("report_identity_unknown")
    groups = [defaultdict(list), defaultdict(list)]
    for findings, grouped in zip((bf, af), groups):
        for finding in findings:
            grouped[(finding.package.scope, alias(finding.advisory))].append(finding)
    bi_scopes = defaultdict(list)
    for package in bi:
        bi_scopes[package.scope].append(package)
    ai_scopes = defaultdict(list)
    for package in ai:
        ai_scopes[package.scope].append(package)
    # Inventory consistency belongs to the package scope, not one advisory row.
    # A different advisory can directly contradict a disappearance/removal claim.
    conflict_scopes = {f.package.scope for findings, packages in ((bf, bi), (af, ai))
                       for f in findings if f.package not in packages}
    after_observed_scopes = {f.package.scope for f in af}
    transitions = []
    for scope, advisory in sorted(groups[0].keys() | groups[1].keys()):
        previous = groups[0].get((scope, advisory), [])
        current = groups[1].get((scope, advisory), [])
        old_versions = sorted({f.package.version for f in previous})
        new_versions = sorted({f.package.version for f in current})
        row_reasons = list(reasons)
        inventory_ok = all(f.package in bi for f in previous) and all(f.package in ai for f in current)
        if not inventory_ok:
            row_reasons.append("finding_missing_from_inventory")
        if scope in conflict_scopes:
            row_reasons.append("report_inventory_conflict")
        fixed = False
        resolution = "observed"
        if current and previous:
            classification = "persistent" if old_versions == new_versions else "version_changed_still_affected"
        elif current:
            classification = "introduced"
            resolution = "incomparable" if row_reasons else "observed"
        elif (inventory_ok and not identity_unknown and scope not in conflict_scopes and scope not in after_observed_scopes
              and bm["inventory_complete"] and am["inventory_complete"] and not ai_scopes[scope]):
            classification = "package_removed"
            resolution = "inventory_evidence"
        elif not row_reasons and ai_scopes[scope]:
            classification = "fixed_within_snapshot"
            resolution = "scan_evidence"
            fixed = True
        else:
            classification = "no_longer_reported"
            resolution = "incomparable" if reasons else "unresolved"
        package = (previous or current)[0].package.as_dict()
        del package["version"]
        transitions.append(dict(package=package, advisory=advisory,
                                aliases=aliases.get(advisory, [advisory]),
                                before_ids=sorted({f.advisory for f in previous}),
                                after_ids=sorted({f.advisory for f in current}),
                                before_versions=old_versions, after_versions=new_versions,
                                after_inventory_versions=sorted({p.version for p in ai_scopes[scope]}),
                                classification=classification, resolution=resolution, fixed=fixed,
                                reasons=row_reasons,
                                before_inventory_records=sorted(bi[p] for p in bi_scopes[scope]),
                                after_inventory_records=sorted(ai[p] for p in ai_scopes[scope]),
                                before_records=[f.source for f in previous],
                                after_records=[f.source for f in current]))
    documents = dict(before_report=before, after_report=after, before_bom=before_bom,
                     after_bom=after_bom, metadata=metadata)
    counts = Counter(t["classification"] for t in transitions)
    families = {meta[side]["scanner"]["name"] for side in ("before", "after")}
    result = dict(schema_version=1, tool="scan-delta", report_family=next(iter(families)) if len(families) == 1 else "mixed",
                evidence_notice="Scan and inventory evidence only; not proof that all vulnerabilities are found or fixed.",
                comparable=not reasons, comparability_reasons=reasons,
                summary=dict(sorted(counts.items())), transitions=transitions,
                accounting=dict(before_findings=len(bf) + len(unknown["before"]),
                                after_findings=len(af) + len(unknown["after"]),
                                before_inventory_components=len(bi), after_inventory_components=len(ai),
                                before_records_accounted=sum(len(t["before_records"]) for t in transitions) + len(unknown["before"]),
                                after_records_accounted=sum(len(t["after_records"]) for t in transitions) + len(unknown["after"])),
                evidence={name: dict(sha256=hashlib.sha256(canonical(doc).encode()).hexdigest(),
                                     digest_encoding="canonical-json-ascii-utf8", document=doc)
                          for name, doc in documents.items()})
    if "grype" in families:
        result.update(unknown_findings=unknown, adapter_provenance=provenance)
    if explain_advisory is not None:
        from .explain import explain_findings
        result["explanation"] = explain_findings(result, explain_advisory, bf, af,
                                                 side=explain_side, artifact_id=explain_artifact_id,
                                                 reason_code=explain_reason_code, match_index=explain_match_index,
                                                 reason_codes_all=explain_reason_codes_all,
                                                 reason_codes_any=explain_reason_codes_any, target=explain_target,
                                                 package_path=explain_package_path)
    return result
