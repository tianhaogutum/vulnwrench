"""Grype 0.86.1 JSON, adapter contract v1. No inferred package locations.

Native format references: anchore/grype v0.86.1 grype/presenter/models,
and anchore/syft v1.18.1 syft/file/coordinates.go. Independently implemented.
"""
from collections import defaultdict

from .core import (Finding, InputError, TYPES, array, canonical, normalize_name,
                   obj, purl, require, string)

GRYPE_VERSION = "0.86.1"
PACKAGE_TYPES = {"npm": "npm", "python": "pypi"}
# Exact adapter vocabulary; ANY requests must not hide unsupported codes behind
# a matching code. Supported codes need not occur in the current comparison.
UNKNOWN_REASON_CODES = frozenset({
    "artifact_id_conflict", "unsupported_package_type", "ambiguous_package_location",
    "unsupported_package_location", "scope_binding_missing", "scope_binding_location_mismatch",
    "package_identity_unsupported", "package_identity_disagrees", "scope_binding_type_mismatch",
})


def comparison_reasons(before, after):
    """Native contradictions can veto, but never establish, caller identities."""
    old, new = before["descriptor"], after["descriptor"]
    reasons = []
    for key, reason in (("checksum", "grype_database_checksum_changed"),
                        ("schemaVersion", "grype_database_schema_changed")):
        a, b = (old.get("db") or {}).get(key), (new.get("db") or {}).get(key)
        if a and b and a != b:
            reasons.append(reason)
    if (old.get("configuration") is not None and new.get("configuration") is not None
            and canonical(old["configuration"]) != canonical(new["configuration"])):
        reasons.append("grype_configuration_changed")
    return reasons


def coordinate(value, loc):
    value = obj(value, loc)
    require({"path"} <= set(value) <= {"path", "layerID"}, loc + ": unsupported location fields")
    string(value["path"], loc + " path")
    require(isinstance(value.get("layerID", ""), str), loc + " layerID: expected string")
    return value


def configuration(value, side):
    loc = "metadata " + side + " grype"
    value = obj(value, loc)
    require(set(value) == {"adapter_version", "targets", "bindings"}, loc + ": invalid fields")
    require(type(value["adapter_version"]) is int and value["adapter_version"] == 1,
            loc + ": only adapter_version 1 is supported")
    targets = set()
    for target in array(value["targets"], loc + " targets"):
        target = obj(target, loc + " target")
        require(set(target) == {"target", "type"}, loc + ": invalid target fields")
        name = string(target["target"], loc + " target")
        kind = string(target["type"], loc + " type")
        require(kind in TYPES and (name, kind) not in targets, loc + ": unsupported or duplicate target/type")
        targets.add((name, kind))
    bindings = {}
    for i, binding in enumerate(array(value["bindings"], loc + " bindings")):
        binding = obj(binding, loc + " binding")
        require(set(binding) == {"artifact_id", "target", "package_path", "location"},
                loc + ": invalid binding fields")
        identity = string(binding["artifact_id"], loc + " artifact_id")
        require(identity not in bindings, loc + ": duplicate artifact binding")
        target = string(binding["target"], loc + " binding target")
        require(any(t == target for t, _ in targets), loc + ": binding target not declared")
        require(isinstance(binding["package_path"], str), loc + " package_path: expected string")
        if binding["package_path"]:
            string(binding["package_path"], loc + " package_path")
        coordinate(binding["location"], loc + " location")
        bindings[identity] = (binding, f"/metadata/{side}/grype/bindings/{i}")
    return targets, bindings


def grype_report(document, side, metadata):
    loc = side + " report"
    root = obj(document, loc)
    descriptor = obj(root.get("descriptor"), loc + " descriptor")
    require(descriptor.get("name") == "grype" and descriptor.get("version") == GRYPE_VERSION
            and metadata["scanner"]["version"] == GRYPE_VERSION,
            loc + ": only pinned Grype 0.86.1 JSON is supported")
    require("SchemaVersion" not in root and "Results" not in root, loc + ": mixed report formats unsupported")
    require(not root.get("error") and not root.get("errors"), loc + ": scan error evidence present")
    require(not root.get("ignoredMatches"), loc + ": ignored matches unsupported")
    source = obj(root.get("source"), loc + " source")
    require(source.get("type") in ("directory", "file"), loc + ": only directory/file sources supported")
    string(source.get("target"), loc + " source target")
    if descriptor.get("db") is not None:
        db = obj(descriptor["db"], loc + " descriptor db")
        require(not db.get("error"), loc + ": database error evidence present")
        if "checksum" in db:
            require(isinstance(db["checksum"], str), loc + " db checksum: expected string")
        if "schemaVersion" in db:
            require(type(db["schemaVersion"]) is int and db["schemaVersion"] > 0,
                    loc + " db schemaVersion: expected positive integer")
    targets, bindings = configuration(metadata["grype"], side)
    matches = array(root.get("matches"), loc + " matches")
    # Artifact IDs are report-local references, never package identity across scans.
    artifacts = defaultdict(set)
    for match in matches:
        artifact = obj(obj(match, loc + " match").get("artifact"), loc + " artifact")
        identity = string(artifact.get("id"), loc + " artifact id")
        artifacts[identity].add(canonical(artifact))
    findings, unknown, provenance = [], [], []
    for i, match in enumerate(matches):
        source = f"/{side}_report/matches/{i}"
        advisory = string(obj(match.get("vulnerability"), loc + " vulnerability").get("id"), loc + " vulnerability id")
        artifact = match["artifact"]
        identity = artifact["id"]
        kind = string(artifact.get("type"), loc + " artifact type")
        name = string(artifact.get("name"), loc + " artifact name")
        version = string(artifact.get("version"), loc + " artifact version")
        locations = array(artifact.get("locations"), loc + " artifact locations")
        for location in locations:
            coordinate(location, loc + " artifact location")
        reasons = []
        if len(artifacts[identity]) != 1:
            reasons.append("artifact_id_conflict")
        if kind not in PACKAGE_TYPES:
            reasons.append("unsupported_package_type")
        if len(locations) != 1:
            reasons.append("ambiguous_package_location")
        elif locations[0].get("layerID"):
            reasons.append("unsupported_package_location")
        bound = bindings.get(identity)
        package = None
        if bound is None:
            reasons.append("scope_binding_missing")
        else:
            binding, binding_record = bound
            if len(locations) == 1 and locations[0] != binding["location"]:
                reasons.append("scope_binding_location_mismatch")
            try:
                package = purl(artifact.get("purl"), binding["target"], binding["package_path"], loc + " artifact purl")
            except InputError:
                reasons.append("package_identity_unsupported")
            if package is not None:
                if (package.ecosystem != PACKAGE_TYPES.get(kind)
                        or normalize_name(name, package.ecosystem) != package.name or version != package.version):
                    reasons.append("package_identity_disagrees")
                if (package.target, next(k for k, e in TYPES.items() if e == package.ecosystem)) not in targets:
                    reasons.append("scope_binding_type_mismatch")
        if reasons:
            unknown.append(dict(source=source, advisory=advisory, artifact_id=identity, reasons=reasons))
        else:
            findings.append(Finding(package, advisory, source))
            provenance.append(dict(source=source, adapter="grype-json-0.86.1-v1", artifact_id=identity,
                                   location_record=source + "/artifact/locations/0", binding_record=binding_record))
    return findings, targets, unknown, provenance
