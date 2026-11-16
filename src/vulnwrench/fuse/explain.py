"""Trace one finding back to exact scanner assertions, without reinterpreting them."""

from copy import deepcopy

from .identity import InputError, text


def _resolve(document, pointer):
    for token in pointer.split("/")[1:]:
        token = token.replace("~1", "/").replace("~0", "~")
        document = document[int(token)] if isinstance(document, list) else document[token]
    return document


def _fields(document, pointer, keys):
    obj = _resolve(document, pointer)
    return [{"pointer": pointer + "/" + key, "value": obj[key]} for key in keys if key in obj]


def _locations(document, observation):
    """Retain original field names and indices; no inferred filesystem identities."""
    pointer = observation["pointer"]
    scanner = observation["scanner"]
    raw = _resolve(document, pointer)
    if scanner == "trivy":
        result_pointer = pointer.rsplit("/Vulnerabilities/", 1)[0]
        package = _fields(document, pointer, ("PkgName", "InstalledVersion"))
        package += _fields(document, result_pointer, ("Type",))
        if raw.get("PkgIdentifier") is not None:
            package += _fields(document, pointer + "/PkgIdentifier", ("PURL",))
        paths = _fields(document, result_pointer, ("Target",)) + _fields(document, pointer, ("PkgPath",))
    elif scanner == "grype":
        package = [{"pointer": pointer + "/artifact", "value": raw["artifact"]}]
        paths = [field for i, _ in enumerate(raw["artifact"].get("locations") or [])
                 for field in _fields(document, pointer + f"/artifact/locations/{i}", ("path", "accessPath", "realPath"))]
    else:
        package_pointer = pointer.rsplit("/vulnerabilities/", 1)[0] + "/package"
        result_pointer = pointer.split("/packages/", 1)[0]
        package = [{"pointer": package_pointer, "value": _resolve(document, package_pointer)}]
        result = _resolve(document, result_pointer)
        paths = _fields(document, result_pointer + "/source", ("path",)) if result.get("source") is not None else []
    return package, [field for field in paths if field["value"]]


def _alias_links(observation, document):
    pointer = observation["pointer"]
    raw = _resolve(document, pointer)
    if observation["scanner"] == "osv":
        assertions = [(f"/aliases/{i}", alias) for i, alias in enumerate(raw.get("aliases") or [])]
        primary, basis = "/id", "osv-aliases"
    elif observation["scanner"] == "grype":
        assertions = [(f"/relatedVulnerabilities/{i}/id", alias["id"])
                      for i, alias in enumerate(raw.get("relatedVulnerabilities") or [])]
        primary, basis = "/vulnerability/id", "grype-relatedVulnerabilities"
    else:
        return []
    return [{"from": observation["originalId"], "to": alias, "basis": basis,
             "sourceId": observation["sourceId"], "observationId": observation["observationId"],
             "primaryIdPointer": pointer + primary, "pointer": pointer + suffix}
            for suffix, alias in assertions if alias != observation["originalId"]]


def explain_finding(merged, *, finding_id=None, advisory=None, package=None):
    """Explain exactly one finding from an unmodified merge_reports result.

    Select by finding_id OR exact advisory ID plus optional canonical package key.
    An advisory alone must identify one finding. Unknown package identities can
    be selected by finding_id. Selectors never infer aliases or normalize names.
    Returns detached evidence; does not modify the merge or assess remediation.
    """
    if finding_id is not None:
        if advisory is not None or package is not None:
            raise InputError("explain: use a finding ID or advisory/package selectors, not both")
        text(finding_id)
        matches = [f for f in merged["findings"] if f["findingId"] == finding_id]
    else:
        if advisory is None:
            raise InputError("explain: a finding ID or advisory selector is required")
        text(advisory)
        if package is not None:
            text(package)
        matches = [f for f in merged["findings"] if advisory in f["ids"]
                   and (package is None or f["package"]["identity"] == package)]
    if not matches:
        raise InputError("explain: no finding matches the selectors")
    if len(matches) != 1:
        raise InputError("explain: selection is ambiguous; add a package identity or use a finding ID")
    finding = matches[0]
    ids = set(finding["ids"])
    # Alias assertions are global: another package can supply a transitive bridge.
    # Include all actual links in this component, never a synthetic spanning edge.
    alias_observations = {edge["observationId"] for edge in merged["aliasEdges"]
                          if edge["from"] in ids and edge["to"] in ids}
    selected = {o["observationId"] for o in finding["observations"]}
    needed = selected | alias_observations
    sources = {s["sourceId"]: s for s in merged["inputs"]}
    observations = sorted((o for f in merged["findings"] for o in f["observations"]
                           if o["observationId"] in needed), key=lambda o: o["observationId"])
    evidence, links = [], []
    for observation in observations:
        document = sources[observation["sourceId"]]["rawReport"]
        package_fields, paths = _locations(document, observation)
        evidence.append({"observation": observation, "contributesToFinding": observation["observationId"] in selected,
                         "rawObservation": _resolve(document, observation["pointer"]),
                         "packageEvidence": package_fields, "pathEvidence": paths})
        if observation["observationId"] in alias_observations:
            links.extend(_alias_links(observation, document))
    return deepcopy({
        "schemaVersion": "vulnfuse-explain-1", "toolVersion": merged["toolVersion"], "notice": merged["notice"],
        "groupingRules": {"packageIdentity": "exact-canonical-identity;unknown-isolated-per-observation",
                          "advisoryIdentity": "explicit-global-transitive-alias-component",
                          "scannerPaths": "provenance-only", "purlSubpath": "part-of-package-identity"},
        "remediationAssessment": "not-evaluated", "finding": finding,
        "aliasLinks": sorted(links, key=lambda e: (e["from"], e["to"], e["observationId"], e["pointer"])),
        "evidence": evidence,
        "inputs": [{k: v for k, v in source.items() if k != "rawReport"} for source in merged["inputs"]],
        "coverageAssessment": merged["coverageAssessment"], "coverageManifest": merged["coverageManifest"],
    })
