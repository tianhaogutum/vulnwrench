"""Offline, explicit-edge SBOM reachability. No scanner or network integration."""

from collections import deque
from copy import deepcopy
import hashlib
import json
import re

VERSION = "0.1.0"


class InputError(ValueError):
    """Invalid or unsupported input; messages contain schema locations, not values."""


def _object(value, location):
    if not isinstance(value, dict):
        raise InputError(f"{location} must be an object")
    return value


def _array(value, location):
    if not isinstance(value, list):
        raise InputError(f"{location} must be an array")
    return value


def _text(value, location):
    if not isinstance(value, str) or not value.strip():
        raise InputError(f"{location} must be a nonempty string")
    return value


def _optional_text(obj, key, location):
    value = obj.get(key)
    if value is not None and value != "":
        return _text(value, f"{location}.{key}")
    return None


def _purl(obj, location):
    value = _optional_text(obj, "purl", location)
    if value is not None and not value.startswith("pkg:"):
        raise InputError(f"{location}.purl must start with pkg:")
    return value


def _fingerprint(value):
    data = json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                      separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _cycles(adjacency):
    """Iterative DFS: report back edges, not an exponential enumeration of cycles."""
    colors = {}
    back_edges = []
    for start in sorted(adjacency):
        if colors.get(start):
            continue
        colors[start] = 1
        stack = [(start, iter(adjacency[start]))]
        while stack:
            node, children = stack[-1]
            child = next(children, None)
            if child is None:
                colors[node] = 2
                stack.pop()
            elif colors.get(child) == 1:
                back_edges.append({"from": node, "to": child})
            elif not colors.get(child):
                colors[child] = 1
                stack.append((child, iter(adjacency[child])))
    return sorted(back_edges, key=lambda edge: (edge["from"], edge["to"]))


def _bfs(adjacency, root):
    parents = {root: None}
    pending = deque([root])
    while pending:
        node = pending.popleft()
        for child in adjacency[node]:
            if child not in parents:
                parents[child] = node
                pending.append(child)
    return parents


def _path(parents, target):
    path = []
    node = target
    while node is not None:
        path.append(node)
        node = parents[node]
    return path[::-1]


def _cyclonedx_projection(bom, warnings):
    if bom.get("bomFormat") != "CycloneDX":
        raise InputError("bom.bomFormat must be CycloneDX")
    if bom.get("specVersion") not in ("1.4", "1.5", "1.6"):
        raise InputError("unsupported CycloneDX specVersion; supported: 1.4, 1.5, 1.6")
    warnings.append({"code": "explicit_edges_only",
                     "message": "Only dependencies[].dependsOn is traversed; no runtime exploitability or complete dependency coverage is implied. Other fields remain in evidence."})
    components = {}
    purls = {}
    declared_root = None
    if "services" in bom and _array(bom["services"], "bom.services"):
        raise InputError("CycloneDX services are unsupported")
    if "compositions" in bom and _array(bom["compositions"], "bom.compositions"):
        warnings.append({"code": "compositions_not_interpreted",
                         "message": "Composition completeness assertions are retained, not interpreted."})
    metadata = _object(bom.get("metadata", {}), "bom.metadata")
    work = [(item, f"bom.components[{i}]") for i, item in enumerate(
        _array(bom.get("components", []), "bom.components"))]
    if "component" in metadata:
        root_component = _object(metadata["component"], "bom.metadata.component")
        declared_root = _text(root_component.get("bom-ref"), "bom.metadata.component.bom-ref")
        work.append((root_component, "bom.metadata.component"))
    # Nested component containment declares nodes only, never dependency edges.
    while work:
        component, location = work.pop()
        _object(component, location)
        ref = _text(component.get("bom-ref"), f"{location}.bom-ref")
        if ref in components:
            raise InputError("duplicate bom-ref in component inventory")
        components[ref] = component
        purl = _purl(component, location)
        if purl:
            purls.setdefault(purl, []).append(ref)
        if "components" in component:
            work.extend((item, f"{location}.components[{i}]") for i, item in enumerate(
                _array(component["components"], f"{location}.components")))
    adjacency = {ref: set() for ref in components}
    dependency_refs = set()
    dangling = []
    if "dependencies" not in bom:
        warnings.append({"code": "dependencies_absent", "message": "Dependency section is absent; no edges inferred."})
    for i, dependency in enumerate(_array(bom.get("dependencies", []), "bom.dependencies")):
        location = f"bom.dependencies[{i}]"
        _object(dependency, location)
        ref = _text(dependency.get("ref"), f"{location}.ref")
        if ref in dependency_refs:
            raise InputError("duplicate dependency ref declaration")
        dependency_refs.add(ref)
        if "provides" in dependency and _array(dependency["provides"], f"{location}.provides"):
            raise InputError("dependency provides relationships are unsupported")
        if "dependsOn" not in dependency:
            warnings.append({"code": "depends_on_absent", "ref": ref,
                             "message": "Dependency declaration lacks dependsOn; outgoing relationships are unknown."})
        children = _array(dependency.get("dependsOn", []), f"{location}.dependsOn")
        if ref not in components:
            dangling.append({"from": ref, "to": None, "missing": [ref], "kind": "dependency_source"})
        for child in sorted({_text(child, f"{location}.dependsOn[]") for child in children}):
            missing = sorted({node for node in (ref, child) if node not in components})
            if missing:
                dangling.append({"from": ref, "to": child, "missing": missing, "kind": "edge"})
            else:
                adjacency[ref].add(child)
    declared_roots = [declared_root] if declared_root is not None else []
    return (components, purls, declared_roots, "metadata.component",
            adjacency, dependency_refs, dangling)


def _spdx_id(value, location):
    value = _text(value, location)
    if re.fullmatch(r"SPDXRef-[A-Za-z0-9.-]+", value) is None:
        raise InputError(f"{location} must be a local SPDXRef identifier")
    return value


def _spdx_projection(bom, warnings):
    """Project SPDX 2.3 packages and DEPENDS_ON only; retain original evidence.

    DESCRIBES from the document and documentDescribes select roots, never edges.
    Non-package inventories are indexed only to reject duplicate/unknown IDs.
    This is intentionally not a complete SPDX schema validator or converter.
    """
    if bom.get("spdxVersion") != "SPDX-2.3":
        raise InputError("unsupported SPDX spdxVersion; supported: SPDX-2.3")
    if "bomFormat" in bom:
        raise InputError("mixed SPDX and CycloneDX format declarations are unsupported")
    document_id = _spdx_id(bom.get("SPDXID"), "bom.SPDXID")
    if document_id != "SPDXRef-DOCUMENT":
        raise InputError("bom.SPDXID must identify SPDXRef-DOCUMENT")
    warnings.append({"code": "explicit_edges_only",
                     "message": "Only package-to-package DEPENDS_ON is traversed; no runtime exploitability or complete dependency coverage is implied. Other fields remain in evidence."})
    components, purls = {}, {}
    inventory_ids = {document_id}
    for inventory in ("packages", "files", "snippets"):
        for i, item in enumerate(_array(bom.get(inventory, []), f"bom.{inventory}")):
            location = f"bom.{inventory}[{i}]"
            _object(item, location)
            ref = _spdx_id(item.get("SPDXID"), f"{location}.SPDXID")
            if ref in inventory_ids:
                raise InputError("duplicate SPDXID in document inventory")
            inventory_ids.add(ref)
            if inventory != "packages":
                continue
            package_purls = set()
            for j, external in enumerate(_array(item.get("externalRefs", []), f"{location}.externalRefs")):
                ext_location = f"{location}.externalRefs[{j}]"
                _object(external, ext_location)
                category = _text(external.get("referenceCategory"), f"{ext_location}.referenceCategory")
                kind = _text(external.get("referenceType"), f"{ext_location}.referenceType")
                locator = _text(external.get("referenceLocator"), f"{ext_location}.referenceLocator")
                if category == "PACKAGE-MANAGER" and kind == "purl":
                    if not locator.startswith("pkg:"):
                        raise InputError(f"{ext_location}.referenceLocator must start with pkg:")
                    package_purls.add(locator)
            if len(package_purls) > 1:
                raise InputError("multiple distinct PURLs for one SPDX package are unsupported")
            purl = next(iter(package_purls), None)
            components[ref] = {"purl": purl}
            if purl:
                purls.setdefault(purl, []).append(ref)
    declared_roots = set()
    for ref in _array(bom.get("documentDescribes", []), "bom.documentDescribes"):
        ref = _spdx_id(ref, "bom.documentDescribes[]")
        if ref not in components:
            raise InputError("an SPDX declared root is absent from the package inventory")
        declared_roots.add(ref)
    adjacency = {ref: set() for ref in components}
    dependency_refs = set()
    if "relationships" not in bom:
        warnings.append({"code": "spdx_relationships_absent",
                         "message": "Relationship section is absent; no edges inferred."})
    for i, relationship in enumerate(_array(bom.get("relationships", []), "bom.relationships")):
        location = f"bom.relationships[{i}]"
        _object(relationship, location)
        source = _text(relationship.get("spdxElementId"), f"{location}.spdxElementId")
        target = _text(relationship.get("relatedSpdxElement"), f"{location}.relatedSpdxElement")
        kind = _text(relationship.get("relationshipType"), f"{location}.relationshipType")
        # SPDX right-hand markers are declarations, never inventory nodes/edges.
        if kind == "DEPENDS_ON" and target in ("NONE", "NOASSERTION"):
            if source not in inventory_ids:
                raise InputError(f"{location} has an unresolved or unsupported endpoint")
            if source not in components:
                raise InputError(f"{location} DEPENDS_ON source must be a package")
            dependency_refs.add(source)
            warnings.append({"code": f"spdx_dependency_{target.lower()}", "relationshipIndex": i,
                             "relationshipType": kind, "from": source, "to": target,
                             "message": ("Author asserts no dependencies (NONE); this assertion is retained, not independently verified. No edge or root is inferred."
                                         if target == "NONE" else
                                         "Dependencies are explicitly unknown (NOASSERTION); no edge or root is inferred.")})
            continue
        # CONTAINS markers describe containment completeness, never dependencies.
        contains_marker = kind == "CONTAINS" and target in ("NONE", "NOASSERTION")
        # Every source still resolves locally, including for marker targets.
        if source not in inventory_ids or (target not in inventory_ids and not contains_marker):
            raise InputError(f"{location} has an unresolved or unsupported endpoint")
        if kind == "DEPENDS_ON":
            if source not in components or target not in components:
                raise InputError(f"{location} DEPENDS_ON endpoints must be packages")
            adjacency[source].add(target)
            dependency_refs.add(source)
        elif kind == "DESCRIBES" and source == document_id:
            if target not in components:
                raise InputError(f"{location} declared root must be a package")
            declared_roots.add(target)
        else:
            message = "Relationship retained in evidence but not used as a dependency edge or root declaration."
            if contains_marker:
                message = ("Author asserts no contained elements (NONE); this assertion is retained, not independently verified."
                           if target == "NONE" else
                           "Contained elements are explicitly unknown (NOASSERTION).")
                message += " No dependency declaration, edge or root is inferred."
            warnings.append({"code": "spdx_relationship_not_projected", "relationshipIndex": i,
                             "relationshipType": kind, "from": source, "to": target,
                             "message": message})
    return (components, purls, declared_roots, "spdx-declarations",
            adjacency, dependency_refs, [])


def _select_findings(finding_indexes, available):
    if finding_indexes is None:
        return available
    if not isinstance(finding_indexes, list) or any(
            type(index) is not int or index < 0 for index in finding_indexes):
        raise InputError("finding_indexes must be an array of nonnegative integers")
    selected = set(finding_indexes)
    if not selected <= available:
        raise InputError("a selected finding index is absent from the report input")
    return selected


def explain(bom, grype, *, roots=None, mapping=None, max_roots=100, max_paths=1000,
            finding_indexes=None):
    """Return a JSON-compatible report. Explicit roots replace all format-declared roots.

    max_roots bounds the affected-root list per result; max_paths bounds witness
    paths across the whole report. Counts always cover all selected roots.
    finding_indexes selects original Grype match indexes before allocating caps;
    None selects all, [] selects none. All inputs are still validated and retained.
    Input dictionaries are retained as evidence in a deep copy of the report.
    """
    for value in (max_roots, max_paths):
        if type(value) is not int or value < 1:
            raise InputError("caps must be positive integers")
    _object(bom, "bom")
    _object(grype, "grype")
    warnings = []
    is_spdx = "spdxVersion" in bom
    projection = _spdx_projection if is_spdx else _cyclonedx_projection
    (components, purls, declared_roots, default_selection,
     adjacency, dependency_refs, dangling) = projection(bom, warnings)
    if not components:
        warnings.append({"code": "empty_inventory", "message": "No component refs are available."})
    if roots is None:
        selected_roots = sorted(declared_roots)
        root_selection = default_selection if selected_roots else "none"
    else:
        _array(roots, "roots")
        selected_roots = sorted({_text(root, "roots[]") for root in roots})
        root_selection = "explicit"
    if any(root not in components for root in selected_roots):
        raise InputError("a selected root is absent from the component inventory")
    if not selected_roots:
        warnings.append({"code": "no_roots", "message": "No roots declared or supplied; reachability is unknown. No roots are inferred."})
    adjacency = {ref: sorted(children) for ref, children in sorted(adjacency.items())}
    missing_declarations = sorted(set(components) - dependency_refs)
    if missing_declarations:
        warnings.append({"code": "dependency_declarations_missing", "refs": missing_declarations,
                         "message": "These nodes have no dependency declaration; absence is not proof of no dependencies."})
    if dangling:
        warnings.append({"code": "dangling_dependencies", "message": "Unknown endpoint refs are reported and excluded from traversal."})
    back_edges = _cycles(adjacency)
    if back_edges:
        warnings.append({"code": "cycles_detected", "message": "DFS back edges prove cycles; traversal remains finite."})
    unknown_purls = sorted(ref for ref, component in components.items() if not component.get("purl"))
    if unknown_purls:
        warnings.append({"code": "component_purls_missing", "refs": unknown_purls,
                         "message": "Components without PURLs require explicit artifact-id mapping to join."})

    explicit = {}
    if mapping is not None:
        _object(mapping, "mapping")
        if type(mapping.get("schemaVersion")) is not int or mapping["schemaVersion"] != 1:
            raise InputError("mapping.schemaVersion must be 1")
        for artifact_id, refs in _object(mapping.get("artifacts"), "mapping.artifacts").items():
            _text(artifact_id, "mapping.artifacts key")
            targets = _array(refs, "mapping.artifacts targets")
            if not targets:
                raise InputError("mapping targets must not be empty")
            targets = sorted({_text(ref, "mapping target") for ref in targets})
            if any(ref not in components for ref in targets):
                raise InputError("mapping target is absent from the component inventory")
            explicit[artifact_id] = targets
    descriptor = _object(grype.get("descriptor", {}), "grype.descriptor")
    if "name" in descriptor and descriptor["name"] != "grype":
        raise InputError("unsupported findings producer; expected grype")
    matches = _array(grype.get("matches"), "grype.matches")
    ignored = _array(grype.get("ignoredMatches", []), "grype.ignoredMatches")
    if ignored:
        warnings.append({"code": "ignored_matches_not_analyzed", "count": len(ignored),
                         "message": "Only active matches are analyzed; ignoredMatches are retained in evidence."})
    findings = []
    used_mapping = set()
    for i, match in enumerate(matches):
        location = f"grype.matches[{i}]"
        _object(match, location)
        vulnerability = _object(match.get("vulnerability"), f"{location}.vulnerability")
        vuln_id = _text(vulnerability.get("id"), f"{location}.vulnerability.id")
        artifact = _object(match.get("artifact"), f"{location}.artifact")
        artifact_id = _optional_text(artifact, "id", f"{location}.artifact")
        purl = _purl(artifact, f"{location}.artifact")
        if artifact_id in explicit:
            refs = explicit[artifact_id]
            method = "explicit-artifact-id"
            used_mapping.add(artifact_id)
        else:
            refs = sorted(purls.get(purl, []))
            method = "exact-purl" if refs else None
        findings.append({"findingIndex": i, "vulnerabilityId": vuln_id,
                         "artifactId": artifact_id, "purl": purl, "refs": refs,
                         "joinMethod": method})
    unused = sorted(set(explicit) - used_mapping)
    if unused:
        warnings.append({"code": "unused_mapping", "artifactIds": unused,
                         "message": "Mapping entries do not match active findings."})
    ambiguous = sorted(purl for purl, refs in purls.items() if len(refs) > 1)
    if ambiguous:
        warnings.append({"code": "nonunique_purls", "purls": ambiguous,
                         "message": "Exact PURLs identify multiple refs; every candidate is reported separately."})

    selected_findings = _select_findings(finding_indexes, set(range(len(matches))))
    findings = [finding for finding in findings if finding["findingIndex"] in selected_findings]

    # Count every affected root, retaining only capped root lists.
    targets = {ref for finding in findings for ref in finding["refs"]}
    affected = {target: [] for target in targets}
    affected_counts = {target: 0 for target in targets}
    for root in selected_roots:
        parents = _bfs(adjacency, root)
        for target in sorted(targets & parents.keys()):
            affected_counts[target] += 1
            if len(affected[target]) < max_roots:
                affected[target].append(root)
    results = []
    paths_emitted = 0
    pending_paths = {}
    for finding in sorted(findings, key=lambda item: (item["vulnerabilityId"], item["purl"] or "", item["artifactId"] or "", item["findingIndex"])):
        refs = finding["refs"]
        common = {key: value for key, value in finding.items() if key not in ("refs", "joinMethod")}
        if not refs:
            results.append({**common, "vulnerableRef": None, "join": {"method": None, "candidateCount": 0},
                            "status": "unknown_identity" if not finding["purl"] else "unmapped",
                            "affectedRootCount": None, "affectedRoots": [],
                            "truncation": {"rootsOmitted": 0, "pathsOmitted": 0}})
            continue
        for ref in refs:
            all_roots = affected[ref]
            roots_list = []
            omitted_paths = 0
            for root in all_roots[:max_roots]:
                entry = {"root": root, "path": None}
                if paths_emitted < max_paths:
                    pending_paths.setdefault(root, []).append((entry, ref))
                    paths_emitted += 1
                else:
                    entry["pathOmittedReason"] = "max_paths"
                    omitted_paths += 1
                roots_list.append(entry)
            results.append({**common, "vulnerableRef": ref,
                            "join": {"method": finding["joinMethod"], "candidateCount": len(refs)},
                            "status": "reachable" if all_roots else ("unreachable" if selected_roots else "roots_unknown"),
                            "affectedRootCount": affected_counts[ref] if selected_roots else None,
                            "affectedRoots": roots_list,
                            "truncation": {"rootsOmitted": max(0, affected_counts[ref] - max_roots), "pathsOmitted": omitted_paths}})
    # A second BFS only for roots with emitted witnesses avoids materializing
    # uncapped path collections. At most max_paths complete paths are built.
    for root, entries in pending_paths.items():
        parents = _bfs(adjacency, root)
        for entry, ref in entries:
            entry["path"] = _path(parents, ref)
    roots_omitted = sum(result["truncation"]["rootsOmitted"] for result in results)
    paths_omitted = sum(result["truncation"]["pathsOmitted"] for result in results)
    if roots_omitted or paths_omitted:
        warnings.append({"code": "output_truncated", "message": "Witness/root caps were reached; full affected-root counts are retained."})
    report = {
        "schemaVersion": "1.0", "tool": {"name": "sbom-pathfinder", "version": VERSION},
        "provenance": {"inputDigests": {"bom": _fingerprint(bom), "grype": _fingerprint(grype),
                                         "mapping": _fingerprint(mapping) if mapping is not None else None},
                       "digestAlgorithm": "sha256-canonical-json", "rootSelection": root_selection,
                       "identityPolicy": "explicit mapping overrides exact PURL; no name/version guessing",
                       "inferredEdges": 0},
        "roots": selected_roots,
        "graph": {"nodeCount": len(components), "edgeCount": sum(map(len, adjacency.values())),
                  "danglingDependencies": sorted(dangling, key=lambda edge: (edge["from"], edge["to"] or "")),
                  "missingDependencyDeclarations": missing_declarations,
                  "cycles": {"detected": bool(back_edges), "backEdges": back_edges}},
        "limits": {"maxRootsPerResult": max_roots, "maxPathsTotal": max_paths},
        "summary": {"activeFindings": len(matches), "ignoredFindings": len(ignored), "results": len(results),
                    "unmappedFindings": sum(not finding["refs"] for finding in findings),
                    "witnessPaths": paths_emitted, "rootsOmitted": roots_omitted, "pathsOmitted": paths_omitted},
        "results": results, "warnings": warnings,
        "evidence": {"bom": bom, "grype": grype, "mapping": mapping},
    }
    if is_spdx:
        report["provenance"].update(bomFormat="SPDX", specVersion="SPDX-2.3")
    if finding_indexes is not None:
        report["provenance"]["selectedFindingIndexes"] = sorted(selected_findings)
    return deepcopy(report)


def _md(value):
    """Escape untrusted strings in Markdown text/table context (including HTML)."""
    value = str(value)
    value = value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    for char in "\\`*_{}[]()!|":
        value = value.replace(char, "\\" + char)
    return value.replace("\r", "&#13;").replace("\n", "&#10;")


def to_markdown(report):
    """Human-readable projection; JSON is the lossless evidence format."""
    lines = ["# SBOM dependency witnesses", "",
             "Only explicit edges are traversed. Unreachable does not mean safe.", "",
             f"Roots: {', '.join(_md(root) for root in report['roots']) or '(unknown)'}. Inferred edges: 0.", ""]
    if report["provenance"]["rootSelection"] == "explicit":
        roots = ", ".join(_md(root) for root in report["roots"]) or "(none)"
        lines.extend([f"Roots selected explicitly: {roots}.", ""])
    if "selectedFindingIndexes" in report["provenance"]:
        indexes = ", ".join(str(index) for index in report["provenance"]["selectedFindingIndexes"]) or "(none)"
        lines.extend([f"Selected original finding indexes (Grype matches, zero-based): {indexes}. "
                      f"Total active input findings: {report['summary']['activeFindings']}; "
                      f"selected results: {report['summary']['results']}.", ""])
    lines.extend(["| Vulnerability | Ref | Artifact / PURL | Identity / state | Root | Shortest witness |",
                  "| --- | --- | --- | --- | --- | --- |"])
    for result in report["results"]:
        entries = result["affectedRoots"] or [{"root": "—", "path": None}]
        for entry in entries:
            path = " → ".join(_md(node) for node in entry["path"]) if entry["path"] is not None else "—"
            if entry.get("pathOmittedReason"):
                path = "omitted: max_paths"
            cells = [_md(result["vulnerabilityId"]), _md(result["vulnerableRef"] or "—"),
                     _md(result["purl"] or result["artifactId"] or "unknown"),
                     f"finding {result['findingIndex']}: {_md(result['status'])}; {_md(result['join']['method'] or 'unjoined')}",
                     _md(entry["root"]), path]
            lines.append("| " + " | ".join(cells) + " |")
        if result["truncation"]["rootsOmitted"]:
            lines.append(f"\nFinding {result['findingIndex']}: {result['truncation']['rootsOmitted']} affected roots omitted.\n")
    lines.extend(["", "## Completeness and provenance", ""])
    for warning in report["warnings"]:
        details = json.dumps({k: v for k, v in warning.items() if k != "message"}, sort_keys=True, ensure_ascii=False)
        lines.append(f"- {_md(details)}: {_md(warning['message'])}")
    lines.extend(["", "## Dangling dependencies", ""])
    for edge in report["graph"]["danglingDependencies"]:
        lines.append(f"- {_md(edge['from'])} → {_md(edge['to'] if edge['to'] is not None else '(declaration)')}; missing: {_md(', '.join(edge['missing']))}")
    lines.extend(["", f"Witness paths: {report['summary']['witnessPaths']}; roots omitted: {report['summary']['rootsOmitted']}; paths omitted: {report['summary']['pathsOmitted']}.",
                  "", "Input digests (SHA-256, canonical JSON):", ""])
    for name, digest in report["provenance"]["inputDigests"].items():
        if digest:
            lines.append(f"- {name}: {digest}")
    lines.extend(["", "Markdown is a projection. Use JSON for complete input evidence, mapping provenance, and per-finding details.", ""])
    return "\n".join(lines)
