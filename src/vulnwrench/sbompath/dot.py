"""Bounded DOT projection of existing shortest witnesses, without graph inference."""
import json

from .core import InputError, _select_findings


def _quoted(value):
    r"""Quote DOT strings and neutralize Graphviz label substitutions (e.g. \N).

    Unlike JSON, DOT does not decode Unicode escapes. Keep printable Unicode;
    render controls/surrogates as visible escape text, never raw invalid UTF-8.
    Only generated IDs are used as node identifiers.
    """
    chars = []
    for char in str(value):
        if char == "\\":
            chars.append("\\\\")
        elif char == '"':
            chars.append('\\"')
        elif char == "\n":
            chars.append("\\n")
        elif ord(char) < 32 or 127 <= ord(char) <= 159 or 0xD800 <= ord(char) <= 0xDFFF:
            chars.append(f"\\\\u{ord(char):04x}")
        else:
            chars.append(char)
    return '"' + "".join(chars) + '"'


def _attrs(values):
    # JSON is a raw custom attribute, not a Graphviz escString label. Its
    # serializer avoids backslash-quote pairs, so only structural quotes need
    # escaping; doubling its other backslashes would corrupt JSON on agget().
    attributes = []
    for key, value in sorted(values.items()):
        quoted = ('"' + value.replace('"', '\\"') + '"'
                  if key in ("results_json", "selected_roots_json", "input_digests_json",
                             "dangling_dependencies_json", "missing_dependency_declarations_json") else _quoted(value))
        attributes.append(f"{key}={quoted}")
    return ", ".join(attributes)


def _json(value):
    encoded = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    # Valid JSON Unicode escapes avoid the ambiguous DOT backslash-before-quote
    # case. Replacing escaped backslashes first preserves literal escape text.
    return encoded.replace("\\\\", "\\u005c").replace('\\"', "\\u0022")


def to_dot(report, *, finding_indexes=None, max_nodes=200, max_edges=400,
           include_input_digests=False, include_dangling_dependencies=False,
           include_missing_dependency_declarations=False):
    """Project an explain() report into deterministic DOT without mutating it.

    Select original Grype match indexes, including every candidate for an index.
    Nodes are selected roots, matched refs and retained witness intermediates.
    Edges are the union of retained shortest witnesses, not all dependency edges
    or all possible paths. Report truncation and DOT truncation remain distinct.
    To reserve path budget for selected findings, pass finding_indexes to explain()
    first; this formatter cannot recover witnesses omitted from an existing report.
    Caps limit emitted node/edge statements, not labels/metadata or working memory.
    Explicit root scope includes all selected refs even when nodes are capped.
    Explicit finding scope preserves explain() selection, or formatter selection
    alone; selected_findings and selected_results describe emitted results.
    Opt-in input digests identify the full original canonical JSON inputs, not
    the selected projection. No raw input evidence is embedded.
    Opt-in dangling diagnostics retain all full-input records, including null
    declaration targets and missing refs; they never add graph nodes or edges.
    Opt-in missing-declaration refs cover the full input, not just witnesses.
    Absence is not proof of no dependencies; diagnostics never assert safety.
    """
    if type(include_input_digests) is not bool:
        raise InputError("include_input_digests must be a boolean")
    if type(include_dangling_dependencies) is not bool:
        raise InputError("include_dangling_dependencies must be a boolean")
    if type(include_missing_dependency_declarations) is not bool:
        raise InputError("include_missing_dependency_declarations must be a boolean")
    for cap in (max_nodes, max_edges):
        if type(cap) is not int or cap < 1:
            raise InputError("DOT caps must be positive integers")
    available = {result["findingIndex"] for result in report["results"]}
    selected = _select_findings(finding_indexes, available)
    results = sorted((result for result in report["results"] if result["findingIndex"] in selected),
                     key=lambda result: (result["findingIndex"], result["vulnerableRef"] or ""))
    finding_scope = report["provenance"].get("selectedFindingIndexes")
    if finding_scope is None and finding_indexes is not None:
        finding_scope = sorted(selected)
    roots = set(report["roots"])
    affected = {result["vulnerableRef"] for result in results if result["vulnerableRef"] is not None}
    nodes = roots | affected
    edges = set()
    for result in results:
        for entry in result["affectedRoots"]:
            if entry["path"] is not None:
                nodes.update(entry["path"])
                edges.update(zip(entry["path"], entry["path"][1:]))

    # Preserve context and endpoints first, then sorted intermediates. Never emit
    # an edge whose endpoints were capped out: DOT would create implicit nodes.
    retained = set(sorted(nodes, key=lambda ref: (0 if ref in roots else 1 if ref in affected else 2, ref))[:max_nodes])
    emitted_edges = sorted((a, b) for a, b in edges if a in retained and b in retained)[:max_edges]
    node_ids = {ref: f"n{i}" for i, ref in enumerate(sorted(retained))}
    roots_omitted = sum(result["truncation"]["rootsOmitted"] for result in results)
    paths_omitted = sum(result["truncation"]["pathsOmitted"] for result in results)
    nodes_omitted = len(nodes) - len(retained)
    edges_omitted = len(edges) - len(emitted_edges)
    truncated = str(bool(roots_omitted or paths_omitted or nodes_omitted or edges_omitted)).lower()
    scope = "One shortest path per root and result; alternate paths not enumerated."
    result_metadata = [{key: result[key] for key in (
        "findingIndex", "vulnerabilityId", "vulnerableRef", "status", "affectedRootCount", "truncation")}
        for result in results]
    label_lines = ["Declared dependency witnesses",
                   "Blue boxes: roots; red fill: affected nodes; bold edges: witnesses.", scope,
                   "Unreachable does not mean safe; missing declarations may hide dependencies.",
                   f"Truncated: {truncated}; nodes omitted: {nodes_omitted}; edges omitted: {edges_omitted}; "
                   f"report roots omitted: {roots_omitted}; report paths omitted: {paths_omitted}."]
    if include_input_digests:
        label_lines.append("Input digests: SHA-256 of canonical JSON for full original inputs "
                           "(not the selected witness projection); mapping null means no explicit mapping input.")
    if include_dangling_dependencies:
        label_lines.append(f"Dangling dependency diagnostics (full input): "
                           f"{len(report['graph']['danglingDependencies'])} records; "
                           "unknown endpoint refs excluded from traversal; no nodes or edges added.")
    if include_missing_dependency_declarations:
        label_lines.append(f"Missing dependency declarations (full input): "
                           f"{len(report['graph']['missingDependencyDeclarations'])} refs; "
                           "absence is not proof of no dependencies; no nodes or edges added.")
    if report["provenance"]["rootSelection"] == "explicit":
        label_lines.append(f"Roots selected explicitly: {', '.join(report['roots']) or '(none)' }.")
    if finding_scope is not None:
        indexes = ", ".join(map(str, finding_scope)) or "(none)"
        label_lines.append(f"Findings selected explicitly (zero-based): {indexes}. "
                           f"Total active input findings: {report['summary']['activeFindings']}; "
                           f"selected results: {len(results)}.")
        if sorted(selected) != finding_scope:
            indexes = ", ".join(map(str, sorted(selected))) or "(none)"
            label_lines.append(f"DOT findings emitted (zero-based): {indexes}.")
    for result in results:
        label_lines.append(f"Finding {result['findingIndex']} {result['vulnerabilityId']} / "
                           f"{result['vulnerableRef'] if result['vulnerableRef'] is not None else '(unjoined)'}: "
                           f"{result['status']}; affected roots: "
                           f"{result['affectedRootCount'] if result['affectedRootCount'] is not None else 'unknown'}")
    attrs = {"rankdir": "LR", "labelloc": "t", "label": "\n".join(label_lines),
             "witness_scope": scope, "selected_findings": _json(sorted(selected)),
             "results_json": _json(result_metadata), "inferred_edges": 0,
             "input_cycles_detected": str(report["graph"]["cycles"]["detected"]).lower(),
             "max_nodes": max_nodes, "max_edges": max_edges,
             "nodes_total": len(nodes), "edges_total": len(edges),
             "nodes_omitted": nodes_omitted, "edges_omitted": edges_omitted,
             "report_roots_omitted": roots_omitted, "report_paths_omitted": paths_omitted,
             "truncated": truncated}
    if include_input_digests:
        attrs.update(input_digests_json=_json(report["provenance"]["inputDigests"]),
                     digest_algorithm=report["provenance"]["digestAlgorithm"])
    if include_dangling_dependencies:
        attrs.update(dangling_dependencies_json=_json(report["graph"]["danglingDependencies"]),
                     dangling_dependency_count=len(report["graph"]["danglingDependencies"]))
    if include_missing_dependency_declarations:
        attrs.update(missing_dependency_declarations_json=_json(report["graph"]["missingDependencyDeclarations"]),
                     missing_dependency_declaration_count=len(report["graph"]["missingDependencyDeclarations"]))
    if report["provenance"]["rootSelection"] == "explicit":
        attrs.update(root_selection="explicit", selected_roots_json=_json(report["roots"]))
    if finding_scope is not None:
        attrs.update(finding_selection="explicit", selected_finding_indexes_json=_json(finding_scope),
                     active_findings=report["summary"]["activeFindings"], selected_results=len(results))
    lines = ["digraph sbom_witnesses {", "  graph [" + _attrs(attrs) + "];"]
    vulnerabilities = {}
    for result in results:
        vulnerabilities.setdefault(result["vulnerableRef"], set()).add(result["vulnerabilityId"])
    for ref in sorted(retained):
        is_root, is_affected = ref in roots, ref in affected
        label = "\n".join([ref, *sorted(vulnerabilities.get(ref, []))])
        attrs = {"label": label, "sbom_ref": ref,
                 "is_root": str(is_root).lower(), "is_affected": str(is_affected).lower(),
                 "shape": "box" if is_root else "ellipse", "style": "filled",
                 "color": "blue" if is_root else "black",
                 "fillcolor": "mistyrose" if is_affected else "white"}
        lines.append(f"  {node_ids[ref]} [" + _attrs(attrs) + "];")
    for source, target in emitted_edges:
        lines.append(f"  {node_ids[source]} -> {node_ids[target]} [" +
                     _attrs({"witness": "true", "style": "bold", "color": "firebrick"}) + "];")
    lines.extend(["}", ""])
    return "\n".join(lines)
