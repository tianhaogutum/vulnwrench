"""Pre-join diagnostics without resolving conflicting assignments or loading evidence."""

from collections import defaultdict
import html
import json
from pathlib import Path
import re

from .core import InputError, _inventory, _purl, _read, normalize_repository


def render_lint_markdown(report: dict) -> str:
    """Render coverage and every issue location, with a lossless lint appendix."""
    def cell(value):
        text = str(value) if value is not None else "—"
        # Entities cannot introduce Markdown syntax (including pipes, links,
        # emphasis or backticks). Preserve exact strings in the JSON appendix.
        return "".join(" " if char in "\r\n\t\v\f\x1c\x1d\x1e\x85\u2028\u2029" else f"&#{ord(char)};"
                       if char in "\\`*_{}[]()#+!|~" else html.escape(char)
                       for char in text)

    def row(values):
        return "| " + " | ".join(cell(value) for value in values) + " |"

    summary = report["summary"]
    lines = ["# Mapping lint", "",
             f"Components: **{summary['components']}**; mapped: **{summary['mappedComponents']}**; "
             f"ambiguous: **{summary['ambiguousComponents']}**; unmapped or missing PURL: **{summary['unmappedComponents']}**.", "",
             f"Mapping entries: **{summary['mappingEntries']}**; ambiguous PURLs: **{summary['ambiguousMappings']}**; "
             f"unused PURLs: **{summary['unusedMappings']}**; duplicate PURLs: **{summary['duplicateMappings']}**; "
             f"shared repository identifiers: **{summary['duplicateRepositoryIdentifiers']}**.", "",
             "Mapping status describes coverage, not a security decision.", "",
             "## Components", "",
             "| Name | PURL | Repository | Mapping status | File | JSON Pointer |",
             "| --- | --- | --- | --- | --- | --- |"]
    for component in report["components"]:
        lines.append(row([component["name"], component["purl"], component["repository"],
                          component["mappingStatus"], report["inputs"]["bom"]["file"], component["path"]]))
    lines.extend(["", "## Issues", "",
                  "| Issue | Message | PURL | Repository | File | JSON Pointer | Occurrence |",
                  "| --- | --- | --- | --- | --- | --- | --- |"])
    for issue in report["issues"]:
        repository = (", ".join(issue["repositories"]) if "repositories" in issue
                      else issue.get("repository"))
        for location in issue["locations"]:
            lines.append(row([issue["code"], issue["message"], issue.get("purl"), repository,
                              location["file"], location["pointer"], location.get("occurrence")]))
    if not report["issues"]:
        lines.extend(["", "No issues."])
    lines.extend(["", "## Evidence", "",
                  "The JSON appendix retains the complete lint report, including every component, mapping entry, issue, location and input digest.", ""])
    appendix = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False)
    fence = "`" * max(3, 1 + max((len(run) for run in re.findall(r"`+", appendix)), default=0))
    appendix = appendix.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    lines.extend([fence + "json", appendix, fence, ""])
    return "\n".join(lines)


def lint_mappings(bom_path, mapping_path) -> dict:
    """Return advisory diagnostics; malformed inputs raise InputError.

    Repeated mapping keys are retained solely for analysis. Every assignment must
    still be an exact PURL and an explicit repository identifier. No assignment is
    selected for an ambiguous PURL, even when one repository has more occurrences.
    """
    try:
        return _lint_mappings(Path(bom_path), Path(mapping_path))
    except InputError:
        raise
    except (OSError, ValueError, TypeError, RecursionError, OverflowError):
        raise InputError("invalid or excessively nested input") from None


def _lint_mappings(bom_path, mapping_path):
    budget = [0]
    bom, bom_source = _read(bom_path, "SBOM", budget)
    inventory = _inventory(bom)
    pairs, mapping_source = _read(mapping_path, "mapping", budget, preserve_pairs=True)
    by_purl = defaultdict(list)
    by_repository = defaultdict(list)
    entries = []
    for purl, value in pairs:
        _purl(purl)
        repository = normalize_repository(value)
        pointer = "/" + purl.replace("~", "~0").replace("/", "~1")
        entry = {"purl": purl, "repository": repository,
                 "location": {"file": mapping_path.name, "pointer": pointer,
                              "occurrence": len(by_purl[purl]) + 1}}
        entries.append(entry)
        by_purl[purl].append(entry)
        by_repository[repository].append(entry)

    component_locations = defaultdict(list)
    for component in inventory:
        component_locations[component["purl"]].append(
            {"file": bom_path.name, "pointer": component["path"]})

    issues = []

    def issue(code, message, locations, **details):
        issues.append({"code": code, "message": message, "locations": locations, **details})

    assignments = {}
    ambiguous = set()
    unused = 0
    redundant = 0
    for purl, candidates in sorted(by_purl.items()):
        repositories = sorted({entry["repository"] for entry in candidates})
        locations = [entry["location"] for entry in candidates]
        if len(repositories) > 1:
            ambiguous.add(purl)
            issue("ambiguous_mapping", "One exact PURL assigns different canonical repositories; remove the conflicting entries before joining.",
                  locations + component_locations.get(purl, []), purl=purl, repositories=repositories)
        else:
            assignments[purl] = repositories[0]
            if len(candidates) > 1:
                redundant += 1
                issue("duplicate_mapping", "Repeated PURL entries assign the same canonical repository; keep one entry because check rejects repeated JSON keys.",
                      locations, purl=purl, repository=repositories[0])
        if purl not in component_locations:
            unused += 1
            issue("unused_mapping", "No component uses this exact PURL; check its version, qualifiers, case and escaping or remove the entry.",
                  locations, purl=purl)

    duplicate_repositories = 0
    for repository, candidates in sorted(by_repository.items()):
        if len(candidates) > 1:
            duplicate_repositories += 1
            issue("duplicate_repository_identifier", "Multiple mapping entries normalize to this repository; shared repositories are valid, but verify the assignments are intentional.",
                  [entry["location"] for entry in candidates], repository=repository)

    rows = []
    for component in inventory:
        purl = component["purl"]
        status = ("missing_purl" if purl is None else "ambiguous" if purl in ambiguous
                  else "mapped" if purl in assignments else "unmapped")
        row = dict(component, repository=assignments.get(purl), mappingStatus=status)
        rows.append(row)
        if status in ("missing_purl", "unmapped"):
            issue("missing_purl" if purl is None else "unmapped_component",
                  "Component has no PURL; supply an explicit PURL to map it." if purl is None else
                  "No exact mapping exists; supply an explicit PURL-to-repository assignment. No repository was inferred.",
                  [{"file": bom_path.name, "pointer": component["path"]}], purl=purl)

    return {
        "reportVersion": "1", "tool": {"name": "scorecard-join", "version": "0.1.0"},
        "summary": {
            "components": len(rows), "mappingEntries": len(entries),
            "mappedComponents": sum(row["mappingStatus"] == "mapped" for row in rows),
            "ambiguousComponents": sum(row["mappingStatus"] == "ambiguous" for row in rows),
            "unmappedComponents": sum(row["mappingStatus"] in ("unmapped", "missing_purl") for row in rows),
            "unusedMappings": unused, "ambiguousMappings": len(ambiguous),
            "duplicateRepositoryIdentifiers": duplicate_repositories, "duplicateMappings": redundant,
        },
        "issues": issues, "components": rows, "mappings": entries,
        "inputs": {"bom": {"file": bom_path.name, "sha256": bom_source["sha256"]},
                   "mapping": {"file": mapping_path.name, "sha256": mapping_source["sha256"]}},
    }
