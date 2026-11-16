"""Trace existing batch decisions without classifying findings a second time."""
from collections import defaultdict

from .core import require


def explain_findings(result, advisory, before_findings, after_findings, *, side=None, artifact_id=None, reason_code=None,
                     match_index=None, reason_codes_all=None, reason_codes_any=None, target=None, package_path=None):
    documents = {key: entry["document"] for key, entry in result["evidence"].items()}
    meta = documents["metadata"]
    filtered_side = side
    if filtered_side is not None:
        require(meta[filtered_side]["scanner"]["name"] == "grype",
                "explain: artifact filter requires a Grype report on selected side")
        if match_index is not None:
            require(match_index < len(documents[f"{filtered_side}_report"]["matches"]),
                    "explain: match index outside native matches array")

    def metadata_sources(field):
        return [f"/metadata/{side}/{field}" for side in ("before", "after")]

    report_sources = [f"/{side}_report/" + ("matches" if meta[side]["scanner"]["name"] == "grype" else "Results")
                      for side in ("before", "after")]
    coverage_sources = [f"/metadata/{side}/grype/targets" if meta[side]["scanner"]["name"] == "grype"
                        else f"/{side}_report/Results" for side in ("before", "after")]
    unknown_sources = [item["source"] for entries in result.get("unknown_findings", {}).values() for item in entries]
    # References to containers also resolve when optional fields/records are absent.
    reason_sources = {
        "scanner_identity_changed": metadata_sources("scanner"),
        "database_identity_missing": metadata_sources("database"),
        "database_identity_changed": metadata_sources("database"),
        "scan_profile_changed": metadata_sources("profile"),
        "incomplete_report": metadata_sources("report_complete"),
        "incomplete_inventory": metadata_sources("inventory_complete"),
        "report_target_coverage_changed": coverage_sources,
        "report_identity_unknown": unknown_sources or report_sources,
        "grype_database_checksum_changed": ["/before_report/descriptor/db", "/after_report/descriptor/db"],
        "grype_database_schema_changed": ["/before_report/descriptor/db", "/after_report/descriptor/db"],
        "grype_configuration_changed": ["/before_report/descriptor/configuration", "/after_report/descriptor/configuration"],
    }
    global_checks = [
        ("scanner_identity_unchanged", ["scanner_identity_changed"], metadata_sources("scanner")),
        ("database_identity_unchanged", ["database_identity_missing", "database_identity_changed"], metadata_sources("database")),
        ("scan_profile_unchanged", ["scan_profile_changed"], metadata_sources("profile")),
        ("reports_complete", ["incomplete_report"], metadata_sources("report_complete")),
        ("inventories_complete", ["incomplete_inventory"], metadata_sources("inventory_complete")),
        ("report_target_coverage_unchanged", ["report_target_coverage_changed"], coverage_sources),
        ("report_identities_known", ["report_identity_unknown"], unknown_sources or report_sources),
    ]
    if all(meta[side]["scanner"]["name"] == "grype" for side in ("before", "after")):
        global_checks.append(("grype_native_metadata_consistent",
                              ["grype_database_checksum_changed", "grype_database_schema_changed", "grype_configuration_changed"],
                              ["/before_report/descriptor", "/after_report/descriptor"]))

    explanations = []
    for index, row in enumerate(result["transitions"]):
        if filtered_side is not None or advisory not in row["aliases"]:
            continue
        if target is not None and row["package"]["target"] != target:
            continue
        if package_path is not None and row["package"]["path"] != package_path:
            continue
        report_records = row["before_records"] + row["after_records"]
        inventory_sources = ["/before_bom/components", "/after_bom/components"]
        scope_records = [f.source for f in before_findings + after_findings
                         if all(f.package.as_dict()[key] == value for key, value in row["package"].items())]
        sources = dict(reason_sources,
                       finding_missing_from_inventory=report_records + inventory_sources,
                       report_inventory_conflict=scope_records + inventory_sources)
        reasons = []

        def add_reason(code, refs):
            reasons.append(dict(code=code, sources=refs))

        if row["before_records"] and row["after_records"]:
            add_reason("finding_observed_both_sides", report_records)
            add_reason("version_sets_unchanged" if row["classification"] == "persistent" else "version_sets_changed",
                       report_records)
        elif row["after_records"]:
            add_reason("finding_newly_observed", [report_sources[0]] + row["after_records"])
        else:
            add_reason("finding_absent_after", row["before_records"] + [report_sources[1]])
        ids = set(row["before_ids"] + row["after_ids"])
        if len(ids) > 1 or advisory not in ids or row["advisory"] not in ids:
            # Include the explicit equivalence component (including transitive edges),
            # not unrelated aliases or any inference from advisory URLs.
            refs = ["/metadata/aliases/" + key.replace("~", "~0").replace("/", "~1")
                    for key in sorted(meta.get("aliases", {})) if key in row["aliases"]]
            add_reason("explicit_alias_equivalence", refs)
        for side in ("before", "after"):
            for entry in result.get("adapter_provenance", {}).get(side, []):
                if entry["source"] in report_records:
                    add_reason("explicit_grype_scope_binding", [entry["source"], entry["location_record"], entry["binding_record"]])
        for code in row["reasons"]:
            add_reason(code, sources[code])

        prerequisites = [dict(code=code, satisfied=not any(reason in row["reasons"] for reason in failures), sources=refs)
                         for code, failures, refs in global_checks]
        for code, satisfied, refs in (
            ("before_finding_observed", bool(row["before_records"]), row["before_records"] or [report_sources[0]]),
            ("after_finding_absent", not row["after_records"], row["after_records"] or [report_sources[1]]),
            ("findings_in_inventory", "finding_missing_from_inventory" not in row["reasons"], report_records + inventory_sources),
            ("scope_inventory_consistent", "report_inventory_conflict" not in row["reasons"], scope_records + inventory_sources),
            ("after_scope_present", bool(row["after_inventory_records"]), row["after_inventory_records"] or ["/after_bom/components"]),
        ):
            prerequisites.append(dict(code=code, satisfied=satisfied, sources=refs))
        explanations.append(dict(transition_index=index,
                                 decision=dict(classification=row["classification"], resolution=row["resolution"],
                                               fixed=row["fixed"], sources=report_records + row["before_inventory_records"]
                                               + row["after_inventory_records"] + inventory_sources + coverage_sources),
                                 reasons=reasons, fix_prerequisites=prerequisites))
    # Unknown records cannot be assigned to a normalized scope or transition.
    # Select their native IDs exactly and trace the adapter's reasons verbatim;
    # explicit aliases continue to select normalized rows above only.
    unknown_explanations = []
    for side in ("before", "after"):
        if target is not None:
            continue
        if filtered_side is not None and side != filtered_side:
            continue
        entries = result.get("unknown_findings", {}).get(side, [])
        if not entries:
            continue
        binding_container = f"/metadata/{side}/grype/bindings"
        # Reuse validated artifact IDs, never infer a binding from a path or BOM.
        binding_records = {binding["artifact_id"]: f"{binding_container}/{index}"
                           for index, binding in enumerate(meta[side]["grype"]["bindings"])}
        # Index all retained native artifacts, including unselected advisories.
        # IDs have meaning only within this report; preserve duplicates and indexes.
        artifact_records = defaultdict(list)
        for native_index, match in enumerate(documents[f"{side}_report"]["matches"]):
            artifact_records[match["artifact"]["id"]].append(f"/{side}_report/matches/{native_index}/artifact")
        for index, entry in enumerate(entries):
            if entry["advisory"] != advisory or (filtered_side is not None and entry["artifact_id"] != artifact_id):
                continue
            # Select whole entries; retain all original reasons and their context.
            if reason_code is not None and reason_code not in entry["reasons"]:
                continue
            if reason_codes_all is not None and not all(code in entry["reasons"] for code in reason_codes_all):
                continue
            if reason_codes_any is not None and not any(code in entry["reasons"] for code in reason_codes_any):
                continue
            source = entry["source"]
            # Native indexes belong to this report, not the compact unknown array.
            if match_index is not None and source != f"/{side}_report/matches/{match_index}":
                continue
            artifact = source + "/artifact"
            native_artifact = documents[f"{side}_report"]["matches"][int(source.rsplit("/", 1)[1])]["artifact"]
            context = {
                "artifact_id_conflict": [artifact + "/id"] + artifact_records[entry["artifact_id"]],
                "ambiguous_package_location": [artifact + "/locations"],
                "unsupported_package_location": [artifact + "/locations/0"],
                "scope_binding_missing": [artifact + "/id", binding_container],
                "unsupported_package_type": [artifact + "/type"],
                # Missing PURLs are unknown, but must never create dangling pointers.
                # Present malformed values remain evidence at the original field.
                "package_identity_unsupported": [artifact + "/purl" if "purl" in native_artifact else artifact],
                "package_identity_disagrees": [artifact + "/" + field for field in ("type", "name", "version", "purl")],
            }
            if entry["artifact_id"] in binding_records:
                binding_record = binding_records[entry["artifact_id"]]
                context["scope_binding_location_mismatch"] = [
                    artifact + "/id", artifact + "/locations/0",
                    binding_record + "/location",
                ]
                context["scope_binding_type_mismatch"] = [
                    artifact + "/id", artifact + "/purl", binding_record + "/target",
                    f"/metadata/{side}/grype/targets",
                ]
            unknown_explanations.append(dict(
                side=side, unknown_index=index, advisory=entry["advisory"], source=source,
                reasons=[dict(code=code, sources=[source] + context.get(code, [])) for code in entry["reasons"]]))
    if target is not None:
        require(bool(explanations), "explain: no normalized finding matches advisory, target and package path"
                if package_path is not None else "explain: no normalized finding matches advisory and target")
    else:
        require(bool(explanations or unknown_explanations), "explain: no finding matches advisory")
    explanation = dict(schema_version=1, requested_advisory=advisory, findings=explanations)
    if target is not None:
        explanation["normalized_filter"] = dict(target=target)
        if package_path is not None:
            explanation["normalized_filter"]["package_path"] = package_path
    if filtered_side is not None:
        explanation["unknown_filter"] = dict(side=filtered_side, artifact_id=artifact_id)
        if reason_code is not None:
            explanation["unknown_filter"]["reason_code"] = reason_code
        if reason_codes_all is not None:
            explanation["unknown_filter"]["reason_codes_all"] = reason_codes_all
        if reason_codes_any is not None:
            explanation["unknown_filter"]["reason_codes_any"] = reason_codes_any
        if match_index is not None:
            explanation["unknown_filter"]["match_index"] = match_index
    if unknown_explanations:
        explanation["unknown_findings"] = unknown_explanations
    return explanation
