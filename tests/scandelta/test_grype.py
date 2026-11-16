"""Pinned-format synthetic integration fixtures; never run a scanner."""
from copy import deepcopy
import json
from pathlib import Path
import unittest

from vulnwrench.scandelta import InputError, compare

FIXTURES = Path(__file__).resolve().parents[2] / "examples/delta/grype"


def documents(trivy=False):
    names = (["trivy-before.json", "trivy-after.json"] if trivy else ["before.json", "after.json"])
    names += ["before-bom.json", "after-bom.json", "trivy-scans.json" if trivy else "scans.json"]
    return [json.loads((FIXTURES / name).read_text()) for name in names]


class GrypeTests(unittest.TestCase):
    def test_pinned_fixtures_have_equivalent_package_advisory_transitions(self):
        trivy = compare(*documents(trivy=True))
        docs = documents()
        original = deepcopy(docs)
        grype = compare(*docs)
        for key in ("transitions",):
            def semantic(rows):
                return [{k: v for k, v in row.items() if k not in {"before_records", "after_records"}}
                        for row in rows]
            self.assertEqual(semantic(grype[key]), semantic(trivy[key]))
        self.assertEqual(grype["summary"], {"version_changed_still_affected": 1})
        self.assertEqual(grype["report_family"], "grype")
        self.assertTrue(grype["comparable"])
        self.assertEqual(docs, original)
        self.assertEqual(grype, compare(*docs))

    def test_fix_requires_same_scanner_database_profile_and_target_coverage(self):
        docs = documents()
        docs[1]["matches"] = []
        self.assertEqual(compare(*docs)["summary"], {"fixed_within_snapshot": 1})
        for change, expected in (
            (lambda d: d[4]["after"].update(database={}), "database_identity_missing"),
            (lambda d: d[4]["after"]["database"].update(id="other"), "database_identity_changed"),
            (lambda d: d[4]["after"].update(profile="other"), "scan_profile_changed"),
            (lambda d: d[4]["after"]["grype"].update(targets=[]), "report_target_coverage_changed"),
        ):
            changed = deepcopy(docs)
            change(changed)
            # No stale binding to an undeclared target.
            if not changed[4]["after"]["grype"]["targets"]:
                changed[4]["after"]["grype"]["bindings"] = []
            row = compare(*changed)["transitions"][0]
            self.assertEqual(row["classification"], "no_longer_reported")
            self.assertIn(expected, row["reasons"])
            self.assertFalse(row["fixed"])

    def test_unknown_identity_blocks_fix_and_removal_and_is_accounted(self):
        for mutation, reason in (
            (lambda d: d[4]["after"]["grype"].update(bindings=[]), "scope_binding_missing"),
            (lambda d: d[1]["matches"][0]["artifact"].update(locations=[]), "ambiguous_package_location"),
            (lambda d: d[1]["matches"][0]["artifact"]["locations"].append({"path": "/other"}), "ambiguous_package_location"),
            (lambda d: d[1]["matches"][0]["artifact"].update(type="rpm"), "unsupported_package_type"),
            (lambda d: d[1]["matches"][0]["artifact"].update(purl=""), "package_identity_unsupported"),
            (lambda d: d[1]["matches"][0]["artifact"].update(version="different"), "package_identity_disagrees"),
            (lambda d: d[4]["after"]["grype"]["bindings"][0]["location"].update(path="/guess"), "scope_binding_location_mismatch"),
            (lambda d: d[1]["matches"][0]["artifact"]["locations"][0].update(layerID="sha256:layer"), "unsupported_package_location"),
        ):
            for remove_inventory in (False, True):
                docs = documents()
                mutation(docs)
                if remove_inventory:
                    docs[3]["components"] = []
                with self.subTest(reason=reason, removal=remove_inventory):
                    result = compare(*docs)
                    row = result["transitions"][0]
                    self.assertEqual(row["classification"], "no_longer_reported")
                    self.assertFalse(row["fixed"])
                    self.assertIn("report_identity_unknown", row["reasons"])
                    unknown = result["unknown_findings"]["after"]
                    self.assertEqual(len(unknown), 1)
                    self.assertIn(reason, unknown[0]["reasons"])
                    self.assertEqual(unknown[0]["source"], "/after_report/matches/0")
                    self.assertEqual(result["accounting"]["after_findings"], 1)
                    self.assertEqual(result["accounting"]["after_records_accounted"], 1)

    def test_native_and_binding_provenance_resolves(self):
        result = compare(*documents())
        docs = {k: v["document"] for k, v in result["evidence"].items()}
        for side in ("before", "after"):
            item = result["adapter_provenance"][side][0]
            values = {}
            for key in ("source", "location_record", "binding_record"):
                value = docs
                for token in item[key].lstrip("/").split("/"):
                    value = value[int(token)] if isinstance(value, list) else value[token]
                values[key] = value
            self.assertEqual(values["source"]["artifact"]["locations"][0], values["location_record"])
            self.assertEqual(values["binding_record"]["location"], values["location_record"])

    def test_pypi_and_scoped_npm_use_same_normalization_as_trivy(self):
        for ecosystem, kind, name, encoded, target_type in (
            ("pypi", "python", "Demo_Pkg", "demo-pkg", "python-pkg"),
            ("npm", "npm", "@team/demo", "%40team/demo", "node-pkg"),
        ):
            docs, trivy = documents(), documents(trivy=True)
            for side, idx in (("before", 0), ("after", 1)):
                version = "1.0" if idx == 0 else "1.1"
                url = f"pkg:{ecosystem}/{encoded}@{version}?source=synthetic"
                artifact = docs[idx]["matches"][0]["artifact"]
                artifact.update(name=name, type=kind, purl=url)
                docs[4][side]["grype"]["targets"][0]["type"] = target_type
                trivy[idx]["Results"][0]["Type"] = target_type
                vuln = trivy[idx]["Results"][0]["Vulnerabilities"][0]
                vuln["PkgName"], vuln["PkgIdentifier"]["PURL"] = name, url
                for inputs in (docs, trivy):
                    inputs[idx + 2]["components"][0].update(name=name, purl=url)
            self.assertEqual(compare(*docs)["summary"], compare(*trivy)["summary"])
            self.assertEqual(compare(*docs)["transitions"][0]["package"], compare(*trivy)["transitions"][0]["package"])

    def test_copies_duplicate_records_and_conflicting_artifact_ids(self):
        docs = documents()
        for side, idx in (("before", 0), ("after", 1)):
            second = deepcopy(docs[idx]["matches"][0])
            second["artifact"]["id"] += "-copy"
            second["artifact"]["locations"][0]["path"] = "/workspace/vendor/demo/package.json"
            docs[idx]["matches"].append(second)
            binding = deepcopy(docs[4][side]["grype"]["bindings"][0])
            binding.update(artifact_id=second["artifact"]["id"], package_path="vendor/demo",
                           location=second["artifact"]["locations"][0])
            docs[4][side]["grype"]["bindings"].append(binding)
            component = deepcopy(docs[idx + 2]["components"][0])
            component["bom-ref"] += "-copy"
            component["properties"][1]["value"] = "vendor/demo"
            docs[idx + 2]["components"].append(component)
        docs[0]["matches"].append(deepcopy(docs[0]["matches"][0]))
        docs[1]["matches"].pop()  # Only the vendor copy no longer reports the advisory.
        result = compare(*docs)
        self.assertEqual(result["summary"], {"fixed_within_snapshot": 1, "version_changed_still_affected": 1})
        self.assertEqual(result["accounting"]["before_records_accounted"], 3)
        docs[0]["matches"][-1]["artifact"]["locations"][0]["path"] = "/conflict"
        result = compare(*docs)
        self.assertEqual(len(result["unknown_findings"]["before"]), 2)
        self.assertIn("artifact_id_conflict", result["unknown_findings"]["before"][0]["reasons"])
        self.assertFalse(any(row["fixed"] for row in result["transitions"]))

    def test_grype_audit_inventory_contradiction_prevents_removal(self):
        docs = documents()
        docs[4]["aliases"] = {}
        docs[3]["components"] = []
        result = compare(*docs)
        self.assertEqual(result["summary"], {"introduced": 1, "no_longer_reported": 1})
        self.assertIn("report_inventory_conflict", result["transitions"][0]["reasons"])

    def test_related_advisories_and_fix_hints_are_not_inferred(self):
        docs = documents()
        docs[4]["aliases"] = {}
        docs[1]["matches"][0]["relatedVulnerabilities"] = [{"id": "CVE-SYNTH-001"}]
        docs[0]["matches"][0]["vulnerability"]["fix"] = {"versions": ["1.1"], "state": "fixed"}
        result = compare(*docs)
        self.assertEqual(result["summary"], {"fixed_within_snapshot": 1, "introduced": 1})
        docs[4]["after"]["database"] = {}
        self.assertEqual(compare(*docs)["summary"], {"no_longer_reported": 1, "introduced": 1})

    def test_mixed_scanners_match_observations_but_cannot_fix(self):
        docs, trivy = documents(), documents(trivy=True)
        docs[0], docs[4]["before"] = trivy[0], trivy[4]["before"]
        result = compare(*docs)
        self.assertEqual(result["summary"], {"version_changed_still_affected": 1})
        self.assertEqual(result["report_family"], "mixed")
        self.assertIn("scanner_identity_changed", result["comparability_reasons"])
        docs[1]["matches"] = []
        self.assertEqual(compare(*docs)["summary"], {"no_longer_reported": 1})

    def test_conflicting_native_database_and_configuration_prevent_fix(self):
        for field, old, new, reason in (
            ("db", {"checksum": "sha256:synthetic-A"}, {"checksum": "sha256:synthetic-B"},
             "grype_database_checksum_changed"),
            ("db", {"schemaVersion": 5}, {"schemaVersion": 6}, "grype_database_schema_changed"),
            ("configuration", {"only-fixed": False}, {"only-fixed": True}, "grype_configuration_changed"),
        ):
            docs = documents()
            docs[0]["descriptor"][field], docs[1]["descriptor"][field] = old, new
            docs[1]["matches"] = []
            with self.subTest(field=field):
                result = compare(*docs)
                self.assertEqual(result["summary"], {"no_longer_reported": 1})
                self.assertIn(reason, result["comparability_reasons"])

    def test_unsupported_versions_filters_and_invalid_bindings_fail_closed(self):
        for mutate in (
            lambda d: d[1]["descriptor"].update(version="0.86.2"),
            lambda d: d[4]["after"]["scanner"].update(version="0.86.2"),
            lambda d: d[1].update(ignoredMatches=[{}]),
            lambda d: d[1]["source"].update(type="image"),
            lambda d: d[1]["descriptor"].update(db={"error": "SECRET"}),
            lambda d: d[4]["after"]["grype"].update(adapter_version=True),
            lambda d: d[4]["after"]["grype"]["bindings"].append(deepcopy(d[4]["after"]["grype"]["bindings"][0])),
            lambda d: d[4]["after"]["grype"]["bindings"][0].update(target="undeclared"),
        ):
            docs = documents()
            mutate(docs)
            with self.subTest(mutate=mutate), self.assertRaises(InputError):
                compare(*docs)

    def test_malformed_required_shapes_fail_safely(self):
        paths = [("matches",), ("descriptor",), ("source",), ("matches", 0),
                 ("matches", 0, "vulnerability"), ("matches", 0, "artifact"),
                 ("matches", 0, "artifact", "id"), ("matches", 0, "artifact", "type"),
                 ("matches", 0, "artifact", "locations"),
                 ("matches", 0, "artifact", "locations", 0)]
        for path in paths:
            for value in (None, True, 2, {}):
                docs = documents()
                target = docs[1]
                for part in path[:-1]:
                    target = target[part]
                target[path[-1]] = value
                with self.subTest(path=path, value=value):
                    with self.assertRaises(InputError) as raised:
                        compare(*docs)
                    self.assertNotIn("SECRET", str(raised.exception))
