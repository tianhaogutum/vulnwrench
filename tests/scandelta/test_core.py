from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "delta"))
from corpus import basic, bom, cases, report, vulnerability
from compare_naive import naive
from vulnwrench.scandelta import InputError, compare
from vulnwrench.scandelta.core import canonical


class CoreTests(unittest.TestCase):
    def test_labelled_corpus(self):
        for name, docs, expected in cases():
            with self.subTest(case=name):
                result = compare(*docs)
                self.assertEqual({t["classification"] for t in result["transitions"]}, expected)
                self.assertEqual(result["accounting"]["before_findings"], result["accounting"]["before_records_accounted"])
                self.assertEqual(result["accounting"]["after_findings"], result["accounting"]["after_records_accounted"])

    def test_alias_rename_does_not_introduce_or_fix(self):
        docs = cases()[1][1]
        result = compare(*docs)
        self.assertEqual(result["summary"], {"persistent": 1})
        self.assertFalse(result["transitions"][0]["fixed"])
        self.assertEqual(naive(docs), ({"introduced", "fixed_within_snapshot"}, 1))

    def test_transitive_alias_cycle(self):
        docs = basic()
        docs[4]["aliases"] = {"A": ["B"], "B": ["C"], "C": ["A"]}
        docs[0]["Results"][0]["Vulnerabilities"][0]["VulnerabilityID"] = "C"
        docs[1]["Results"][0]["Vulnerabilities"][0]["VulnerabilityID"] = "B"
        row = compare(*docs)["transitions"][0]
        self.assertEqual(row["advisory"], "A")
        self.assertEqual(row["aliases"], ["A", "B", "C"])
        self.assertEqual(row["classification"], "persistent")

    def test_unmapped_ids_not_inferred_from_url(self):
        docs = basic()
        vuln = docs[1]["Results"][0]["Vulnerabilities"][0]
        vuln.update(VulnerabilityID="GHSA-UNKNOWN", PrimaryURL="https://example.invalid/CVE-SYNTH-001")
        self.assertEqual(compare(*docs)["summary"], {"fixed_within_snapshot": 1, "introduced": 1})

    def test_missing_db_or_changed_scanner_never_fixes(self):
        for field, value in (("database", {}), ("database", {"id": None}),
                             ("scanner", {"name": "trivy", "version": "9.0"}),
                             ("report_complete", False), ("inventory_complete", False)):
            docs = basic()
            docs[1] = report([])
            docs[4]["after"][field] = value
            row = compare(*docs)["transitions"][0]
            self.assertEqual(row["classification"], "no_longer_reported")
            self.assertFalse(row["fixed"])
            self.assertEqual(row["resolution"], "incomparable")

    def test_removal_is_inventory_evidence_even_with_changed_db(self):
        docs = cases()[4][1]
        docs[4]["after"]["database"] = {}
        row = compare(*docs)["transitions"][0]
        self.assertEqual(row["classification"], "package_removed")
        self.assertFalse(row["fixed"])

    def test_before_inventory_missing_prevents_removal_claim(self):
        docs = cases()[4][1]
        docs[2] = bom([])
        self.assertEqual(compare(*docs)["summary"], {"no_longer_reported": 1})

    def test_other_advisory_observes_scope_missing_from_after_inventory(self):
        for version in ("1.0", "2.0"):
            docs = basic()
            docs[1] = report([vulnerability(version=version, advisory="CVE-SYNTH-OTHER")])
            docs[3] = bom([])
            with self.subTest(version=version):
                rows = compare(*docs)["transitions"]
                old = next(row for row in rows if row["before_ids"])
                self.assertEqual(old["classification"], "no_longer_reported")
                self.assertEqual(old["resolution"], "unresolved")
                self.assertIn("report_inventory_conflict", old["reasons"])
                self.assertFalse(old["fixed"])

    def test_other_advisory_inventory_conflict_prevents_fix_in_same_scope(self):
        docs = basic()
        docs[1] = report([vulnerability(version="2.0", advisory="CVE-SYNTH-OTHER")])
        # A stale version is still present in the BOM, but cannot establish a fix.
        rows = compare(*docs)["transitions"]
        old = next(row for row in rows if row["before_ids"])
        self.assertEqual(old["classification"], "no_longer_reported")
        self.assertIn("report_inventory_conflict", old["reasons"])
        self.assertFalse(old["fixed"])

    def test_target_paths_are_distinct(self):
        docs = basic()
        second = deepcopy(docs[0]["Results"][0])
        second["Target"] = "other/package-lock.json"
        docs[0]["Results"].append(second)
        docs[1]["Results"].append(deepcopy(second))
        component = deepcopy(docs[2]["components"][0])
        component["bom-ref"] = "other"
        component["properties"][0]["value"] = "other/package-lock.json"
        for i in (2, 3):
            docs[i]["components"].append(deepcopy(component))
        self.assertEqual(compare(*docs)["summary"], {"persistent": 2})

    def test_different_qualifiers_are_not_same_package(self):
        docs = basic()
        docs[1]["Results"][0]["Vulnerabilities"][0]["PkgIdentifier"]["PURL"] += "?arch=arm64"
        docs[3]["components"][0]["purl"] += "?arch=arm64"
        self.assertEqual(compare(*docs)["summary"], {"introduced": 1, "package_removed": 1})

    def test_duplicates_accounted_and_unknown_evidence_retained(self):
        docs = basic()
        docs[0]["Results"][0]["Vulnerabilities"].append(deepcopy(docs[0]["Results"][0]["Vulnerabilities"][0]))
        docs[0]["future_extension"] = {"unknown": [42]}
        original = deepcopy(docs)
        result = compare(*docs)
        self.assertEqual(len(result["transitions"][0]["before_records"]), 2)
        self.assertEqual(result["accounting"]["before_findings"], 2)
        self.assertEqual(result["evidence"]["before_report"]["document"], docs[0])
        self.assertEqual(result["evidence"]["before_report"]["sha256"], hashlib.sha256(canonical(docs[0]).encode()).hexdigest())
        self.assertEqual(docs, original)
        self.assertEqual(result, compare(*docs))

    def test_all_source_pointers_resolve(self):
        result = compare(*cases()[-1][1])
        documents = {key: value["document"] for key, value in result["evidence"].items()}
        for row in result["transitions"]:
            for field in ("before_records", "after_records", "before_inventory_records", "after_inventory_records"):
                for pointer in row[field]:
                    value = documents
                    for part in pointer.lstrip("/").split("/"):
                        value = value[int(part)] if isinstance(value, list) else value[part]
                    if field.endswith("inventory_records"):
                        self.assertEqual(value["name"], row["package"]["name"])
                    else:
                        self.assertIn(value["VulnerabilityID"], row["before_ids"] + row["after_ids"])

    def test_nested_components_and_cdx_versions(self):
        for version in ("1.4", "1.5", "1.6"):
            docs = basic()
            for i in (2, 3):
                docs[i]["specVersion"] = version
                parent = deepcopy(docs[i]["components"][0])
                parent.update(name="parent", purl="pkg:npm/parent@1.0", **{"bom-ref": "parent"})
                parent["components"] = docs[i]["components"]
                docs[i]["components"] = [parent]
            self.assertEqual(compare(*docs)["summary"], {"persistent": 1})

    def test_pypi_normalization(self):
        docs = basic()
        for i in (0, 1):
            result = docs[i]["Results"][0]
            result["Type"] = "python-pkg"
            vuln = result["Vulnerabilities"][0]
            vuln["PkgName"] = "Demo_Pkg"
            vuln["PkgIdentifier"]["PURL"] = "pkg:pypi/demo-pkg@1.0"
        for i in (2, 3):
            docs[i]["components"][0].update(name="demo.pkg", purl="pkg:pypi/demo-pkg@1.0")
        self.assertEqual(compare(*docs)["summary"], {"persistent": 1})

    def test_scoped_npm_name(self):
        docs = basic()
        for i in (0, 1):
            vuln = docs[i]["Results"][0]["Vulnerabilities"][0]
            vuln["PkgName"] = "@team/demo"
            vuln["PkgIdentifier"]["PURL"] = "pkg:npm/%40team/demo@1.0"
        for i in (2, 3):
            docs[i]["components"][0].update(name="demo", group="@team", purl="pkg:npm/%40team/demo@1.0")
        self.assertEqual(compare(*docs)["summary"], {"persistent": 1})

    def test_null_vulnerabilities_supported(self):
        docs = basic()
        docs[1]["Results"][0]["Vulnerabilities"] = None
        self.assertEqual(compare(*docs)["summary"], {"fixed_within_snapshot": 1})

    def test_invalid_manifest_and_reports_fail_closed(self):
        mutations = [
            (0, lambda x: x.update(SchemaVersion=1)),
            (1, lambda x: (x.clear(), x.update(matches=[]))),
            (4, lambda x: x.update(schema_version=True)),
            (4, lambda x: x["after"].update(database="secret")),
            (4, lambda x: x["after"].update(report_complete="yes")),
            (4, lambda x: x["after"].update(unknown=True)),
            (4, lambda x: x.update(aliases={"A": "B"})),
            (4, lambda x: x["before"]["scanner"].update(name="grype")),
            (2, lambda x: x.update(specVersion=[])),
            (2, lambda x: x["components"][0].update(type="application")),
            (2, lambda x: x["components"][0].update(properties=[])),
            (2, lambda x: x["components"].append(deepcopy(x["components"][0]))),
            (0, lambda x: x["Results"][0].update(Type="debian")),
            (0, lambda x: x["Results"][0].update(Secrets=[{"x": "secret"}])),
            (0, lambda x: x["Results"][0].update(Errors=["secret"])),
            (0, lambda x: x["Results"][0]["Vulnerabilities"][0].update(InstalledVersion="different")),
            (0, lambda x: x["Results"][0]["Vulnerabilities"][0].update(PkgIdentifier={})),
        ]
        for index, mutation in mutations:
            docs = basic()
            mutation(docs[index])
            with self.subTest(index=index, mutation=mutation), self.assertRaises(InputError):
                compare(*docs)

    def test_invalid_purls(self):
        for value in ("pkg:cargo/demo@1", "pkg:npm/demo", "pkg:npm/demo@1#path", "pkg:npm/%GG@1", "pkg:npm/demo@1?a=x&a=y", "pkg:npm/demo@1?A=x", "pkg:npm/demo@1?a=%FF"):
            docs = basic()
            docs[0]["Results"][0]["Vulnerabilities"][0]["PkgIdentifier"]["PURL"] = value
            with self.subTest(value=value), self.assertRaises(InputError):
                compare(*docs)

    def test_malformed_field_types_raise_safe_input_error(self):
        # Mutate each required shape independently; no unhandled Python type errors.
        locations = [
            (0, ("SchemaVersion",)), (0, ("Results",)),
            (0, ("Results", 0, "Target")), (0, ("Results", 0, "Type")),
            (0, ("Results", 0, "Class")),
            (0, ("Results", 0, "Vulnerabilities", 0, "PkgIdentifier")),
            (0, ("Results", 0, "Vulnerabilities", 0, "VulnerabilityID")),
            (2, ("bomFormat",)), (2, ("specVersion",)), (2, ("components",)),
            (2, ("components", 0, "purl")), (2, ("components", 0, "bom-ref")),
            (2, ("components", 0, "properties")),
            (4, ("before",)), (4, ("after", "scanner")),
            (4, ("after", "scanner", "version")), (4, ("after", "profile")),
            (4, ("after", "report_complete")), (4, ("aliases",)),
        ]
        wrong = {"SchemaVersion": [None, True, {}, [], "2"],
                 "Results": [None, True, {}, 2, ""], "components": [None, True, {}, 2, ""],
                 "properties": [None, True, {}, 2, ""], "report_complete": [None, 1, {}, [], "true"],
                 "aliases": [None, True, [], 2, ""]}
        for index, path in locations:
            for value in wrong.get(path[-1], [None, True, {}, [], 2]):
                docs = basic()
                current = docs[index]
                for part in path[:-1]:
                    current = current[part]
                current[path[-1]] = value
                with self.subTest(path=path, value=value), self.assertRaises(InputError):
                    compare(*docs)
