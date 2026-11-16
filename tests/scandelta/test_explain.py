"""Explain must expose the batch decision, never reinterpret absence."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "delta"))
from corpus import basic, cases, report, vulnerability, bom
from vulnwrench.scandelta import InputError, compare
from .test_grype import documents as grype_documents


def resolve(documents, pointer):
    value = documents
    for token in pointer.lstrip("/").split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        value = value[int(token)] if isinstance(value, list) else value[token]
    return value


class ExplainTests(unittest.TestCase):
    def check_unknown_parity(self, docs, advisory):
        original = deepcopy(docs)
        batch = compare(*docs)
        explained = compare(*docs, explain_advisory=advisory)
        explanation = explained.pop("explanation")
        self.assertEqual(explained, batch)
        self.assertEqual(docs, original)
        documents = {k: v["document"] for k, v in batch["evidence"].items()}
        selected = [(side, index, entry) for side in ("before", "after")
                    for index, entry in enumerate(batch["unknown_findings"][side])
                    if entry["advisory"] == advisory]
        self.assertEqual(len(explanation["unknown_findings"]), len(selected))
        for entry, (side, index, unknown) in zip(explanation["unknown_findings"], selected):
            self.assertEqual(set(entry), {"side", "unknown_index", "advisory", "source", "reasons"})
            self.assertEqual((entry["side"], entry["unknown_index"], entry["advisory"], entry["source"]),
                             (side, index, advisory, unknown["source"]))
            self.assertEqual([r["code"] for r in entry["reasons"]], unknown["reasons"])
            native = resolve(documents, entry["source"])
            self.assertEqual(native["vulnerability"]["id"], advisory)
            for reason in entry["reasons"]:
                self.assertEqual(set(reason), {"code", "sources"})
                self.assertEqual(reason["sources"][0], entry["source"])
                for pointer in reason["sources"]:
                    resolve(documents, pointer)
        self.assertFalse(batch["comparable"])
        self.assertIn("report_identity_unknown", batch["comparability_reasons"])
        self.assertFalse(any(row["fixed"] or row["classification"] == "package_removed"
                             for row in batch["transitions"]))
        for side in ("before", "after"):
            self.assertEqual(batch["accounting"][side + "_findings"],
                             batch["accounting"][side + "_records_accounted"])
        return explanation

    def test_unknown_fixture_contracts(self):
        cases = json.loads((ROOT / "examples/delta/explain/unknown-cases.json").read_text())
        for case in cases:
            with self.subTest(case=case["name"]):
                docs = [json.loads((ROOT / "examples" / "delta" / path).read_text()) for path in case["inputs"]]
                explanation = self.check_unknown_parity(docs, case["advisory"])
                batch = compare(*docs)
                self.assertEqual([f["decision"]["classification"] for f in explanation["findings"]],
                                 case["expected"]["classifications"])
                for side in ("before", "after"):
                    self.assertEqual(batch["accounting"][side + "_findings"], case["expected"][side + "_findings"])
                self.assertEqual([dict(side=f["side"], unknown_index=f["unknown_index"], source=f["source"],
                                       reason_codes=[r["code"] for r in f["reasons"]],
                                       reason_sources={r["code"]: r["sources"] for r in f["reasons"]})
                                  for f in explanation["unknown_findings"]], case["expected"]["unknown"])
                self.check_parity(docs, case["advisory"])

    def test_unknown_locations_bindings_both_sides_and_duplicates(self):
        for side_index, side in enumerate(("before", "after")):
            for change in ("absent-location", "multiple-locations", "missing-binding", "location-mismatch", "layer"):
                with self.subTest(side=side, change=change):
                    docs = grype_documents()
                    match = docs[side_index]["matches"][0]
                    if change == "missing-binding":
                        docs[4][side]["grype"]["bindings"] = []
                    elif change == "absent-location":
                        match["artifact"]["locations"] = []
                    elif change == "location-mismatch":
                        match["artifact"]["locations"] = [{"path": "/other"}]
                    elif change == "layer":
                        match["artifact"]["locations"][0]["layerID"] = "synthetic-layer"
                        docs[4][side]["grype"]["bindings"][0]["location"]["layerID"] = "synthetic-layer"
                    else:
                        match["artifact"]["locations"].append({"path": "/other"})
                    docs[side_index]["matches"].append(deepcopy(match))
                    explanation = self.check_unknown_parity(docs, match["vulnerability"]["id"])
                    self.assertEqual(len(explanation["unknown_findings"]), 2)
                    for index, entry in enumerate(explanation["unknown_findings"]):
                        source = f"/{side}_report/matches/{index}"
                        reason, = entry["reasons"]
                        expected = {
                            "absent-location": [source, source + "/artifact/locations"],
                            "multiple-locations": [source, source + "/artifact/locations"],
                            "missing-binding": [source, source + "/artifact/id", f"/metadata/{side}/grype/bindings"],
                            "location-mismatch": [source, source + "/artifact/id", source + "/artifact/locations/0",
                                                  f"/metadata/{side}/grype/bindings/0/location"],
                            "layer": [source, source + "/artifact/locations/0"],
                        }
                        self.assertEqual(reason["sources"], expected[change])

    def test_unknown_binding_context_keeps_original_binding_index(self):
        for side_index, side in enumerate(("before", "after")):
            with self.subTest(side=side):
                docs = grype_documents()
                binding = deepcopy(docs[4][side]["grype"]["bindings"][0])
                binding["artifact_id"] = "unrelated-binding"
                docs[4][side]["grype"]["bindings"].insert(0, binding)
                docs[side_index]["matches"][0]["artifact"]["locations"] = [{"path": "/other"}]
                explanation = self.check_unknown_parity(docs, docs[side_index]["matches"][0]["vulnerability"]["id"])
                entry, = explanation["unknown_findings"]
                reason, = entry["reasons"]
                self.assertEqual(reason["sources"], [entry["source"], entry["source"] + "/artifact/id",
                                                     entry["source"] + "/artifact/locations/0",
                                                     f"/metadata/{side}/grype/bindings/1/location"])

    def test_unknown_combined_reasons_and_missing_location_field(self):
        docs = grype_documents()
        docs[0]["matches"] = []
        match = docs[1]["matches"][0]
        match["artifact"]["locations"] = []
        docs[4]["after"]["grype"]["bindings"] = []
        explanation = self.check_unknown_parity(docs, "GHSA-SYNTH-001")
        entry, = explanation["unknown_findings"]
        self.assertEqual(entry["reasons"], [
            dict(code="ambiguous_package_location", sources=[entry["source"], entry["source"] + "/artifact/locations"]),
            dict(code="scope_binding_missing", sources=[entry["source"], entry["source"] + "/artifact/id",
                                                       "/metadata/after/grype/bindings"]),
        ])
        del match["artifact"]["locations"]
        with self.assertRaises(InputError):
            compare(*docs, explain_advisory="GHSA-SYNTH-001")

    def test_unknown_identity_context_both_sides_and_duplicates(self):
        for side_index, side in enumerate(("before", "after")):
            for change in ("absent-purl", "null-purl", "empty-purl", "object-purl", "unsupported-purl",
                           "unsupported-type", "name", "version", "ecosystem"):
                with self.subTest(side=side, change=change):
                    docs = grype_documents()
                    artifact = docs[side_index]["matches"][0]["artifact"]
                    fields = ["purl"]
                    codes = ["package_identity_unsupported"]
                    if change == "absent-purl":
                        del artifact["purl"]
                        fields = [""]  # The existing artifact shows the missing key.
                    elif change.endswith("purl"):
                        artifact["purl"] = {"null-purl": None, "empty-purl": "", "object-purl": {},
                                            "unsupported-purl": "pkg:rpm/demo@1"}[change]
                    elif change == "unsupported-type":
                        artifact["type"] = "rpm"
                        codes = ["unsupported_package_type", "package_identity_disagrees"]
                    else:
                        if change == "ecosystem":
                            artifact["purl"] = "pkg:pypi/demo@" + artifact["version"]
                            # Keep target coverage consistent to isolate identity disagreement.
                            docs[4][side]["grype"]["targets"].append(dict(target="package-lock.json", type="python-pkg"))
                        else:
                            artifact[change] = "different"
                        codes = ["package_identity_disagrees"]
                    docs[side_index]["matches"].append(deepcopy(docs[side_index]["matches"][0]))
                    advisory = docs[side_index]["matches"][0]["vulnerability"]["id"]
                    explanation = self.check_unknown_parity(docs, advisory)
                    self.assertEqual(len(explanation["unknown_findings"]), 2)
                    for entry in explanation["unknown_findings"]:
                        source = entry["source"]
                        expected = {
                            "unsupported_package_type": [source, source + "/artifact/type"],
                            "package_identity_unsupported": [source] + [source + "/artifact" + ("/" + f if f else "") for f in fields],
                            "package_identity_disagrees": [source] + [source + "/artifact/" + f for f in ("type", "name", "version", "purl")],
                        }
                        self.assertEqual(entry["reasons"], [dict(code=c, sources=expected[c]) for c in codes])

    def test_unknown_binding_type_context_both_sides_and_combined_reasons(self):
        for side_index, side in enumerate(("before", "after")):
            for combined in (False, True):
                with self.subTest(side=side, combined=combined):
                    docs = grype_documents()
                    config = docs[4][side]["grype"]
                    # Matching ecosystem at a different target cannot satisfy this binding.
                    config["targets"] = [dict(target="unrelated.lock", type="node-pkg"),
                                         dict(target="package-lock.json", type="python-pkg")]
                    binding = config["bindings"][0]
                    config["bindings"] = [dict(binding, artifact_id="unused-0"),
                                          dict(binding, artifact_id="unused-1"), binding]
                    match = docs[side_index]["matches"][0]
                    if combined:
                        match["artifact"]["name"] = "different"
                        match["artifact"]["locations"][0]["path"] = "/different"
                    docs[side_index]["matches"].append(deepcopy(match))
                    explanation = self.check_unknown_parity(docs, match["vulnerability"]["id"])
                    self.assertEqual(len(explanation["unknown_findings"]), 2)
                    for index, entry in enumerate(explanation["unknown_findings"]):
                        self.assertEqual(entry["unknown_index"], index)
                        source = entry["source"]
                        codes = (["scope_binding_location_mismatch", "package_identity_disagrees"]
                                 if combined else []) + ["scope_binding_type_mismatch"]
                        self.assertEqual([r["code"] for r in entry["reasons"]], codes)
                        self.assertEqual(entry["reasons"][-1]["sources"], [
                            source, source + "/artifact/id", source + "/artifact/purl",
                            f"/metadata/{side}/grype/bindings/2/target", f"/metadata/{side}/grype/targets"])

    def test_binding_type_context_does_not_create_unknown_reasons(self):
        docs = grype_documents()
        docs[4]["after"]["grype"]["targets"].append(dict(target="package-lock.json", type="python-pkg"))
        explained = compare(*docs, explain_advisory="GHSA-SYNTH-001")
        self.assertFalse(explained["unknown_findings"]["after"])
        self.assertNotIn("unknown_findings", explained["explanation"])
        # A malformed PURL prevents an ecosystem comparison; do not invent a type mismatch.
        docs[1]["matches"][0]["artifact"]["purl"] = None
        docs[4]["after"]["grype"]["targets"] = [dict(target="package-lock.json", type="python-pkg")]
        explanation = self.check_unknown_parity(docs, "GHSA-SYNTH-001")
        self.assertEqual([r["code"] for r in explanation["unknown_findings"][0]["reasons"]],
                         ["package_identity_unsupported"])

    def test_artifact_conflict_context_both_sides_and_combined_reasons(self):
        for side_index, side in enumerate(("before", "after")):
            for change in ("identity", "extension", "combined"):
                with self.subTest(side=side, change=change):
                    docs = grype_documents()
                    selected = docs[side_index]["matches"][0]
                    peer = deepcopy(selected)
                    peer["vulnerability"]["id"] = "UNSELECTED-CONFLICT"
                    if change == "identity":
                        peer["artifact"].update(version="9", purl="pkg:npm/demo@9")
                    else:
                        peer["artifact"]["extension"] = {"retained": "different"}
                    if change == "combined":
                        selected["artifact"]["name"] = "disagrees"
                    unrelated = deepcopy(peer)
                    unrelated["artifact"]["id"] = "unrelated"
                    docs[side_index]["matches"] = [peer, unrelated, selected, deepcopy(selected)]
                    # Same ID but different artifact across scans is never conflict context.
                    other_side = "after" if side == "before" else "before"
                    docs[1 - side_index]["matches"][0]["artifact"]["id"] = selected["artifact"]["id"]
                    docs[4][other_side]["grype"]["bindings"][0]["artifact_id"] = selected["artifact"]["id"]
                    explanation = self.check_unknown_parity(docs, selected["vulnerability"]["id"])
                    for entry, native_index in zip(explanation["unknown_findings"], (2, 3)):
                        self.assertEqual(entry["source"], f"/{side}_report/matches/{native_index}")
                        self.assertEqual(entry["unknown_index"], native_index)
                        codes = ["artifact_id_conflict"] + (["package_identity_disagrees"] if change == "combined" else [])
                        self.assertEqual([r["code"] for r in entry["reasons"]], codes)
                        self.assertEqual(entry["reasons"][0]["sources"], [
                            entry["source"], entry["source"] + "/artifact/id",
                            f"/{side}_report/matches/0/artifact", f"/{side}_report/matches/2/artifact",
                            f"/{side}_report/matches/3/artifact",
                        ])
                    self.assertEqual(len(explanation["unknown_findings"]), 2)

    def test_artifact_conflict_negative_contracts(self):
        docs = grype_documents()
        # Same report-local ID, distinct versions across scans: valid normalized records.
        identity = docs[0]["matches"][0]["artifact"]["id"]
        docs[1]["matches"][0]["artifact"]["id"] = identity
        docs[4]["after"]["grype"]["bindings"][0]["artifact_id"] = identity
        duplicate = deepcopy(docs[1]["matches"][0])
        duplicate["artifact"] = dict(reversed(list(duplicate["artifact"].items())))
        duplicate["extension"] = {"match-only": "does not change artifact identity"}
        duplicate["vulnerability"]["id"] = "UNSELECTED"
        docs[1]["matches"].append(duplicate)
        batch = compare(*docs)
        self.assertEqual(batch["unknown_findings"], {"before": [], "after": []})
        self.assertTrue(batch["comparable"])
        self.check_parity(docs, "GHSA-SYNTH-001")
        # Even a selected unknown does not acquire a conflict from another report.
        docs[1]["matches"][0]["artifact"]["locations"] = []
        docs[1]["matches"].pop()
        explanation = self.check_unknown_parity(docs, "GHSA-SYNTH-001")
        self.assertEqual([r["code"] for r in explanation["unknown_findings"][0]["reasons"]],
                         ["ambiguous_package_location"])

    def test_artifact_conflict_exact_native_selection(self):
        cases = json.loads((ROOT / "examples/delta/explain/unknown-cases.json").read_text())
        for case in (c for c in cases if "artifact-conflict" in c["name"]):
            docs = [json.loads((ROOT / "examples" / "delta" / path).read_text()) for path in case["inputs"]]
            explanation = self.check_unknown_parity(docs, "UNSELECTED-CONFLICT")
            self.assertEqual(len(explanation["unknown_findings"]), 1)
            self.assertEqual(explanation["unknown_findings"][0]["unknown_index"], 0)
            for selector in ("SYNTHETIC_SECRET_RELATED", "SYNTHETIC_SECRET_EXTENSION"):
                with self.subTest(case=case["name"], selector=selector), self.assertRaises(InputError):
                    compare(*docs, explain_advisory=selector)
            if case["name"].startswith("unknown"):
                with self.assertRaises(InputError):
                    compare(*docs, explain_advisory="CVE-SYNTH-001")
            else:
                known = compare(*docs, explain_advisory="CVE-SYNTH-001")["explanation"]
                self.assertEqual(len(known["findings"]), 1)
                self.assertNotIn("unknown_findings", known)

    def test_required_identity_fields_remain_invalid(self):
        for field in ("name", "type", "version"):
            for absent, value in ((True, None), (False, None), (False, ""), (False, {})):
                with self.subTest(field=field, absent=absent, value=value):
                    docs = grype_documents()
                    artifact = docs[1]["matches"][0]["artifact"]
                    if absent:
                        del artifact[field]
                    else:
                        artifact[field] = value
                    with self.assertRaises(InputError):
                        compare(*docs, explain_advisory="GHSA-SYNTH-001")

    def test_unknown_selection_requires_exact_native_id(self):
        docs = grype_documents()
        docs[0]["matches"] = []
        docs[1]["matches"][0]["artifact"]["locations"] = []
        docs[1]["extension"] = {"id": "SYNTHETIC_SECRET_EXTENSION"}
        docs[1]["matches"][0]["relatedVulnerabilities"] = [{"id": "SYNTHETIC_SECRET_RELATED"}]
        for selector in ("CVE-SYNTH-001", "SYNTHETIC_SECRET_ABSENT", "SYNTHETIC_SECRET_EXTENSION",
                         "SYNTHETIC_SECRET_RELATED", "", [], 5):
            with self.subTest(selector=selector), self.assertRaises(InputError) as raised:
                compare(*docs, explain_advisory=selector)
            self.assertNotIn("SYNTHETIC_SECRET", str(raised.exception))

    def test_selected_unknown_indexes_skip_unselected_records(self):
        docs = grype_documents()
        docs[0]["matches"] = []
        match = docs[1]["matches"][0]
        match["artifact"]["locations"] = []
        other = deepcopy(match)
        other["vulnerability"]["id"] = "UNSELECTED"
        docs[1]["matches"].insert(0, other)
        explanation = self.check_unknown_parity(docs, "GHSA-SYNTH-001")
        entry, = explanation["unknown_findings"]
        self.assertEqual(entry["unknown_index"], 1)
        self.assertEqual(entry["source"], "/after_report/matches/1")

    def check_parity(self, docs, advisory):
        original = deepcopy(docs)
        batch = compare(*docs)
        explained = compare(*docs, explain_advisory=advisory)
        explanation = explained.pop("explanation")
        self.assertEqual(explained, batch)
        self.assertEqual(docs, original)
        self.assertEqual(explanation["requested_advisory"], advisory)
        expected_indexes = [i for i, row in enumerate(batch["transitions"]) if advisory in row["aliases"]]
        self.assertEqual([f["transition_index"] for f in explanation["findings"]], expected_indexes)
        if not any(entry["advisory"] == advisory for entries in batch.get("unknown_findings", {}).values()
                   for entry in entries):
            self.assertNotIn("unknown_findings", explanation)
        sources = {k: v["document"] for k, v in batch["evidence"].items()}
        for finding in explanation["findings"]:
            row = batch["transitions"][finding["transition_index"]]
            for key in ("classification", "resolution", "fixed"):
                self.assertEqual(finding["decision"][key], row[key])
            for entry in finding["reasons"] + finding["fix_prerequisites"] + [finding["decision"]]:
                self.assertTrue(entry["sources"])
                for pointer in entry["sources"]:
                    resolve(sources, pointer)
            satisfied = all(check["satisfied"] for check in finding["fix_prerequisites"])
            self.assertEqual(satisfied, row["fixed"])
        return explanation["findings"]

    def test_explicit_fixtures_and_source_references(self):
        fixtures = json.loads((ROOT / "examples/delta/explain/cases.json").read_text())
        for case in fixtures:
            docs = [json.loads((ROOT / "examples" / "delta" / p).read_text()) for p in case["inputs"]]
            with self.subTest(case=case["name"]):
                finding, = self.check_parity(docs, case["advisory"])
                expected = case["expected"]
                self.assertEqual(finding["decision"]["classification"], expected["classification"])
                codes = {r["code"] for r in finding["reasons"]}
                self.assertTrue(set(expected["reason_codes"]) <= codes)
                self.assertEqual({p["code"] for p in finding["fix_prerequisites"] if not p["satisfied"]},
                                 set(expected["failed_prerequisites"]))
                pointers = {p for item in finding["reasons"] + finding["fix_prerequisites"] for p in item["sources"]}
                self.assertTrue(set(expected["source_references"]) <= pointers)

    def test_all_labelled_decisions_match_batch(self):
        for name, docs, _ in cases():
            for row in compare(*docs)["transitions"]:
                with self.subTest(case=name, advisory=row["advisory"]):
                    self.check_parity(docs, row["advisory"])

    def test_scope_conflict_explanation_cites_other_advisory(self):
        docs = basic()
        docs[1] = report([vulnerability(version="2.0", advisory="OTHER")])
        docs[3] = bom([])
        finding, = self.check_parity(docs, "CVE-SYNTH-001")
        conflict = next(r for r in finding["reasons"] if r["code"] == "report_inventory_conflict")
        self.assertIn("/after_report/Results/0/Vulnerabilities/0", conflict["sources"])

    def test_coverage_and_completeness_block_fix(self):
        for flag in ("report_complete", "inventory_complete"):
            docs = basic()
            docs[1] = {"SchemaVersion": 2, "Results": []}
            docs[4]["after"][flag] = False
            finding, = self.check_parity(docs, "CVE-SYNTH-001")
            codes = {r["code"] for r in finding["reasons"]}
            self.assertIn("report_target_coverage_changed", codes)
            self.assertIn("incomplete_" + flag.split("_")[0], codes)

    def test_transitive_alias_and_escaped_pointer(self):
        docs = basic()
        docs[4]["aliases"] = {"A/~": ["B"], "B": ["CVE-SYNTH-001"], "UNRELATED": ["OTHER"]}
        docs[1]["Results"][0]["Vulnerabilities"][0]["VulnerabilityID"] = "A/~"
        finding, = self.check_parity(docs, "B")
        reason = next(r for r in finding["reasons"] if r["code"] == "explicit_alias_equivalence")
        self.assertEqual(reason["sources"], ["/metadata/aliases/A~1~0", "/metadata/aliases/B"])

    def test_grype_unknown_and_native_contradictions(self):
        docs = grype_documents()
        self.check_parity(docs, "GHSA-SYNTH-001")
        docs[1]["matches"][0]["artifact"]["locations"].append({"path": "/other"})
        finding, = self.check_parity(docs, "CVE-SYNTH-001")
        reason = next(r for r in finding["reasons"] if r["code"] == "report_identity_unknown")
        self.assertIn("/after_report/matches/0", reason["sources"])
        for field, before, after in (("db", {"checksum": "A"}, {"checksum": "B"}),
                                     ("configuration", {"a": True}, {"a": False})):
            docs = grype_documents()
            docs[1]["matches"] = []
            docs[0]["descriptor"][field], docs[1]["descriptor"][field] = before, after
            self.check_parity(docs, "CVE-SYNTH-001")

    def test_selection_preserves_copies_and_duplicate_records(self):
        docs = cases()[-1][1]
        docs[0]["Results"][0]["Vulnerabilities"].append(deepcopy(docs[0]["Results"][0]["Vulnerabilities"][0]))
        findings = self.check_parity(docs, "CVE-SYNTH-001")
        self.assertEqual(len(findings), 2)

    def test_unknown_or_invalid_selector_is_safe_error(self):
        for selector in ("SYNTHETIC_SECRET_UNKNOWN", "", [], 5):
            with self.subTest(selector=selector), self.assertRaises(InputError) as raised:
                compare(*basic(), explain_advisory=selector)
            self.assertNotIn("SYNTHETIC_SECRET", str(raised.exception))
