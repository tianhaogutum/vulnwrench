from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "delta"))
from corpus import basic, cases


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.paths = [self.folder / name for name in ("before.json", "after.json", "before-bom.json", "after-bom.json", "metadata.json")]
        self.docs = basic()
        self.save()

    def save(self):
        for path, document in zip(self.paths, self.docs):
            path.write_text(json.dumps(document), encoding="utf-8")

    def run_cli(self, *extra, mode="compare", stdout=None):
        command = [sys.executable, "-m", "vulnwrench", "delta", mode]
        for flag, path in zip(("--before", "--after", "--before-bom", "--after-bom", "--metadata"), self.paths):
            command.extend([flag, str(path)])
        streams = {"capture_output": True} if stdout is None else {"stdout": stdout, "stderr": subprocess.PIPE}
        return subprocess.run(command + list(extra), cwd=ROOT, text=True, timeout=60, **streams)

    def check_stdout_failures(self, large):
        self.docs[0]["Results"][0]["Vulnerabilities"] = []
        self.docs[4]["after"]["database"] = {}
        sentinel = "SYNTHETIC_OUTPUT_SECRET"
        if large:
            self.docs[1]["extension"] = sentinel * 1000
        self.save()
        policies = (((), 0), (("--fail-on", "introduced"), 1),
                    (("--fail-on-unknown",), 3),
                    (("--fail-on", "introduced", "--fail-on-unknown"), 3))
        for format in ("json", "markdown"):
            expected = self.run_cli("--format", format).stdout
            if not large:
                self.assertLess(len(expected.encode()), 8192, "exercise buffered flush failures")
            for flags, code in policies:
                with self.subTest(format=format, flags=flags):
                    success = self.run_cli(*flags, "--format", format)
                    self.assertEqual(success.returncode, code, success.stderr)
                    self.assertEqual(success.stdout, expected)
                    self.assertFalse(success.stderr)
                    # A closed pipe fails independently of buffering and /dev/full.
                    reader, writer = os.pipe()
                    os.close(reader)
                    try:
                        result = self.run_cli(*flags, "--format", format, stdout=writer)
                    finally:
                        os.close(writer)
                    self.assert_stdout_error(result, sentinel)
                    if Path("/dev/full").exists():
                        with open("/dev/full", "wb") as sink:
                            result = self.run_cli(*flags, "--format", format, stdout=sink)
                        self.assert_stdout_error(result, sentinel)

    def assert_stdout_error(self, result, sentinel):
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(result.stderr, "vulnwrench delta: input/output or JSON structure error (values omitted)\n")
        self.assertNotIn(sentinel, result.stderr)

    def test_buffered_stdout_errors_override_policy_exits(self):
        self.check_stdout_failures(large=False)

    def test_large_stdout_errors_override_policy_exits(self):
        self.check_stdout_failures(large=True)

    def test_stdout_json_and_gate_pass(self):
        result = self.run_cli("--fail-on", "introduced")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["summary"], {"persistent": 1})
        self.assertFalse(result.stderr)

    def test_introduced_gate_writes_output_then_returns_one(self):
        self.docs[0]["Results"][0]["Vulnerabilities"] = []
        self.save()
        output = self.folder / "matrix.json"
        result = self.run_cli("--fail-on", "introduced", "--output", str(output))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(json.loads(output.read_text())["summary"], {"introduced": 1})
        self.assertEqual(list(self.folder.glob(".vulnwrench-delta-*")), [])

    def test_unknown_gate_corpus_contract_and_unchanged_output(self):
        failing = {"changed-database", "missing-database", "missing-inventory-record",
                   "incomplete-inventory", "missing-target-coverage", "changed-profile"}
        for name, docs, _ in cases():
            with self.subTest(case=name):
                self.docs = docs
                self.save()
                ungated = self.run_cli()
                gated = self.run_cli("--fail-on-unknown")
                self.assertEqual(gated.returncode, 3 if name in failing else 0, gated.stderr)
                self.assertEqual(gated.stdout, ungated.stdout)
                self.assertFalse(gated.stderr)

    def test_unknown_gate_empty_reports_and_incomplete_metadata(self):
        for doc in self.docs[:2]:
            doc["Results"][0]["Vulnerabilities"] = []
            doc["extension"] = {"uninterpreted": True}
        self.save()
        result = self.run_cli("--fail-on-unknown")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["transitions"], [])
        for side in ("before", "after"):
            for change in ({"database": {}}, {"report_complete": False}, {"inventory_complete": False},
                           {"scanner": {"name": "trivy", "version": "different"}}):
                with self.subTest(side=side, change=change):
                    original = deepcopy(self.docs[4][side])
                    self.docs[4][side].update(change)
                    self.save()
                    result = self.run_cli("--fail-on-unknown")
                    self.assertEqual(result.returncode, 3, result.stderr)
                    self.assertEqual(json.loads(result.stdout)["transitions"], [])
                    self.docs[4][side] = original

    def test_unknown_gate_catches_scope_conflicts_on_observed_rows(self):
        for side, index in (("before", 2), ("after", 3)):
            for stale in (False, True):
                with self.subTest(side=side, stale=stale):
                    self.docs = basic()
                    if stale:
                        self.docs[index]["components"][0].update(version="stale", purl="pkg:npm/demo@stale")
                    else:
                        self.docs[index]["components"] = []
                    self.save()
                    result = self.run_cli("--fail-on-unknown")
                    self.assertEqual(result.returncode, 3, result.stderr)
                    matrix = json.loads(result.stdout)
                    self.assertTrue(matrix["comparable"])
                    self.assertEqual(matrix["summary"], {"persistent": 1})
                    self.assertIn("report_inventory_conflict", matrix["transitions"][0]["reasons"])

    def test_unknown_gate_both_policies_and_output_precedence(self):
        self.docs[0]["Results"][0]["Vulnerabilities"] = []
        self.save()
        flags = ("--fail-on", "introduced", "--fail-on-unknown")
        self.assertEqual(self.run_cli(*flags).returncode, 1)
        self.docs[4]["after"]["database"] = {}
        self.save()
        self.assertEqual(self.run_cli("--fail-on", "introduced").returncode, 1)
        for format in ("json", "markdown"):
            with self.subTest(format=format):
                output = self.folder / ("matrix." + format)
                output.write_text("previous output", encoding="utf-8")
                expected = self.run_cli("--format", format).stdout
                result = self.run_cli(*flags, "--format", format, "--output", str(output))
                self.assertEqual(result.returncode, 3, result.stderr)
                self.assertEqual(output.read_text(), expected)
                self.assertFalse(result.stdout + result.stderr)
                self.assertEqual(list(self.folder.glob(".vulnwrench-delta-*")), [])
        self.assertEqual(self.run_cli(*flags, "--output", str(self.folder / "missing/out.json")).returncode, 2)
        original = self.paths[0].read_bytes()
        self.assertEqual(self.run_cli(*flags, "--output", str(self.paths[0])).returncode, 2)
        self.assertEqual(self.paths[0].read_bytes(), original)

    def test_unknown_gate_unknown_grype_on_either_side_without_normalized_rows(self):
        for side in ("before", "after"):
            with self.subTest(side=side):
                self.docs = [json.loads((ROOT / "examples/delta/grype" / name).read_text())
                             for name in ("before.json", "after.json", "before-bom.json", "after-bom.json", "scans.json")]
                for index, label in enumerate(("before", "after")):
                    if label == side:
                        self.docs[index]["matches"][0]["artifact"]["locations"] = []
                    else:
                        self.docs[index]["matches"] = []
                self.save()
                ungated = self.run_cli()
                result = self.run_cli("--fail-on-unknown")
                self.assertEqual(ungated.returncode, 0, ungated.stderr)
                self.assertEqual(result.returncode, 3, result.stderr)
                self.assertEqual(result.stdout, ungated.stdout)
                matrix = json.loads(result.stdout)
                self.assertEqual(matrix["transitions"], [])
                self.assertEqual(len(matrix["unknown_findings"][side]), 1)
                self.assertEqual(matrix["accounting"][side + "_records_accounted"], 1)

    def test_unknown_gate_invalid_input_preserves_output(self):
        output = self.folder / "matrix.json"
        output.write_text("previous output", encoding="utf-8")
        self.paths[0].write_text('{"secret":"SYNTHETIC_SECRET",broken}', encoding="utf-8")
        result = self.run_cli("--fail-on-unknown", "--fail-on", "introduced", "--output", str(output))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(output.read_text(), "previous output")
        self.assertFalse(result.stdout)
        self.assertNotIn("SYNTHETIC_SECRET", result.stderr)

    def test_unknown_gate_is_compare_only(self):
        result = self.run_cli("--advisory", "CVE-SYNTH-001", "--fail-on-unknown", mode="explain")
        self.assertEqual(result.returncode, 2)
        self.assertFalse(result.stdout)

    def test_markdown_contains_matrix_and_retained_evidence(self):
        result = self.run_cli("--format", "markdown")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("| npm:demo |", result.stdout)
        self.assertIn("Full evidence and accounting", result.stdout)
        self.assertIn('"before_records"', result.stdout)

    def test_json_error_does_not_leak_values_or_write_output(self):
        sentinel = "SUPER_SECRET_SYNTHETIC_INPUT"
        self.paths[1].write_text('{"secret":"' + sentinel + '", broken}', encoding="utf-8")
        output = self.folder / "out.json"
        output.write_text("previous output", encoding="utf-8")
        result = self.run_cli("--output", str(output))
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(sentinel, result.stderr + result.stdout)
        self.assertEqual(output.read_text(), "previous output")
        self.assertNotIn("Traceback", result.stderr)

    def test_schema_error_redacts_values(self):
        self.docs[4]["after"]["database"] = "SUPER_SECRET_SYNTHETIC_INPUT"
        self.save()
        result = self.run_cli()
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("SUPER_SECRET", result.stderr)
        self.assertFalse(result.stdout)

    def test_missing_file_and_unwritable_output(self):
        self.paths[0].unlink()
        self.assertEqual(self.run_cli().returncode, 2)
        self.save()
        self.assertEqual(self.run_cli("--output", str(self.folder / "missing" / "out.json")).returncode, 2)

    def test_duplicate_keys_nan_and_invalid_utf8_rejected(self):
        for raw in (b'{"SchemaVersion":2,"SchemaVersion":2,"Results":[]}', b'{"x":NaN}', b'\xff'):
            with self.subTest(raw=raw):
                self.paths[0].write_bytes(raw)
                result = self.run_cli()
                self.assertEqual(result.returncode, 2)
                self.assertFalse(result.stdout)
                self.assertNotIn("Traceback", result.stderr)

    def test_overwrite_input_direct_symlink_and_hardlink_rejected(self):
        links = [self.paths[0], self.folder / "symlink.json", self.folder / "hardlink.json"]
        links[1].symlink_to(self.paths[0])
        os.link(self.paths[0], links[2])
        original = self.paths[0].read_bytes()
        for path in links:
            with self.subTest(path=path):
                self.assertEqual(self.run_cli("--output", str(path)).returncode, 2)
                self.assertEqual(self.paths[0].read_bytes(), original)

    def test_unsupported_family(self):
        self.docs[1] = {"matches": [], "descriptor": {"name": "grype"}}
        self.save()
        self.assertEqual(self.run_cli().returncode, 2)

    def test_help(self):
        for args in (("--help",), ("compare", "--help"), ("explain", "--help")):
            result = subprocess.run([sys.executable, "-m", "vulnwrench", "delta", *args], cwd=ROOT, capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0)
            self.assertIn("usage:", result.stdout)
            if args[0] == "compare":
                self.assertIn("--fail-on-unknown", result.stdout)
                self.assertIn("exit 3", result.stdout)

    def test_explain_unknown_json_markdown_and_batch_parity(self):
        cases = json.loads((ROOT / "examples/delta/explain/unknown-cases.json").read_text())
        for case in cases:
            self.docs = [json.loads((ROOT / "examples" / "delta" / path).read_text()) for path in case["inputs"]]
            self.save()
            batch = json.loads(self.run_cli().stdout)
            with self.subTest(case=case["name"]):
                result = self.run_cli("--advisory", case["advisory"], mode="explain")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(result.stderr)
                explained = json.loads(result.stdout)
                trace = explained.pop("explanation")
                self.assertEqual(explained, batch)
                self.assertEqual([dict(side=e["side"], unknown_index=e["unknown_index"], source=e["source"],
                                       reason_codes=[r["code"] for r in e["reasons"]],
                                       reason_sources={r["code"]: r["sources"] for r in e["reasons"]})
                                  for e in trace["unknown_findings"]], case["expected"]["unknown"])
                result = self.run_cli("--advisory", case["advisory"], "--format", "markdown", mode="explain")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(result.stderr)
                table, appendix = result.stdout.split("## Full evidence and accounting", 1)
                self.assertIn("## Selected unknown evidence", table)
                self.assertIn("| Side | Unknown index | Native advisory | Reason | Source pointers |", table)
                for entry in trace["unknown_findings"]:
                    self.assertIn(entry["source"], table)
                    for reason in entry["reasons"]:
                        self.assertIn(reason["code"], table)
                        for pointer in reason["sources"]:
                            self.assertIn(pointer, table)
                self.assertEqual(json.loads(appendix.split("```json\n", 1)[1].rsplit("```", 1)[0]),
                                 dict(batch, explanation=trace))

    def test_explain_unknown_safe_selector_errors_preserve_output(self):
        cases = json.loads((ROOT / "examples/delta/explain/unknown-cases.json").read_text())
        for case in (cases[0], *(c for c in cases if c["name"] in ("unknown-binding-type", "unknown-artifact-conflict-identity"))):
            self.docs = [json.loads((ROOT / "examples" / "delta" / path).read_text()) for path in case["inputs"]]
            self.save()
            output = self.folder / "existing.txt"
            for format in ("json", "markdown"):
                for selector in (None, "", "SYNTHETIC_SECRET_ABSENT", "CVE-SYNTH-001", "SYNTHETIC_SECRET_RELATED", "SYNTHETIC_SECRET_EXTENSION"):
                    output.write_text("previous output")
                    flags = [] if selector is None else ["--advisory", selector]
                    with self.subTest(case=case["name"], format=format, selector=selector):
                        result = self.run_cli(*flags, "--format", format, "--output", str(output), mode="explain")
                        self.assertEqual(result.returncode, 2, result.stderr)
                        self.assertFalse(result.stdout)
                        self.assertNotIn("SYNTHETIC_SECRET", result.stderr)
                        self.assertNotIn("Traceback", result.stderr)
                        self.assertEqual(output.read_text(), "previous output")
                        self.assertEqual(list(self.folder.glob(".vulnwrench-delta-*")), [])

    def test_explain_unknown_invalid_evidence_preserves_output(self):
        case = next(c for c in json.loads((ROOT / "examples/delta/explain/unknown-cases.json").read_text())
                    if c["name"] == "unknown-identity-absent-purl")
        output = self.folder / "existing.txt"
        for change in ("locations", "version", "name", "type", "artifact-version"):
            self.docs = [json.loads((ROOT / "examples" / "delta" / path).read_text()) for path in case["inputs"]]
            if change == "version":
                self.docs[1]["descriptor"]["version"] = "SYNTHETIC_SECRET_VERSION"
            else:
                del self.docs[1]["matches"][0]["artifact"]["version" if change == "artifact-version" else change]
            self.save()
            for format in ("json", "markdown"):
                with self.subTest(change=change, format=format):
                    output.write_text("previous output")
                    result = self.run_cli("--advisory", case["advisory"], "--format", format,
                                          "--output", str(output), mode="explain")
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertFalse(result.stdout)
                    self.assertNotIn("SYNTHETIC_SECRET", result.stderr)
                    self.assertNotIn("Traceback", result.stderr)
                    self.assertEqual(output.read_text(), "previous output")
                    self.assertEqual(list(self.folder.glob(".vulnwrench-delta-*")), [])

    def test_explain_unknown_invalid_binding_preserves_output(self):
        case = next(c for c in json.loads((ROOT / "examples/delta/explain/unknown-cases.json").read_text())
                    if c["name"] == "unknown-binding-type")
        for change in ("undeclared-target", "duplicate-id"):
            self.docs = [json.loads((ROOT / "examples" / "delta" / path).read_text()) for path in case["inputs"]]
            config = self.docs[4]["after"]["grype"]
            if change == "undeclared-target":
                config["bindings"][2]["target"] = "SYNTHETIC_SECRET_UNDECLARED"
            else:
                config["bindings"][0]["artifact_id"] = config["bindings"][2]["artifact_id"]
            self.save()
            output = self.folder / "existing.txt"
            for format in ("json", "markdown"):
                with self.subTest(change=change, format=format):
                    output.write_text("previous output")
                    result = self.run_cli("--advisory", case["advisory"], "--format", format,
                                          "--output", str(output), mode="explain")
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertFalse(result.stdout)
                    self.assertNotIn("SYNTHETIC_SECRET", result.stderr)
                    self.assertNotIn("Traceback", result.stderr)
                    self.assertEqual(output.read_text(), "previous output")
                    self.assertEqual(list(self.folder.glob(".vulnwrench-delta-*")), [])

    def test_explain_conflict_invalid_unselected_match_preserves_output(self):
        cases = json.loads((ROOT / "examples/delta/explain/unknown-cases.json").read_text())
        for case in (c for c in cases if "artifact-conflict" in c["name"]):
            side_index, peer_index = (0, 0) if case["name"].startswith("unknown") else (1, 1)
            for field in ("id", "locations", "vulnerability"):
                self.docs = [json.loads((ROOT / "examples" / "delta" / path).read_text()) for path in case["inputs"]]
                peer = self.docs[side_index]["matches"][peer_index]
                del (peer if field == "vulnerability" else peer["artifact"])[field]
                self.save()
                for format in ("json", "markdown"):
                    with self.subTest(case=case["name"], field=field, format=format):
                        output = self.folder / "existing.txt"
                        output.write_text("previous output")
                        result = self.run_cli("--advisory", case["advisory"], "--format", format,
                                              "--output", str(output), mode="explain")
                        self.assertEqual(result.returncode, 2, result.stderr)
                        self.assertFalse(result.stdout)
                        self.assertNotIn("SYNTHETIC_SECRET", result.stderr)
                        self.assertNotIn("Traceback", result.stderr)
                        self.assertEqual(output.read_text(), "previous output")
                        self.assertEqual(list(self.folder.glob(".vulnwrench-delta-*")), [])

    def test_explain_alias_and_batch_parity(self):
        self.docs[4]["aliases"] = {"ALIAS": ["CVE-SYNTH-001"]}
        self.save()
        batch = json.loads(self.run_cli().stdout)
        result = self.run_cli("--advisory", "ALIAS", mode="explain")
        self.assertEqual(result.returncode, 0, result.stderr)
        explained = json.loads(result.stdout)
        trace = explained.pop("explanation")["findings"][0]
        self.assertEqual(explained, batch)
        self.assertEqual(trace["decision"]["classification"], "persistent")
        self.assertIn("explicit_alias_equivalence", {r["code"] for r in trace["reasons"]})

    def test_explain_failure_preserves_output_and_redacts_selector(self):
        output = self.folder / "trace.json"
        output.write_text("previous output", encoding="utf-8")
        for extra in ([], ["--advisory", "SYNTHETIC_SECRET_UNKNOWN"], ["--advisory", ""]):
            result = self.run_cli(*extra, "--output", str(output), mode="explain")
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertFalse(result.stdout)
            self.assertNotIn("SYNTHETIC_SECRET", result.stderr)
            self.assertNotIn("Traceback", result.stderr)
            self.assertEqual(output.read_text(), "previous output")

    def test_explain_rejects_invalid_evidence_before_writing(self):
        self.docs[0]["SchemaVersion"] = 1
        self.save()
        output = self.folder / "trace.json"
        result = self.run_cli("--advisory", "CVE-SYNTH-001", "--output", str(output), mode="explain")
        self.assertEqual(result.returncode, 2)
        self.assertFalse(output.exists())

    def test_markdown_escapes_cells_and_uses_safe_fence(self):
        from vulnwrench.scandelta.cli import markdown
        from vulnwrench.scandelta import compare
        self.docs[0]["extension"] = "``````"
        row = compare(*self.docs)
        row["transitions"][0]["package"]["target"] = "<script>|danger"
        result = markdown(row)
        self.assertIn("&lt;script&gt;&#124;danger", result)
        self.assertIn("```````json", result)

    def test_input_size_limit(self):
        from vulnwrench.scandelta.cli import MAX_INPUT_BYTES
        self.paths[0].write_bytes(b" " * (MAX_INPUT_BYTES + 1))
        result = self.run_cli()
        self.assertEqual(result.returncode, 2)
        self.assertIn("20 MiB", result.stderr)
        self.assertFalse(result.stdout)
