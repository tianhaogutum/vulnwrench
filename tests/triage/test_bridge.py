from __future__ import annotations

from copy import deepcopy
from datetime import date
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import patch

from vulnwrench.triage import (BridgeError, compile_decisions, load_document,
                           parse_decisions, write_compilation)
from vulnwrench.triage.model import JUSTIFICATIONS, decode_document, parse_purl
from tests.triage.schema_subset import validate_openvex

ROOT = Path(__file__).resolve().parents[2]
PARAMS = dict(as_of="2026-11-11", author="Synthetic Example Team", product_id="urn:example:demo-product:1.0",
              timestamp="2026-11-11T12:00:00Z", allow_scope_loss=True)


def fixture():
    return json.loads((ROOT / "examples/triage/decisions.json").read_text())


class ModelTests(unittest.TestCase):
    def assert_bad(self, doc, code="E_INPUT", **params):
        with self.assertRaises(BridgeError) as error:
            compile_decisions(doc, **(PARAMS | params))
        self.assertEqual(error.exception.code, code)
        return str(error.exception)

    def test_missing_fields(self):
        for field in ("owner", "reason", "package", "ids", "expiresOn", "status"):
            with self.subTest(field=field):
                doc = fixture()
                del doc["decisions"][0][field]
                self.assert_bad(doc)

    def test_unknown_fields_and_schema(self):
        for value in (2, "1", True, None):
            doc = fixture() | {"schemaVersion": value}
            self.assert_bad(doc)
        self.assert_bad(fixture() | {"secret-unknown-field": "secret-value"})
        doc = fixture()
        doc["decisions"][0]["unknown"] = {"future": "evidence"}
        self.assert_bad(doc)
        self.assert_bad({"decisions": []})
        self.assert_bad([])

    def test_text_validation(self):
        for field in ("owner", "reason"):
            for value in (None, 1, "", " ", " leading", "trailing ", "nul\x00", "bad\ud800"):
                with self.subTest(field=field, value=repr(value)):
                    doc = fixture()
                    doc["decisions"][0][field] = value
                    self.assert_bad(doc)

    def test_bad_dates(self):
        for value in ("2026-02-29", "2026-13-01", "2026-1-01", "20261111", 12, "2026-11-11T00:00:00Z"):
            doc = fixture()
            doc["decisions"][0]["expiresOn"] = value
            self.assert_bad(doc, "E_DATE")
        self.assert_bad(fixture(), "E_DATE", as_of="2026-02-30")

    def test_expiry_boundary(self):
        for expires, passes in (("2026-11-10", False), ("2026-11-11", False), ("2026-11-12", True)):
            doc = fixture()
            doc["decisions"][0]["expiresOn"] = expires
            if passes:
                compile_decisions(doc, **PARAMS)
            else:
                self.assert_bad(doc, "E_EXPIRED")

    def test_timestamp_profile(self):
        for value in ("2026-11-11", "2026-11-11T12:00:00", "2026-11-11T12:00:60Z",
                      "2026-11-11T12:00:00+00:99", "2026-11-12T12:00:00Z", "secret"):
            self.assert_bad(fixture(), "E_DATE", timestamp=value)
        result = compile_decisions(fixture(), **(PARAMS | {"timestamp": "2026-11-11T14:00:00+02:00"}))
        self.assertEqual(result.report["parameters"]["timestamp"], PARAMS["timestamp"])

    def test_explicit_metadata_required_and_valid(self):
        self.assert_bad(fixture(), author="")
        for value in ("relative/path", "https://example.test/a b", "urn:example:%ZZ"):
            self.assert_bad(fixture(), product_id=value)
        for key in ("author", "product_id", "timestamp", "as_of"):
            params = PARAMS.copy()
            del params[key]
            with self.assertRaises(TypeError):
                compile_decisions(fixture(), **params)

    def test_purl_profile(self):
        valid = ["pkg:npm/demo@1.0", "pkg:npm/%40example/demo@1.0", "pkg:pypi/demo-lib@1.2+local",
                 "pkg:deb/debian/demo@1:2.0-1?arch=amd64&distro=debian-12"]
        for purl in valid:
            self.assertEqual(parse_purl(purl), purl)
        invalid = ["demo", "pkg:npm/demo", "pkg:npm/demo@*", "pkg:npm/demo@%2A", "pkg:npm/demo@1#sub",
                   "pkg:npm/../demo@1", "pkg:npm/demo@1?z=a&a=b", "pkg:npm/demo@1?a=b&a=c",
                   "pkg:npm/demo@1?a=", "pkg:npm/demo@1?arch=amd64&", "pkg:npm/demo@1?arch=a/b",
                   "pkg:npm/%GG@1", "pkg:NPM/demo@1", "pkg:npm/demo@1%00", "pkg:npm/%FF@1"]
        for purl in invalid:
            with self.subTest(purl=purl), self.assertRaises(BridgeError):
                parse_purl(purl)

    def test_invalid_identifier(self):
        for ids in ([], ["*"], ["CVE-1", "CVE-1"], "CVE-1", ["has space"], ["secret\nvalue"]):
            doc = fixture()
            doc["decisions"][0]["ids"] = ids
            self.assert_bad(doc, "E_CONFLICT" if ids == ["CVE-1", "CVE-1"] else "E_INPUT")

    def test_alias_map_validation(self):
        for aliases in (["GHSA-1"], {"UNKNOWN": ["GHSA-1"]}, {"CVE-2025-0001": "GHSA-1"}):
            doc = fixture()
            doc["decisions"][0]["aliases"] = aliases
            self.assert_bad(doc)
        doc = fixture()
        doc["decisions"][0]["aliases"] = {"CVE-2025-0001": ["CVE-2025-0001"]}
        self.assert_bad(doc, "E_CONFLICT")

    def test_contradictory_and_duplicate_decisions(self):
        for status in ("under_investigation", "fixed", "accepted_risk"):
            doc = fixture()
            other = deepcopy(doc["decisions"][0])
            other["status"] = status
            doc["decisions"].append(other)
            self.assert_bad(doc, "E_CONFLICT")

    def test_alias_overlap_and_ambiguous_canonical_ids(self):
        doc = fixture()
        doc["decisions"][0]["aliases"] = {"CVE-2025-0001": ["GHSA-demo"]}
        other = deepcopy(doc["decisions"][0])
        other["package"] = "pkg:npm/other@1.0"
        other["ids"] = ["GHSA-demo"]
        other.pop("aliases")
        doc["decisions"].append(other)
        self.assert_bad(doc, "E_CONFLICT")

    def test_status_and_justification_errors(self):
        for status, extras in (("ignored", {}), ("accepted-risk", {}), ("not_affected", {}), ("affected", {}),
                               ("not_affected", {"justification": "risk_accepted"}),
                               ("fixed", {"justification": "component_not_present"}),
                               ("accepted_risk", {"action_statement": "secret"}),
                               ("under_investigation", {"impact_statement": "secret"})):
            doc = fixture()
            doc["decisions"][0].update(status=status, **extras)
            self.assert_bad(doc, "E_STATUS")

    def test_every_justification_and_impact_only(self):
        for extras in [dict(justification=j) for j in sorted(JUSTIFICATIONS)] + [dict(impact_statement="Synthetic reason")]:
            doc = fixture()
            doc["decisions"][0].update(status="not_affected", **extras)
            validate_openvex(json.loads(compile_decisions(doc, **PARAMS).files["openvex.json"]))

    def test_strict_json_decoding(self):
        for raw in (b'{"decisions": [], "decisions": []}', b'{"decisions": NaN}', b'{"value": Infinity}',
                    b'\xff', b'{bad', b'\xef\xbb\xbf{}', b'[' * 2000):
            with self.subTest(raw=raw[:25]), self.assertRaises(BridgeError):
                decode_document(raw)
        with self.assertRaises(BridgeError):
            decode_document(b" " * (2 * 1024 * 1024 + 1))

    def test_diagnostics_do_not_echo_values(self):
        doc = fixture()
        doc["decisions"][0]["status"] = "SUPER_SECRET_TOKEN"
        self.assertNotIn("SUPER_SECRET_TOKEN", self.assert_bad(doc, "E_STATUS"))


class ProjectionTests(unittest.TestCase):
    def test_default_scope_failure(self):
        with self.assertRaises(BridgeError) as error:
            compile_decisions(fixture(), **(PARAMS | {"allow_scope_loss": False}))
        self.assertEqual(error.exception.code, "E_SCOPE_LOSS")

    def test_real_format_field_mapping(self):
        result = compile_decisions(fixture(), **PARAMS)
        row = fixture()["decisions"][0]
        trivy = json.loads(result.files[".trivyignore.yaml"])["vulnerabilities"]
        self.assertEqual(trivy, [{"id": row["ids"][0], "purls": [row["package"]],
                                  "statement": row["reason"], "expired_at": row["expiresOn"]}])
        osv = tomllib.loads(result.files["osv-scanner.toml"].decode())["IgnoredVulns"]
        self.assertEqual(osv, [{"id": row["ids"][0], "reason": row["reason"], "effectiveUntil": date(2026, 12, 1)}])
        vex = json.loads(result.files["openvex.json"])
        validate_openvex(vex)
        statement = vex["statements"][0]
        self.assertEqual(statement["status"], row["status"])
        self.assertEqual(statement["products"], [{"@id": PARAMS["product_id"], "subcomponents": [{"@id": row["package"]}]}])
        self.assertEqual(vex["author"], PARAMS["author"])
        self.assertEqual(vex["timestamp"], PARAMS["timestamp"])

    def test_report_preserves_records_and_loss_provenance(self):
        result = compile_decisions(fixture(), **PARAMS)
        report = result.report
        self.assertEqual(report["decisions"][0]["record"], parse_decisions(fixture())[0].as_record())
        scope = next(loss for loss in report["losses"] if loss["code"] == "package_scope_widened")
        self.assertEqual(scope["decisionIndices"], [0])
        self.assertIn("expiry_not_enforced", {loss["code"] for loss in report["losses"]})
        for name, data in result.files.items():
            if name != "conversion-report.json":
                self.assertEqual(report["artifacts"][name]["sha256"], hashlib.sha256(data).hexdigest())

    def test_determinism_and_content_ids(self):
        result = compile_decisions(fixture(), **PARAMS)
        self.assertEqual(result.files, compile_decisions(fixture(), **PARAMS).files)
        vex = json.loads(result.files["openvex.json"])
        expected_id = vex.pop("@id")
        from vulnwrench.triage.compiler import json_bytes
        self.assertEqual(expected_id, "urn:sha256:" + hashlib.sha256(json_bytes(vex)).hexdigest())
        for field, value in (("author", "Other Team"), ("product_id", "urn:example:other"), ("timestamp", "2026-11-11T13:00:00Z")):
            changed = compile_decisions(fixture(), **(PARAMS | {field: value}))
            self.assertNotEqual(result.report["openvexId"], changed.report["openvexId"])
        doc = fixture()
        doc["decisions"][0]["owner"] = "other-owner"
        self.assertNotEqual(result.report["openvexId"], compile_decisions(doc, **PARAMS).report["openvexId"])

    def test_accepted_risk_never_becomes_vex(self):
        doc = fixture()
        doc["decisions"][0]["status"] = "accepted_risk"
        result = compile_decisions(doc, **PARAMS)
        self.assertNotIn("openvex.json", result.files)
        self.assertIsNone(result.report["openvexId"])
        self.assertEqual(result.report["counts"]["vexStatements"], 0)
        self.assertEqual(result.report["omittedArtifacts"][0]["file"], "openvex.json")
        self.assertIn("no_vex_assertion", {loss["code"] for loss in result.report["losses"]})

    def test_mixed_all_statuses_explicit_aliases_only(self):
        result = compile_decisions(load_document(ROOT / "examples/triage/mixed-decisions.json"), **PARAMS)
        self.assertEqual(result.report["counts"], {"decisions": 5, "trivyEntries": 6, "osvEntries": 6, "vexStatements": 4})
        vex = json.loads(result.files["openvex.json"])
        validate_openvex(vex)
        names = {s["vulnerability"]["name"] for s in vex["statements"]}
        self.assertNotIn("CVE-2025-0002", names)
        self.assertEqual({s["status"] for s in vex["statements"]}, {"under_investigation", "not_affected", "affected", "fixed"})
        aliases = [s["vulnerability"].get("aliases", []) for s in vex["statements"]]
        self.assertIn(["GHSA-demo-0001-0001"], aliases)

    def test_multiple_primary_ids_are_not_inferred_aliases(self):
        doc = fixture()
        doc["decisions"][0]["ids"].append("CVE-2025-0099")
        result = compile_decisions(doc, **PARAMS)
        statements = json.loads(result.files["openvex.json"])["statements"]
        self.assertEqual(len(statements), 2)
        self.assertTrue(all("aliases" not in s["vulnerability"] for s in statements))

    def test_global_coalescing_and_conflict(self):
        doc = fixture()
        other = deepcopy(doc["decisions"][0])
        other["package"] = "pkg:npm/other@2.0"
        doc["decisions"].append(other)
        result = compile_decisions(doc, **PARAMS)
        self.assertEqual(result.report["counts"]["osvEntries"], 1)
        self.assertEqual(result.report["counts"]["trivyEntries"], 2)
        self.assertIn("global_entries_coalesced", {loss["code"] for loss in result.report["losses"]})
        for field, value in (("reason", "Different reason"), ("expiresOn", "2026-12-31")):
            bad = deepcopy(doc)
            bad["decisions"][1][field] = value
            with self.assertRaises(BridgeError) as error:
                compile_decisions(bad, **PARAMS)
            self.assertEqual(error.exception.code, "E_CONFLICT")

    def test_unicode_and_string_escaping(self):
        doc = fixture()
        reason = 'Synthetic "quote", backslash \\, newline\n制品 😀\tend'
        doc["decisions"][0]["reason"] = reason
        result = compile_decisions(doc, **PARAMS)
        self.assertEqual(tomllib.loads(result.files["osv-scanner.toml"].decode())["IgnoredVulns"][0]["reason"], reason)
        self.assertEqual(json.loads(result.files[".trivyignore.yaml"])["vulnerabilities"][0]["statement"], reason)
        validate_openvex(json.loads(result.files["openvex.json"]))

    def test_official_schema_checker_rejects_invalid_vex(self):
        original = json.loads(compile_decisions(fixture(), **PARAMS).files["openvex.json"])
        variants = []
        for field in ("author", "timestamp", "@id"):
            doc = deepcopy(original)
            doc.pop(field)
            variants.append(doc)
        doc = deepcopy(original)
        doc["statements"] = []
        variants.append(doc)
        for status in ("not_affected", "affected", "accepted_risk"):
            doc = deepcopy(original)
            doc["statements"][0]["status"] = status
            variants.append(doc)
        doc = deepcopy(original)
        doc["unknown"] = 1
        variants.append(doc)
        for variant in variants:
            with self.assertRaises(AssertionError):
                validate_openvex(variant)


class OutputTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.result = compile_decisions(fixture(), **PARAMS)

    def test_new_output_and_existing_refusal(self):
        path = self.root / "out"
        write_compilation(self.result, path)
        self.assertEqual({p.name: p.read_bytes() for p in path.iterdir()}, self.result.files)
        with self.assertRaises(BridgeError):
            write_compilation(self.result, path)
        self.assertEqual({p.name: p.read_bytes() for p in path.iterdir()}, self.result.files)
        self.assertEqual(path.stat().st_mode & 0o777, 0o700)
        self.assertTrue(all((p.stat().st_mode & 0o777) == 0o600 for p in path.iterdir()))

    def test_traversal_and_missing_parent(self):
        for path in (self.root / ".." / "escape", self.root / "missing" / "out", Path("/"), Path(".")):
            with self.subTest(path=path), self.assertRaises(BridgeError):
                write_compilation(self.result, path)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_symlink_components_and_destination(self):
        target = self.root / "real"
        target.mkdir()
        link = self.root / "link"
        link.symlink_to(target, target_is_directory=True)
        for path in (link, link / "out"):
            with self.assertRaises(BridgeError):
                write_compilation(self.result, path)
        self.assertEqual(list(target.iterdir()), [])

    def test_output_file_collision_is_not_modified(self):
        path = self.root / "out"
        path.write_text("preserve")
        with self.assertRaises(BridgeError):
            write_compilation(self.result, path)
        self.assertEqual(path.read_text(), "preserve")

    def test_partial_io_failure_rolls_back_created_files(self):
        real_fdopen = os.fdopen
        calls = 0

        def fdopen(fd, *args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                os.close(fd)
                raise OSError("secret disk path")
            return real_fdopen(fd, *args, **kwargs)

        with patch("vulnwrench.triage.io.os.fdopen", side_effect=fdopen):
            with self.assertRaises(BridgeError) as error:
                write_compilation(self.result, self.root / "out")
        self.assertNotIn("secret", str(error.exception))
        self.assertFalse((self.root / "out").exists())

    def test_library_rejects_arbitrary_artifact_names(self):
        from vulnwrench.triage import Compilation
        with self.assertRaises(BridgeError):
            write_compilation(Compilation({"../escape": b"x", "conversion-report.json": b"{}"}), self.root / "out")

    def test_input_io_errors_are_redacted(self):
        with self.assertRaises(BridgeError) as error:
            load_document(self.root / "SECRET_PATH")
        self.assertNotIn("SECRET_PATH", str(error.exception))


class CLITests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, "-m", "vulnwrench", "triage", *args], cwd=ROOT,
                              capture_output=True, text=True, timeout=60)

    def args(self, input_path, output):
        return ["compile", str(input_path), "--as-of", PARAMS["as_of"], "--author", PARAMS["author"],
                "--product-id", PARAMS["product_id"], "--timestamp", PARAMS["timestamp"], "--out-dir", str(output)]

    def test_help_and_version(self):
        for args in (["--help"], ["compile", "--help"], ["--version"]):
            result = self.run_cli(*args)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_cli_scope_fail_then_real_formats(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "out"
            args = self.args(ROOT / "examples/triage/decisions.json", output)
            rejected = self.run_cli(*args)
            self.assertEqual(rejected.returncode, 2)
            self.assertIn("E_SCOPE_LOSS", rejected.stderr)
            self.assertFalse(output.exists())
            accepted = self.run_cli(*args, "--allow-scope-loss")
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertEqual(len(json.loads(accepted.stdout)["files"]), 4)
            tomllib.loads((output / "osv-scanner.toml").read_text())
            validate_openvex(json.loads((output / "openvex.json").read_text()))
            existing = self.run_cli(*args, "--allow-scope-loss")
            self.assertEqual(existing.returncode, 2)
            self.assertIn("E_OUTPUT", existing.stderr)

    def test_cli_invalid_json_and_expired(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, out = Path(tmp) / "input.json", Path(tmp) / "out"
            for raw, expected in (("{SECRET_INVALID_JSON", "E_INPUT"),
                                  (json.dumps(fixture()).replace("2026-12-01", "2026-11-11"), "E_EXPIRED")):
                path.write_text(raw)
                result = self.run_cli(*self.args(path, out), "--allow-scope-loss")
                self.assertEqual(result.returncode, 2)
                self.assertIn(expected, result.stderr)
                self.assertNotIn("SECRET", result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertFalse(out.exists())

    def test_cli_argument_errors_are_redacted(self):
        for args in (["SECRET_SUBCOMMAND"], ["--SECRET_FLAG"], ["compile", "SECRET_PATH"]):
            result = self.run_cli(*args)
            self.assertEqual(result.returncode, 2)
            self.assertNotIn("SECRET", result.stderr)
            self.assertIn("E_ARGUMENT", result.stderr)


if __name__ == "__main__":
    unittest.main()
