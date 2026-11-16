"""Markdown is a view of the complete validated renewal plan, never policy."""
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

from vulnwrench.triage import (compile_decisions, preview_renewal, verify_report_source,
                           write_compilation)
from vulnwrench.triage.cli import main
from vulnwrench.triage.compiler import json_bytes
from vulnwrench.triage.model import MAX_INPUT_BYTES
from vulnwrench.triage.renewal_markdown import render_renewal_markdown

from tests.triage.test_bridge import ROOT
from tests.triage.test_renewal_inputs import arguments
from tests.triage.test_renewal import fixture
from tests.triage.test_source_verification import ARCHIVED
import tempfile


def appendix(markdown):
    section = markdown.split("## Full plan (JSON)\n", 1)[1]
    start = re.search(r"^`{3,}json$", section, re.MULTILINE).start()
    block = section[start:].strip().splitlines()
    fence = block[0].removesuffix("json")
    assert block[-1] == fence
    return json.loads("\n".join(block[1:-1]))


class RenewalMarkdownTests(unittest.TestCase):
    def cli(self, args):
        return subprocess.run([sys.executable, "-m", "vulnwrench", "triage", *map(str, args)],
                              cwd=ROOT, capture_output=True, timeout=60)

    def test_markdown_is_complete_and_gate_matches_json(self):
        args = arguments(current=ROOT / "examples/triage/renewal/current.json")
        ordinary = self.cli(args)
        explicit = self.cli([*args, "--format", "json"])
        expected = (ROOT / "examples/triage/renewal/expected-plan.json").read_bytes()
        self.assertEqual(ordinary.returncode, 0, ordinary.stderr)
        self.assertEqual(ordinary.stdout, expected)
        self.assertEqual(explicit.returncode, 0, explicit.stderr)
        self.assertEqual(explicit.stdout, expected)
        rendered = self.cli([*args, "--format", "markdown"])
        gated = self.cli([*args, "--format", "markdown", "--fail-on-review"])
        self.assertEqual(rendered.returncode, 0, rendered.stderr)
        self.assertEqual(gated.returncode, 1, gated.stderr)
        self.assertEqual(rendered.stderr, b"")
        self.assertEqual(gated.stderr, b"")
        self.assertEqual(rendered.stdout, gated.stdout)
        markdown = rendered.stdout.decode()
        self.assertTrue(markdown.startswith("# Renewal review plan\n"))
        self.assertEqual(appendix(markdown), json.loads(expected))
        self.assertIn("Prior expiry", markdown)
        self.assertIn("Current expiry", markdown)
        self.assertIn("| automaticActions | `[]` |", markdown)

    def assert_view(self, plan):
        before = deepcopy(plan)
        markdown = render_renewal_markdown(plan)
        self.assertEqual(plan, before)
        self.assertEqual(appendix(markdown), plan)
        self.assertEqual(render_renewal_markdown(plan), markdown)
        summary = markdown.split("## Decisions\n", 1)[1].split("## Source evidence", 1)[0]
        rows = [line.split(" | ") for line in summary.splitlines() if line.startswith("| `")]
        self.assertEqual(len(rows), plan["counts"]["decisions"])
        for row, entry in zip(rows, plan["decisions"]):
            self.assertEqual(row[0], "| `" + entry["decisionId"] + "`")
            self.assertEqual(row[3], ", ".join("`" + s + "`" for s in entry["statuses"]))
            self.assertEqual(row[4], ", ".join("`" + a + "`" for a in entry["actions"]) or "`[]`")
            for index, side, status in ((1, "prior", "expiryStatus"), (2, "current", "currentExpiryStatus")):
                expected = (entry[side]["record"]["expiresOn"] + " (" + entry[status] + ")"
                            if entry[side] is not None else "absent")
                self.assertEqual(row[index], "`" + expected + "`")
        return markdown

    def test_all_accumulated_reasons_expiry_sides_and_empty_actions(self):
        prior = fixture()
        current = deepcopy(prior)
        current["decisions"][0].update(expiresOn="2027-01-01", owner=None,
            package="pkg:npm/changed@2", reason="Changed policy", sourceRefs=["urn:changed"])
        current["decisions"][2]["expiresOn"] = "2026-11-11"
        current["decisions"][3]["expiresOn"] = "2026-11-18"
        current["decisions"][4].update(decisionId="new-exception", ids=["NEW-ID"])
        plan = preview_renewal(prior, current=current, prior_as_of="2026-11-01",
                               as_of="2026-11-11", expiring_within_days=7)
        self.assertEqual(plan["decisions"][0]["statuses"], ["expired", "owner_missing",
            "scope_changed", "policy_changed", "source_refs_changed"])
        statuses = {s for entry in plan["decisions"] for s in entry["statuses"]}
        self.assertEqual(statuses, {"expired", "expiring_soon", "owner_missing", "scope_changed",
            "policy_changed", "source_refs_changed", "current_expired", "current_expiring_soon",
            "added", "removed", "unchanged"})
        self.assert_view(plan)
        changed_owner = deepcopy(prior)
        changed_owner["decisions"][0]["owner"] = "new-team"
        owner_plan = preview_renewal(prior, current=changed_owner, prior_as_of="2026-11-01", as_of="2026-11-11")
        self.assertIn("owner_changed", owner_plan["decisions"][0]["statuses"])
        self.assert_view(owner_plan)

    def test_reordered_active_records_have_no_findings_and_gate_zero(self):
        prior = {"decisions": fixture()["decisions"][-2:]}
        current = {"decisions": list(reversed(prior["decisions"]))}
        with tempfile.TemporaryDirectory() as tmp:
            p, c = Path(tmp) / "prior", Path(tmp) / "current"
            p.write_bytes(json_bytes(prior))
            c.write_bytes(json_bytes(current))
            for candidate in (None, c):
                args = arguments(p, candidate)
                result = self.cli([*args, "--format", "markdown", "--fail-on-review"])
                self.assertEqual(result.returncode, 0, result.stderr)
                plan = appendix(result.stdout.decode())
                self.assertEqual(plan["counts"]["reviewRequired"], 0)
                self.assertEqual([e["statuses"] for e in plan["decisions"]], [["unchanged"], ["unchanged"]])
                self.assertEqual([e["actions"] for e in plan["decisions"]], [[], []])
                self.assertEqual(result.stdout.decode(), self.assert_view(plan))

    def test_opaque_text_unicode_controls_and_fence_injection_stay_inert(self):
        prior = {"decisions": [fixture()["decisions"][-1]]}
        text = 'café 雪 🐈 | ` ``` `````` <script> [click](https://example.invalid)\n# heading\tend\u202e\u2066\u0085\u2028\u2029 literal\\u007c'
        prior["decisions"][0].update(owner=text, reason=text,
            sourceRefs=[text, "https://example.invalid/path", "www.example.invalid"])
        plan = preview_renewal(prior, prior_as_of="2026-11-01", as_of="2026-11-11")
        markdown = self.assert_view(plan)
        body, raw = markdown.split("## Full plan (JSON)\n", 1)
        self.assertIn("café 雪 🐈", body)
        self.assertIn(r"\u007c \u0060 \u0060\u0060\u0060", body)
        self.assertIn(r"\u003cscript\u003e", body)
        self.assertIn(r"\n# heading\tend\u202e\u2066\u0085\u2028\u2029", body)
        self.assertIn(r"literal\\u007c", body)
        self.assertIn('`["', body)  # Opaque references remain inside a code span.
        for control in ("\t", "\u202e", "\u2066", "\u0085", "\u2028", "\u2029"):
            self.assertNotIn(control, markdown)
        self.assertNotIn("<script>", body)
        self.assertNotIn("\n# heading", body)
        self.assertIn("```````json\n", raw)
        self.assertIn("not redacted", raw)
        for line in body.splitlines():
            if line.startswith("| "):
                self.assertIn(line.count("|"), (3, 5, 7))

    def test_report_verification_combinations_archived_indices_and_no_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            prior = fixture()
            compiled = compile_decisions(prior, **ARCHIVED)
            bundle = root / "bundle"
            write_compilation(compiled, bundle)
            report = deepcopy(compiled.report)
            report["decisions"].reverse()
            p, source, c = root / "report", root / "source", root / "current"
            p.write_bytes(json_bytes(report))
            source.write_bytes(json_bytes(prior))
            current = deepcopy(prior)
            current["decisions"][0]["expiresOn"] = "2027-01-01"
            current["decisions"].reverse()
            c.write_bytes(json_bytes(current))
            before = {f: (f.read_bytes(), f.stat().st_mode) for f in root.rglob("*") if f.is_file()}
            entries = set(root.rglob("*"))
            for candidate in (None, c):
                for check_source, check_artifacts in ((False, False), (True, False), (False, True), (True, True)):
                    args = arguments(p, candidate, report=True)
                    if check_source:
                        args += ["--verify-source", str(source)]
                    if check_artifacts:
                        args += ["--verify-artifacts", str(bundle)]
                    js = self.cli([*args, "--fail-on-review"])
                    md = self.cli([*args, "--format", "markdown", "--fail-on-review"])
                    self.assertEqual(js.returncode, 1, js.stderr)
                    self.assertEqual(md.returncode, js.returncode, md.stderr)
                    plan = json.loads(js.stdout)
                    self.assertEqual(appendix(md.stdout.decode()), plan)
                    body = md.stdout.decode().split("## Full plan (JSON)", 1)[0]
                    self.assertEqual("sourceVerification" in plan, check_source)
                    self.assertEqual("artifactVerification" in plan, check_artifacts)
                    for pos, entry in enumerate(plan["decisions"]):
                        evidence = entry["prior"]["source"]
                        self.assertEqual(evidence["decisionIndex"], 5 - pos)
                        for key, value in evidence.items():
                            self.assertIn(f"| prior | {key} | `{value}` |", body)
                    self.assertIn("expired", plan["decisions"][-1]["statuses"])
            self.assertEqual({f: (f.read_bytes(), f.stat().st_mode) for f in before}, before)
            self.assertEqual(set(root.rglob("*")), entries)

    def assert_invalid(self, args, code):
        for gate in ([], ["--fail-on-review"]):
            result = self.cli([*args, "--format", "markdown", *gate])
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(result.stdout, b"")
            self.assertIn(code.encode(), result.stderr)
            self.assertNotIn(b"SECRET", result.stderr)
            self.assertNotIn(b"Traceback", result.stderr)

    def test_invalid_files_semantics_and_format_emit_no_partial_markdown(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "SECRET-input"
            for raw in (b'null', b'\xffSECRET', b'{"SECRET":1,"SECRET":2}', b'{"SECRET":NaN}',
                        b' ' * (MAX_INPUT_BYTES + 1)):
                p.write_bytes(raw)
                self.assert_invalid(arguments(p), "E_INPUT")
                self.assert_invalid(arguments(current=p), "E_INPUT")
            bad = fixture()
            bad["decisions"][-1]["decisionId"] = bad["decisions"][0]["decisionId"]
            p.write_bytes(json_bytes(bad))
            self.assert_invalid(arguments(p), "E_CONFLICT")
            report = compile_decisions(fixture(), **ARCHIVED).report
            report["warnings"].append("SECRET")
            p.write_bytes(json_bytes(report))
            self.assert_invalid(arguments(p, report=True), "E_REPORT")
            self.assert_invalid(arguments() + ["--as-of", "SECRET"], "E_DATE")
            self.assert_invalid(arguments() + ["--verify-source", str(p)], "E_ARGUMENT")
            for raw, code in ((b'{}', "E_SOURCE"), (b'\xffSECRET', "E_INPUT")):
                p.write_bytes(raw)
                self.assert_invalid(arguments(report=True) + ["--verify-source", str(p)], code)
            self.assert_invalid(arguments(report=True) + ["--verify-artifacts", str(p)], "E_ARTIFACT")
            p.unlink()
            self.assert_invalid(arguments(p), "E_IO")
            invalid_format = self.cli(arguments(p) + ["--format", "SECRET"])
            self.assertEqual(invalid_format.returncode, 2)
            self.assertEqual(invalid_format.stdout, b"")
            self.assertIn(b"E_ARGUMENT", invalid_format.stderr)
            self.assertNotIn(b"SECRET", invalid_format.stderr)

    def test_regular_symlinks_and_nonblocking_fifo_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            link = root / "prior-link"
            link.symlink_to(ROOT / "examples/triage/renewal/prior.json")
            actual = self.cli(arguments(link) + ["--format", "markdown"])
            expected = self.cli(arguments() + ["--format", "markdown"])
            self.assertEqual(actual.returncode, 0, actual.stderr)
            self.assertEqual(actual.stdout, expected.stdout)
            fifo = root / "SECRET-fifo"
            os.mkfifo(fifo)
            for held in (False, True):
                peer = os.open(fifo, os.O_RDWR | os.O_NONBLOCK) if held else None
                try:
                    self.assert_invalid(arguments(fifo), "E_IO")
                    self.assert_invalid(arguments(current=fifo), "E_IO")
                    self.assert_invalid(arguments(report=True) + ["--verify-source", str(fifo)], "E_IO")
                finally:
                    if peer is not None:
                        os.close(peer)

    def test_renderer_uses_one_plan_after_checks_and_stream_errors_precede_gate(self):
        args = arguments(report=True) + ["--verify-source", str(ROOT / "examples/triage/renewal/prior.json"),
                                        "--verify-artifacts", "unused", "--format", "markdown", "--fail-on-review"]
        events = []
        def capture(name, function):
            def run(*a, **kw):
                events.append(name)
                return function(*a, **kw)
            return run
        # Artifact I/O itself is covered above; this isolates CLI single-call order.
        artifact_result = {"status": "verified", "artifacts": []}
        with patch("vulnwrench.triage.cli.preview_renewal", side_effect=capture("plan", preview_renewal)) as plan_call, \
             patch("vulnwrench.triage.cli.verify_report_source", side_effect=capture("source", verify_report_source)) as source_call, \
             patch("vulnwrench.triage.cli.verify_report_artifacts", side_effect=capture("artifacts", lambda *a: artifact_result)) as artifacts_call, \
             patch("vulnwrench.triage.cli.render_renewal_markdown", side_effect=capture("render", render_renewal_markdown)) as render_call, \
             redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(main(args), 1)
        self.assertEqual(events, ["plan", "source", "artifacts", "render"])
        for operation in (plan_call, source_call, artifacts_call, render_call):
            self.assertEqual(operation.call_count, 1)
        plan = render_call.call_args.args[0]
        self.assertEqual(appendix(stdout.getvalue()), plan)
        self.assertIn("sourceVerification", plan)
        self.assertEqual(plan["artifactVerification"], artifact_result)
        args = arguments() + ["--format", "markdown"]
        for gate in ([], ["--fail-on-review"]):
            for operation in ("write", "flush"):
                stream = Mock(fileno=Mock(return_value=-1))  # argparse on 3.14 probes fileno(); -1 is not a tty
                getattr(stream, operation).side_effect = OSError("SECRET")
                with redirect_stdout(stream), self.assertRaises(OSError):
                    main(args + gate)
                stream.write.assert_called_once()
                self.assertEqual(stream.flush.call_count, int(operation == "flush"))
            stream = Mock(fileno=Mock(return_value=-1))
            with redirect_stdout(stream), redirect_stderr(io.StringIO()):
                self.assertEqual(main(args + gate + ["--as-of", "SECRET"]), 2)
            stream.write.assert_not_called()
            stream.flush.assert_not_called()


if __name__ == "__main__":
    unittest.main()
