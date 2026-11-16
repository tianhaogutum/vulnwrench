"""Native Markdown presents a complete review-only draft, never an approval."""
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from vulnwrench.triage import import_trivy_ignore
from vulnwrench.triage.cli import main
from vulnwrench.triage.compiler import digest, json_bytes
from vulnwrench.triage.model import MAX_INPUT_BYTES
from tests.triage.test_bridge import ROOT
from tests.triage.test_import_trivy import FIXTURES, native


def appendix(markdown):
    section = markdown.split("## Full draft (JSON)\n", 1)[1]
    block = section[re.search(r"^`{3,}json$", section, re.MULTILINE).start():].strip().splitlines()
    assert block[-1] == block[0].removesuffix("json")
    return json.loads("\n".join(block[1:-1]))


class ImportMarkdownTests(unittest.TestCase):
    def cli(self, source, *extra):
        return subprocess.run([sys.executable, "-m", "vulnwrench", "triage", "import-trivy", str(source), *extra],
                              cwd=ROOT, capture_output=True, timeout=60)

    def test_supported_mixed_unsupported_empty_formats_and_gate(self):
        cases = [(FIXTURES / f"{name}.trivyignore.yaml").read_bytes()
                 for name in ("native", "supported", "unsupported")]
        cases += [json_bytes({"vulnerabilities": [native()["vulnerabilities"][0],
                    {"id": "CVE-2", "paths": []}]}), b'{"vulnerabilities": []}',
                  b'{"secrets": [{}, {}]}']
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "native"
            for raw in cases:
                source.write_bytes(raw)
                before = source.stat()
                expected = import_trivy_ignore(raw)
                self.assertEqual(expected["source"]["rawSha256"], digest(raw))
                if raw == cases[0]:
                    self.assertEqual(json_bytes(expected), (FIXTURES / "expected-draft.json").read_bytes())
                markdown = None
                for flags in ((), ("--fail-on-unsupported",)):
                    for format_flags in ((), ("--format", "json"), ("--format", "markdown")):
                        with self.subTest(raw=raw[:50], flags=flags, format=format_flags):
                            result = self.cli(source, *format_flags, *flags)
                            self.assertEqual(result.returncode, int(bool(flags) and expected["counts"]["unsupported"] != 0), result.stderr)
                            self.assertEqual(result.stderr, b"")
                            if "markdown" in format_flags:
                                self.assertTrue(result.stdout.startswith(b"# Trivy import review draft\n"))
                                self.assertEqual(appendix(result.stdout.decode()), expected)
                                if markdown is not None:
                                    self.assertEqual(markdown, result.stdout)
                                markdown = result.stdout
                            else:
                                self.assertEqual(result.stdout, json_bytes(expected))
                self.assertEqual(source.read_bytes(), raw)
                self.assertEqual((source.stat().st_mode, source.stat().st_mtime_ns), (before.st_mode, before.st_mtime_ns))
                self.assertEqual(list(Path(tmp).iterdir()), [source])

    def test_all_fields_indices_order_and_unsupported_kinds_are_visible(self):
        from vulnwrench.triage.import_markdown import render_import_markdown
        from vulnwrench.triage.renewal_markdown import _cell
        doc = {"vulnerabilities": [
            native(purls=["pkg:npm/demo@1", "pkg:npm/demo@2"])["vulnerabilities"][0],
            {"id": "CVE-2"}, {"id": "CVE-2"},
            {"id": "CVE-3", "paths": []}, {"id": "CVE-4", "future": "opaque"},
            {"id": "CVE-5", "purls": ["pkg:npm/demo"]}, {"id": "bad id"}], "sec~/tion": []}
        draft = import_trivy_ignore(json_bytes(doc))
        before = deepcopy(draft)
        markdown = render_import_markdown(draft)
        self.assertEqual(draft, before)
        self.assertEqual(render_import_markdown(draft), markdown)
        self.assertEqual(appendix(markdown), draft)
        body = markdown.split("## Full draft (JSON)\n", 1)[0]
        chunks = body.split("### Draft ")[1:]
        self.assertEqual(len(chunks), 4)
        for index, (chunk, record, review) in enumerate(zip(chunks, draft["decisionDocument"]["decisions"], draft["reviews"])):
            self.assertTrue(chunk.startswith(str(index) + "\n"))
            for key, value in {**record, **review}.items():
                self.assertIn(f"| {key} | {_cell(value)} |", chunk)
            self.assertIsNone(record["owner"])
            self.assertIsNone(record["status"])
        self.assertEqual(draft["reviews"][2]["requiredFields"], ["package", "owner", "reason", "expiresOn", "status"])
        self.assertEqual(draft["reviews"][2]["nativeScope"], "all_packages")
        self.assertEqual(draft["reviews"][0]["nativeScope"], "exact_purls")
        findings = body.split("## Unsupported findings\n", 1)[1].split("## Warnings\n", 1)[0]
        rows = [line for line in findings.splitlines() if line.startswith("| `")]
        self.assertEqual(len(rows), 5)
        for index, (line, entry) in enumerate(zip(rows, draft["unsupported"])):
            self.assertEqual(line, "| " + " | ".join(_cell(x) for x in (index, entry["pointer"], entry["code"], entry["detail"])) + " |")
        for warning in draft["warnings"]:
            self.assertIn("- " + _cell(warning), body)
        for key, value in draft["source"].items():
            self.assertIn(f"| {key} | {_cell(value)} |", body)
        self.assertIn("| automaticActions | `[]` |", body)
        self.assertIn("| mode | `review_only` |", body)

    def test_escaping_unicode_opaque_pointers_and_lossless_disclosure(self):
        from vulnwrench.triage.import_markdown import render_import_markdown
        text = 'café 雪 🐈 | ` ``` `````` <script> [click](https://example.invalid)\n# heading\tend\u202e\u2066\u0085\u2028\u2029 literal\\u007c'
        section = text + '\x00\x1f\x7f~/<tag>'
        draft = import_trivy_ignore(json_bytes(native(statement=text) | {section: []}))
        self.assertEqual(draft["decisionDocument"]["decisions"][0]["reason"], text)
        markdown = render_import_markdown(draft)
        self.assertEqual(appendix(markdown), draft)
        body, raw = markdown.split("## Full draft (JSON)\n", 1)
        self.assertIn("café 雪 🐈", body)
        self.assertIn(r"\u007c \u0060 \u0060\u0060\u0060", body)
        self.assertIn(r"\u003cscript\u003e", body)
        self.assertIn(r"\n# heading\tend\u202e\u2066\u0085\u2028\u2029", body)
        self.assertIn(r"literal\\u007c", body)
        self.assertIn(r"\u0000\u001f\u007f~0~1\u003ctag\u003e", body)
        for control in ("\x00", "\x1f", "\x7f", "\t", "\u202e", "\u2066", "\u0085", "\u2028", "\u2029"):
            self.assertNotIn(control, markdown)
        self.assertNotIn("<script>", body)
        self.assertNotIn("\n# heading", body)
        self.assertIn("```````json\n", raw)
        self.assertIn("not redacted", raw)
        self.assertIn("rejected raw source values", raw)
        for line in body.splitlines():
            if line.startswith("| "):
                self.assertIn(line.count("|"), (3, 5))
        # Invalid IDs remain findings rather than being repaired or copied to drafts.
        invalid = import_trivy_ignore(json_bytes(native(id=text)))
        self.assertEqual(invalid["counts"]["draftDecisions"], 0)
        self.assertEqual(appendix(render_import_markdown(invalid)), invalid)

    def assert_invalid(self, source, code, *extra):
        for flags in ((), ("--fail-on-unsupported",)):
            result = self.cli(source, "--format", "markdown", *extra, *flags)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(result.stdout, b"")
            self.assertIn(code.encode(), result.stderr)
            self.assertNotIn(b"SECRET", result.stderr)
            self.assertNotIn(b"Traceback", result.stderr)

    def test_invalid_syntax_json_size_record_expansion_and_flags_emit_nothing(self):
        blocked = {"id": "CVE-2", "paths": []}
        prefix = b'{"vulnerabilities":[]}'
        exact = prefix + b" " * (MAX_INPUT_BYTES - len(prefix))
        invalid = [exact + b" ", b'\xffSECRET', b'{"SECRET":[],"SECRET":[]}',
                   b'{"SECRET":[NaN]}', b'{"SECRET":[Infinity]}',
                   b'{"SECRET":' + b'[' * 10000 + b'0' + b']' * 10000 + b'}',
                   b'vulnerabilities:\n  - id: &SECRET CVE-1\n',
                   b'{"vulnerabilities":[{"id":"CVE-2","paths":[]}, "SECRET"]}',
                   json_bytes({"vulnerabilities": [blocked] + [{"id": "CVE-1"}] * 10000}),
                   json_bytes({"vulnerabilities": [blocked, {"id": "CVE-1", "purls": ["pkg:npm/demo@1"] * 10001}]})]
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "SECRET-native"
            source.write_bytes(exact)
            result = self.cli(source, "--format", "markdown", "--fail-on-unsupported")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(appendix(result.stdout.decode()), import_trivy_ignore(exact))
            for raw in invalid:
                with self.subTest(size=len(raw), prefix=raw[:40]):
                    source.write_bytes(raw)
                    self.assert_invalid(source, "E_IMPORT")
            for flags in (("--format", "SECRET"), ("--format",), ("--SECRET",),
                          ("--fail-on-unsupported=SECRET",), ("SECRET-extra",)):
                self.assert_invalid(source, "E_ARGUMENT", *flags)
            self.assertEqual(list(Path(tmp).iterdir()), [source])

    def test_nonregular_unreadable_refusals_and_regular_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp, socket.socket(socket.AF_UNIX) as sock:
            root = Path(tmp)
            saved = root / "saved"
            saved.mkdir()
            ancestor = root / "ancestor"
            ancestor.symlink_to(saved, target_is_directory=True)
            source = saved / "native"
            source.write_bytes((FIXTURES / "native.trivyignore.yaml").read_bytes())
            final = root / "final"
            final.symlink_to(source)
            fifo = root / "SECRET-fifo"
            os.mkfifo(fifo)
            link = root / "SECRET-fifo-link"
            link.symlink_to(fifo)
            dangling = root / "SECRET-dangling"
            dangling.symlink_to(root / "SECRET-missing")
            socket_path = root / "SECRET-socket"
            sock.bind(str(socket_path))
            unreadable = root / "SECRET-unreadable"
            unreadable.write_bytes(b'{"vulnerabilities": []}')
            unreadable.chmod(0)
            entries = set(root.rglob("*"))
            try:
                for held in (False, True):
                    peer = os.open(fifo, os.O_RDWR | os.O_NONBLOCK) if held else None
                    try:
                        for path in (fifo, link):
                            self.assert_invalid(path, "E_IO")
                    finally:
                        if peer is not None:
                            os.close(peer)
                for path in (dangling, socket_path, root, Path(os.devnull), root / "SECRET-missing"):
                    self.assert_invalid(path, "E_IO")
                if os.geteuid() != 0:
                    self.assert_invalid(unreadable, "E_IO")
                expected = self.cli(source, "--format", "markdown").stdout
                for path in (final, ancestor / "native"):
                    result = self.cli(path, "--format", "markdown", "--fail-on-unsupported")
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout, expected)
                self.assertEqual(set(root.rglob("*")), entries)
                self.assertEqual(source.read_bytes(), (FIXTURES / "native.trivyignore.yaml").read_bytes())
                self.assertTrue(final.is_symlink())
                self.assertTrue(ancestor.is_symlink())
            finally:
                unreadable.chmod(0o600)

    def test_one_validated_report_rendered_before_write_flush_and_gate(self):
        from vulnwrench.triage.import_markdown import render_import_markdown
        for name in ("native", "unsupported"):
            source = FIXTURES / f"{name}.trivyignore.yaml"
            expected = import_trivy_ignore(source.read_bytes())
            for flags in ([], ["--fail-on-unsupported"]):
                for failure in (None, "write", "flush"):
                    with self.subTest(name=name, flags=flags, failure=failure):
                        events = []
                        class Output(io.StringIO):
                            def write(self, value):
                                events.append("write")
                                if failure == "write":
                                    raise BrokenPipeError("synthetic write failure")
                                return super().write(value)
                            def flush(self):
                                events.append("flush")
                                if failure == "flush":
                                    raise OSError("synthetic flush failure")
                        class Draft(dict):
                            def __getitem__(self, key):
                                if key == "counts" and "rendered" in events:
                                    self_test.assertEqual(events, ["rendered", "write", "flush"])
                                    events.append("gate")
                                return super().__getitem__(key)
                        def render(draft):
                            self.assertIs(draft, validated)
                            self.assertEqual(events, [])
                            result = render_import_markdown(draft)
                            events.append("rendered")
                            return result
                        self_test = self
                        validated = Draft(expected)
                        output, errors = Output(), io.StringIO()
                        with patch("vulnwrench.triage.cli.load_trivy_ignore", return_value=validated) as load, \
                             patch("vulnwrench.triage.cli.render_import_markdown", side_effect=render) as renderer:
                            with redirect_stdout(output), redirect_stderr(errors):
                                if failure:
                                    with self.assertRaises(OSError):
                                        main(["import-trivy", str(source), "--format", "markdown", *flags])
                                else:
                                    code = main(["import-trivy", str(source), "--format", "markdown", *flags])
                                    self.assertEqual(code, int(bool(flags) and expected["counts"]["unsupported"] != 0))
                            load.assert_called_once_with(str(source), regular_only=True)
                            renderer.assert_called_once_with(validated)
                        self.assertEqual(events, ["rendered", "write"] + ([] if failure == "write" else ["flush"])
                                         + (["gate"] if flags and failure is None else []))
                        self.assertEqual(errors.getvalue(), "")
                        if failure != "write":
                            self.assertEqual(output.getvalue(), render_import_markdown(expected))
