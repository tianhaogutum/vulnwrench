"""Small offline CLI. Errors never echo input contents or user-supplied values."""

import argparse
import os
from pathlib import Path
import sys
import tempfile

from .core import InputError, SCANNERS, _input_expectations, dumps, merge_reports, read_coverage_manifest, read_report, render_markdown, validate_coverage, validate_input
from .explain import explain_finding
from .explain_markdown import render_explanation_markdown
from .saved import compare_saved_input_coverage, list_saved_finding_coverage, read_merged, validate_merged, validate_saved_coverage, validate_saved_finding_coverage


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "vulnwrench fuse: invalid command arguments; see --help\n")


def _parser():
    parser = _Parser(prog="vulnwrench fuse", description="Offline Trivy/Grype/OSV report agreement matrix. No scanner execution.")
    parser.add_argument("--version", action="version", version="vulnwrench fuse 0.1.0")
    sub = parser.add_subparsers(dest="command", required=True)
    merge = sub.add_parser("merge", help="merge JSON reports, retaining every observation")
    explain = sub.add_parser("explain", help="trace one finding to original alias, package, path and conflict evidence")
    validate = sub.add_parser("validate", help="check a complete saved merge without selecting a finding")
    validate_scanner = sub.add_parser("validate-input", help="check one scanner profile and summarize byte provenance and counts")
    validate_manifest = sub.add_parser("validate-coverage", help="check manifest/report bindings and summarize provenance, counts and coverage reasons")
    validate_scanner.add_argument("--scanner", choices=SCANNERS, required=True, help="supported scanner profile")
    validate_scanner.add_argument("--input", metavar="FILE", required=True, help="one scanner JSON report")
    validate_scanner.add_argument("--input-sha256", metavar="EXPECTED", help="optional expected 64-digit lowercase SHA-256 of input bytes")
    validate_scanner.add_argument("--output", metavar="FILE", help="JSON validation summary file (default: stdout)")
    for command in (merge, explain, validate_manifest):
        for scanner in SCANNERS:
            command.add_argument("--" + scanner, action="append", default=[], metavar="REPORT.json",
                                 help="input report; repeat for multiple inputs")
        command.add_argument("--output", metavar="FILE", help=("selected-format output file (default: stdout)"
                             if command is explain else "JSON output file (default: stdout)"))
        command.add_argument("--coverage-manifest", metavar="FILE",
                             help="byte-bound per-input coverage declarations (required by live validate-coverage)")
        command.add_argument("--coverage-manifest-sha256", metavar="EXPECTED",
                             help="expected 64-digit lowercase SHA-256 of manifest bytes; requires --coverage-manifest in scanner mode")
        command.add_argument("--expect-input-sha256", nargs=3, action="append", default=[],
                             metavar=("SCANNER", "FILE", "EXPECTED"),
                             help="optional input byte expectation; exact scanner/input argument key; repeat for distinct keys")
    merge.add_argument("--markdown", metavar="FILE", help="also write Markdown summary")
    validate.add_argument("--output", metavar="FILE", help="JSON validation summary file (default: stdout)")
    for command in (explain, validate, validate_manifest):
        command.add_argument("--merged", metavar="FILE", required=command is validate,
                             help="saved vulnfuse-1 merge report (vulnwrench fuse merge output); excludes scanner flags and coverage manifest")
        command.add_argument("--merged-sha256", metavar="EXPECTED", help="expected 64-digit lowercase SHA-256 of saved file bytes; requires --merged")
    selection = explain.add_mutually_exclusive_group(required=True)
    selection.add_argument("--finding", metavar="ID", help="finding ID in the same input set, including unknown identities")
    selection.add_argument("--advisory", metavar="ID", help="exact primary or explicitly linked alias ID")
    coverage_selection = validate_manifest.add_mutually_exclusive_group()
    coverage_selection.add_argument("--finding", metavar="ID", help="summarize one exact finding's absence comparisons; requires --merged")
    coverage_selection.add_argument("--list-findings", action="store_true",
                                    help="list finding IDs and presence counts without evidence; requires --merged")
    coverage_selection.add_argument("--compare-inputs", nargs=2, metavar=("SOURCE_A", "SOURCE_B"),
                                    help="compare two exact distinct source occurrences without evidence; requires --merged")
    explain.add_argument("--package", metavar="IDENTITY", help="exact canonical package identity; requires --advisory")
    explain.add_argument("--format", choices=("json", "markdown"), default="json",
                         help="selected explanation format (default: json); --output writes this format")
    return parser


def _same_file(left, right):
    if Path(left).resolve() == Path(right).resolve():
        return True
    try:
        return os.path.samefile(left, right)
    except FileNotFoundError:
        return False


def _write(path, contents):
    # Atomic per file. Use a private temporary file because reports can be sensitive.
    temporary = None
    try:
        destination = Path(path)
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                         dir=destination.parent, prefix=".vulnwrench-fuse-", delete=False) as stream:
            temporary = stream.name
            stream.write(contents)
        os.replace(temporary, destination)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        inputs = [(s, p) for s in SCANNERS for p in getattr(args, s, [])]
        if args.command == "validate-input":
            inputs = [(args.scanner, args.input)]
        saved = getattr(args, "merged", None)
        expected = getattr(args, "merged_sha256", None)
        coverage = getattr(args, "coverage_manifest", None)
        coverage_expected = getattr(args, "coverage_manifest_sha256", None)
        declarations = getattr(args, "expect_input_sha256", [])
        if saved is not None and declarations:
            raise InputError("input: expected SHA-256 requires scanner mode")
        input_expected = _input_expectations(inputs, declarations)
        if coverage_expected is not None and (coverage is None or saved is not None):
            raise InputError("coverage: expected SHA-256 requires a manifest in scanner mode")
        if expected is not None and saved is None:
            raise InputError("explain: expected merged SHA-256 requires saved input")
        if saved is not None and (inputs or coverage is not None):
            raise InputError("explain: saved input excludes scanner reports and coverage manifest")
        if (args.command == "validate-coverage" and saved is None
                and (args.finding is not None or args.list_findings or args.compare_inputs is not None)):
            raise InputError("coverage: selection or listing requires saved input")
        if not inputs and saved is None:
            raise InputError("at least one scanner report or saved merge is required")
        markdown = getattr(args, "markdown", None)
        outputs = [p for p in [args.output, markdown] if p is not None]
        protected = [p for _, p in inputs] + ([coverage] if coverage is not None else [])
        if saved is not None:
            protected.append(saved)
        if any(_same_file(out, src) for out in outputs for src in protected):
            raise InputError("output must not overwrite an input")
        if len(outputs) == 2 and _same_file(*outputs):
            raise InputError("JSON and Markdown outputs must be different files")
        if args.command == "validate-input":
            result = validate_input(args.scanner, args.input, expected_sha256=args.input_sha256)
        elif args.command == "validate":
            result = validate_merged(saved, expected_sha256=expected)
        elif args.command == "validate-coverage":
            result = (compare_saved_input_coverage(saved, source_a=args.compare_inputs[0],
                                                  source_b=args.compare_inputs[1], expected_sha256=expected)
                      if args.compare_inputs is not None else
                      list_saved_finding_coverage(saved, expected_sha256=expected) if args.list_findings else
                      validate_saved_finding_coverage(saved, finding_id=args.finding, expected_sha256=expected)
                      if args.finding is not None else
                      validate_saved_coverage(saved, expected_sha256=expected) if saved is not None else
                      validate_coverage(inputs, coverage_manifest=coverage,
                                        coverage_manifest_sha256=coverage_expected,
                                        expect_input_sha256=declarations))
        else:
            manifest = read_coverage_manifest(coverage, expected_sha256=coverage_expected) if coverage is not None else None
            merged = read_merged(saved, expected_sha256=expected) if saved is not None else merge_reports(
                (read_report(s, p, expected_sha256=input_expected.get((s, p))) for s, p in inputs),
                coverage_manifest=manifest)
            result = merged
            if args.command == "explain":
                result = explain_finding(merged, finding_id=args.finding, advisory=args.advisory, package=args.package)
        encoded = (render_explanation_markdown(result)
                   if args.command == "explain" and args.format == "markdown" else dumps(result))
        if args.output:
            _write(args.output, encoded)
        if markdown:
            _write(markdown, render_markdown(merged))
        if not args.output:
            sys.stdout.write(encoded)
        return 0
    except InputError as exc:
        sys.stderr.write(f"vulnwrench fuse: {exc}\n")
        return 2
    except (OSError, ValueError, RecursionError, UnicodeError):
        sys.stderr.write("vulnwrench fuse: unable to process input or write output\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
