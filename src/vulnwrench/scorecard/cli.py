"""Command line interface; invalid input diagnostics never echo input contents."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from . import __version__
from .core import KNOWN_CHECKS, InputError, _snapshot_paths, check, gate_exit_code, render_markdown
from .mapping_lint import lint_mappings, render_lint_markdown
from .comparison import compare
from .comparison_markdown import render_comparison_markdown


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        self.exit(2, "vulnwrench scorecard: invalid command-line arguments (use --help)\n")


def _parser():
    parser = _Parser(prog="vulnwrench scorecard",
                     description="Join a CycloneDX SBOM to local Scorecard JSON evidence. Entirely offline.")
    parser.add_argument("--version", action="version", version=f"vulnwrench scorecard {__version__}")
    commands = parser.add_subparsers(dest="command", required=True, parser_class=_Parser)
    command = commands.add_parser("check", help="produce component-level evidence and policy decisions",
                                  description="No scanners, target programs or network requests are executed.",
                                  epilog="Policy check names: " + ", ".join(sorted(KNOWN_CHECKS)))
    command.add_argument("bom", type=Path, help="CycloneDX 1.4–1.6 JSON SBOM")
    command.add_argument("--map", dest="mapping", type=Path, required=True, help="exact PURL -> repository JSON object")
    command.add_argument("--scorecards", type=Path, required=True, help="one native JSON document, or directory of .json documents")
    command.add_argument("--policy", type=Path, required=True, help="JSON checks, maxAgeDays, missing policy")
    command.add_argument("--as-of", required=True, help="UTC date (inclusive whole day) or timezone-aware RFC3339 timestamp")
    command.add_argument("--format", choices=("json", "markdown"), default="json", help="output format (default: json)")
    command.add_argument("--output", type=Path, help="atomic local output file (default: stdout)")
    command.add_argument("--gate", action="store_true", help="exit 1 unless the report decision is pass; still write the report")
    lint = commands.add_parser("lint-mappings", help="report mapping issues before joining; no policy or snapshots required")
    lint.add_argument("bom", type=Path, help="CycloneDX 1.4–1.6 JSON SBOM")
    lint.add_argument("--map", dest="mapping", type=Path, required=True, help="exact PURL -> repository JSON object")
    lint.add_argument("--strict", action="store_true", help="exit 1 on ambiguous assignments; still write all diagnostics")
    lint.add_argument("--fail-on-unmapped", action="store_true",
                      help="exit 1 on unmapped or missing-PURL components; still write all diagnostics (combine with --strict for ambiguity)")
    lint.add_argument("--format", choices=("json", "markdown"), default="json", help="output format (default: json)")
    lint.add_argument("--output", type=Path, help="atomic local output file (default: stdout)")
    comparison = commands.add_parser("compare", help="compare two dated snapshot bundles for the same inventory and mapping")
    comparison.add_argument("bom", type=Path, help="CycloneDX 1.4–1.6 JSON SBOM")
    comparison.add_argument("--map", dest="mapping", type=Path, required=True, help="one exact PURL -> repository mapping for both bundles")
    comparison.add_argument("--before", type=Path, required=True, help="older bundle: one native JSON snapshot or flat directory")
    comparison.add_argument("--after", type=Path, required=True, help="newer bundle: one native JSON snapshot or flat directory")
    comparison.add_argument("--before-as-of", required=True, help="older bundle cutoff: inclusive UTC date or RFC3339 timestamp")
    comparison.add_argument("--after-as-of", required=True, help="newer bundle cutoff, strictly later than --before-as-of")
    comparison.add_argument("--max-age-days", type=int, required=True, help="maximum fresh age in UTC calendar days, inclusive")
    comparison.add_argument("--format", choices=("json", "markdown"), default="json", help="output format (default: json)")
    comparison.add_argument("--output", type=Path, help="atomic local output file (default: stdout)")
    comparison.add_argument("--check", dest="checks", action="append", metavar="NAME",
                            help="select an exact observed check name (repeatable; no policy allowlist); full snapshots remain in the report")
    comparison.add_argument("--fail-on-decrease", action="store_true",
                            help="exit 1 on any comparable observed check score decrease; still write the report. Exit 0 does not establish complete evidence or a security pass")
    return parser


def _write_output(path: Path, text: str, inputs: list[Path]):
    # Avoid an accidental in-place replacement of any supplied evidence, including
    # hardlinks and alternate path spellings. Atomic writes never leave half JSON.
    try:
        _protect_output(path, inputs)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                             dir=path.parent, prefix=".scorecard-join-", delete=False) as stream:
                temporary = stream.name
                stream.write(text)
            os.replace(temporary, path)
        finally:
            if temporary is not None:
                Path(temporary).unlink(missing_ok=True)
    except InputError:
        raise
    except (OSError, ValueError):
        raise InputError("cannot write output file") from None


def _protect_output(path: Path, inputs: list[Path]):
    if path.is_symlink() or any(path.resolve() == source.resolve()
                                or (path.exists() and source.exists() and path.samefile(source))
                                for source in inputs):
        raise InputError("output must not overwrite an input file or symlink")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "lint-mappings":
            report = lint_mappings(args.bom, args.mapping)
            inputs = [args.bom, args.mapping]
            exit_code = int(bool(
                (args.strict and report["summary"]["ambiguousMappings"])
                or (args.fail_on_unmapped and report["summary"]["unmappedComponents"])
            ))
        elif args.command == "compare":
            report = compare(args.bom, args.mapping, args.before, args.after,
                             args.before_as_of, args.after_as_of, max_age_days=args.max_age_days, checks=args.checks)
            inputs = [args.bom, args.mapping, *_snapshot_paths(args.before), *_snapshot_paths(args.after)] if args.output else []
            exit_code = int(bool(args.fail_on_decrease and report["summary"]["checkScoreChanges"]["decreased"]))
        else:
            report = check(args.bom, args.mapping, args.scorecards, args.policy, args.as_of)
            inputs = [args.bom, args.mapping, args.policy, *_snapshot_paths(args.scorecards)] if args.output else []
            exit_code = gate_exit_code(report) if args.gate else 0
        if args.command == "lint-mappings" and args.format == "markdown":
            text = render_lint_markdown(report)
        elif args.command == "compare" and args.format == "markdown":
            text = render_comparison_markdown(report)
        elif args.command == "check" and args.format == "markdown":
            text = render_markdown(report)
        else:
            text = json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n"
        if args.output:
            _write_output(args.output, text, inputs)
        else:
            sys.stdout.write(text)
        return exit_code
    except InputError as error:
        print(f"vulnwrench scorecard: {error}", file=sys.stderr)
        return 2
    except (OSError, UnicodeError, RecursionError):
        print("vulnwrench scorecard: cannot render or write report", file=sys.stderr)
        return 2
