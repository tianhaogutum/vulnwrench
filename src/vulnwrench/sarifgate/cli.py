"""Command-line boundary: bounded reads, sanitized errors, atomic report writes."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
import tempfile

from . import __version__
from .baseline import compare_bytes
from .core import InputError, Policy, check_bytes, dumps, markdown_summary, parse_document

MAX_BYTES = 32 * 1024 * 1024


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        # argparse's usual diagnostics can echo attacker-controlled values.
        self.exit(2, "vulnwrench sarif: invalid arguments; use --help\n")


def _positive(value: str) -> int:
    try:
        number = int(value)
        if number <= 0 or number >= sys.maxsize:
            raise ValueError
        return number
    except ValueError:
        raise argparse.ArgumentTypeError("expected positive integer") from None


def _aliases(left: Path, right: Path) -> bool:
    return left.resolve() == right.resolve() or (
        left.exists() and right.exists() and os.path.samefile(left, right))


def _write(path: Path, content: str) -> None:
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                         dir=path.parent, prefix=".vulnwrench-sarif-", delete=False) as stream:
            temporary = stream.name
            stream.write(content)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            Path(temporary).unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = Parser(prog="vulnwrench sarif", description="Offline SARIF 2.1.0 gate with suppression and execution traces.")
    parser.add_argument("--version", action="version", version=f"vulnwrench sarif {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True, parser_class=Parser)
    check = subparsers.add_parser("check", help="evaluate one self-contained SARIF JSON file")
    check.add_argument("input", help="UTF-8 SARIF file, or - for stdin")
    check.add_argument("--baseline", type=Path, help="optional prior SARIF file (not stdin)")
    check.add_argument("--fingerprint", help="explicit result.fingerprints key; required with --baseline")
    check.add_argument("--run-pairing", type=Path, help="per-side runIndex/pairId JSON manifest; requires --baseline")
    check.add_argument("--level", choices=("note", "warning", "error"), default="warning",
                       help="blocking threshold (default: warning)")
    check.add_argument("--ignore-unchanged", action="store_true", help="explicitly exclude unchanged baseline results")
    check.add_argument("--require-execution-success", action="store_true",
                       help="also fail on absent/unknown invocation success or zero runs")
    check.add_argument("--output", type=Path, help="report destination (default: stdout)")
    check.add_argument("--format", choices=("json", "markdown"), default="json")
    check.add_argument("--markdown", type=Path, help="additional Markdown summary file")
    check.add_argument("--max-bytes", type=_positive, default=MAX_BYTES, help="input byte limit (default: 33554432)")
    args = parser.parse_args(argv)
    if (args.baseline is None) != (args.fingerprint is None) or args.fingerprint == "":
        parser.error("baseline and fingerprint must be supplied together")
    if args.run_pairing is not None and args.baseline is None:
        parser.error("run-pairing requires baseline")
    try:
        source = None if args.input == "-" else Path(args.input)
        destinations = [p for p in (args.output, args.markdown) if p is not None]
        sources = [p for p in (source, args.baseline, args.run_pairing) if p is not None]
        if any(_aliases(src, dest) for src in sources for dest in destinations):
            raise InputError("output: must not overwrite input")
        if len(destinations) == 2 and _aliases(*destinations):
            raise InputError("output: report destinations must differ")
        if source is None:
            data = sys.stdin.buffer.read(args.max_bytes + 1)
        else:
            with source.open("rb") as stream:
                data = stream.read(args.max_bytes + 1)
        if len(data) > args.max_bytes:
            raise InputError("input: byte limit exceeded")
        policy = Policy(args.level, args.ignore_unchanged, args.require_execution_success)
        if args.baseline is not None:
            with args.baseline.open("rb") as stream:
                baseline_data = stream.read(args.max_bytes + 1)
            if len(baseline_data) > args.max_bytes:
                raise InputError("baseline: byte limit exceeded")
            run_pairing = None
            if args.run_pairing is not None:
                with args.run_pairing.open("rb") as stream:
                    pairing_data = stream.read(args.max_bytes + 1)
                if len(pairing_data) > args.max_bytes:
                    raise InputError("runPairing: byte limit exceeded")
                run_pairing = parse_document(pairing_data)
            report = compare_bytes(data, baseline_data, fingerprint=args.fingerprint, policy=policy,
                                   run_pairing=run_pairing)
        else:
            report = check_bytes(data, policy)
        content = dumps(report) if args.format == "json" else markdown_summary(report)
        if args.markdown is not None:
            _write(args.markdown, markdown_summary(report))
        if args.output is not None:
            _write(args.output, content)
        else:
            sys.stdout.write(content)
        return 1 if report["decision"] == "fail" else 0
    except InputError as exc:
        print(f"vulnwrench sarif: {exc}", file=sys.stderr)
        return 2
    except (OSError, UnicodeError, ValueError, RecursionError):
        print("vulnwrench sarif: I/O, encoding, or resource error", file=sys.stderr)
        return 2
