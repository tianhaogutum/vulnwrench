"""Command line interface. Only local JSON files are read."""
import argparse
import json
import os
from pathlib import Path
import stat
import sys
import tempfile

from . import InputError, __version__, explain, to_dot, to_markdown

MAX_INPUT_BYTES = 32 * 1024 * 1024


class Parser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's normal diagnostics echo arbitrary arguments. Do not expose them.
        self.exit(2, "vulnwrench path: invalid command arguments; use --help\n")


def _unique_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise InputError("duplicate JSON object key")
        obj[key] = value
    return obj


def _nonfinite(value):
    raise InputError("nonfinite numbers are not valid JSON")


def load_json(path, label):
    try:
        # Nonblocking open lets us reject FIFOs without waiting for a writer.
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(descriptor, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise InputError(f"{label} must be a regular file")
            raw = handle.read(MAX_INPUT_BYTES + 1)
        if len(raw) > MAX_INPUT_BYTES:
            raise InputError(f"{label} exceeds the 32 MiB input limit")
        return json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_unique_object,
                          parse_constant=_nonfinite)
    except (OSError, ValueError, UnicodeError, RecursionError) as error:
        if isinstance(error, InputError):
            raise
        raise InputError(f"cannot read {label}: expected a readable UTF-8 JSON file") from None


def _positive(value):
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("expected a positive integer") from None
    if number < 1:
        raise argparse.ArgumentTypeError("expected a positive integer")
    return number


def _finding_index(value):
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("expected a nonnegative finding index") from None
    if number < 0:
        raise argparse.ArgumentTypeError("expected a nonnegative finding index")
    return number


def _write_output(path, content):
    if path is None:
        sys.stdout.write(content)
        return
    destination = Path(path)
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                         dir=destination.parent, prefix=".vulnwrench-path-", delete=False) as handle:
            temp_path = handle.name
            handle.write(content)
        os.replace(temp_path, destination)
    finally:
        if temp_path is not None and os.path.exists(temp_path):
            os.unlink(temp_path)


def main(argv: list[str] | None = None) -> int:
    parser = Parser(prog="vulnwrench path", description="Explain local Grype findings using explicit CycloneDX or SPDX dependency edges.")
    parser.add_argument("--version", action="version", version=f"vulnwrench path {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("explain", help="join local JSON reports and find shortest witnesses")
    command.add_argument("bom", help="CycloneDX JSON 1.4-1.6 or SPDX 2.3 JSON")
    command.add_argument("--grype", required=True, help="local Grype JSON report")
    command.add_argument("--mapping", help="explicit artifact-id mapping JSON, schemaVersion 1")
    root_selection = command.add_mutually_exclusive_group()
    root_selection.add_argument("--root", action="append", help="component bom-ref or package SPDXID; repeat to replace declared roots")
    root_selection.add_argument("--no-roots", action="store_true",
                                help="select no roots; reachability stays unknown; repeat is harmless")
    command.add_argument("--max-roots", type=_positive, default=100, help="affected roots per result (default: 100)")
    command.add_argument("--max-paths", type=_positive, default=1000, help="total witness paths (default: 1000)")
    command.add_argument("--format", choices=("json", "markdown", "dot"), default="json")
    selection = command.add_mutually_exclusive_group()
    selection.add_argument("--finding-index", action="append", type=_finding_index,
                           help="original Grype matches index (zero-based); selected before path caps; repeat; default all")
    selection.add_argument("--no-findings", action="store_true",
                           help="select no findings; retain roots and full input validation/evidence; repeat is harmless")
    command.add_argument("--max-nodes", type=_positive, help="DOT only: emitted nodes (default: 200)")
    command.add_argument("--max-edges", type=_positive, help="DOT only: emitted witness edges (default: 400)")
    command.add_argument("--include-input-digests", action="store_true",
                         help="DOT only: include canonical digests of full original inputs; no raw evidence")
    command.add_argument("--include-dangling-dependencies", action="store_true",
                         help="DOT only: include all full-input dangling diagnostic records; no added nodes or edges")
    command.add_argument("--include-missing-dependency-declarations", action="store_true",
                         help="DOT only: include full-input refs without dependency declarations; absence is not proof of no dependencies")
    command.add_argument("--output", help="output file; otherwise stdout")
    args = parser.parse_args(argv)
    try:
        if args.include_missing_dependency_declarations and args.format != "dot":
            raise InputError("include-missing-dependency-declarations requires DOT format")
        if args.include_dangling_dependencies and args.format != "dot":
            raise InputError("include-dangling-dependencies requires DOT format")
        if args.include_input_digests and args.format != "dot":
            raise InputError("include-input-digests requires DOT format")
        if args.format != "dot" and any(value is not None for value in (args.max_nodes, args.max_edges)):
            raise InputError("max-nodes and max-edges require DOT format")
        if args.output:
            destination = Path(args.output).resolve()
            for source in (args.bom, args.grype, args.mapping):
                if source and (destination == Path(source).resolve() or
                               (destination.exists() and os.path.samefile(destination, source))):
                    raise InputError("output must not overwrite an input file")
        bom = load_json(args.bom, "SBOM input")
        grype = load_json(args.grype, "Grype input")
        mapping = load_json(args.mapping, "mapping input") if args.mapping else None
        finding_indexes = [] if args.no_findings else args.finding_index
        roots = [] if args.no_roots else args.root
        report = explain(bom, grype, roots=roots, mapping=mapping,
                         max_roots=args.max_roots, max_paths=args.max_paths,
                         finding_indexes=finding_indexes)
        if args.format == "dot":
            content = to_dot(report, finding_indexes=finding_indexes,
                             include_input_digests=args.include_input_digests,
                             include_dangling_dependencies=args.include_dangling_dependencies,
                             include_missing_dependency_declarations=args.include_missing_dependency_declarations,
                             max_nodes=args.max_nodes if args.max_nodes is not None else 200,
                             max_edges=args.max_edges if args.max_edges is not None else 400)
        elif args.format == "markdown":
            content = to_markdown(report)
        else:
            content = json.dumps(report, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n"
        _write_output(args.output, content)
        return 0
    except InputError as error:
        print(f"vulnwrench path: {error}", file=sys.stderr)
        return 2
    except (OSError, UnicodeError, RecursionError, ValueError):
        print("vulnwrench path: input/output could not be processed safely", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
