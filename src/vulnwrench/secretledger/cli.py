"""Command line entry points; error messages never interpolate user data."""
from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path

from . import __version__
from .core import (LedgerError, compare, dumps, init_key, key_id, load_json,
                   load_renames, markdown, read_key, snapshot)


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "vulnwrench secrets: invalid command arguments; use --help\n")


def parser():
    p = SafeParser(prog="vulnwrench secrets", description="Offline redacted content-aware review ledger for full Gitleaks JSON reports.")
    p.add_argument("--version", action="version", version=f"vulnwrench secrets {__version__}")
    sub = p.add_subparsers(dest="command", required=True, parser_class=SafeParser)
    init = sub.add_parser("init", help="explicitly generate a 0600 key and a sibling Git ignore entry")
    init.add_argument("--key-file", required=True, help="new key file in an existing local directory")
    snap = sub.add_parser("snapshot", help="build a standalone redacted ledger")
    cmp = sub.add_parser("compare", help="compare a prior ledger with a new complete report")
    for command in (snap, cmp):
        command.add_argument("--key-file", required=True)
        command.add_argument("--report", required=True, help="complete local Gitleaks JSON array")
        command.add_argument("--output", help="new JSON file; default stdout; never overwrites")
        command.add_argument("--redacted", action="store_true", help="treat all content as unknown (use for arbitrary redaction placeholders)")
    cmp.add_argument("--before", required=True, help="standalone ledger JSON (schema secret-ledger/v1)")
    cmp.add_argument("--ledger-output", help="new standalone current ledger for the next comparison")
    cmp.add_argument("--markdown", help="new redacted Markdown summary file")
    cmp.add_argument("--path-map", help="JSON array of bijective old_path/new_path mappings; unmatched paths become unknown")
    renames = sub.add_parser("import-renames", help="convert supplied name-status -z bytes to mapping JSON; rename-only by default; never runs Git")
    renames.add_argument("--name-status", required=True, help="local UTF-8 file of NUL-delimited name-status records")
    renames.add_argument("--allow-non-renames", action="store_true", help="validate and ignore single-path A/M/D/T records; other non-rename statuses remain unsupported")
    renames.add_argument("--output", help="new mapping JSON file; default stdout; never overwrites")
    return p


def _preflight(inputs, outputs):
    resolved_inputs = {Path(p).resolve() for p in inputs}
    seen = set()
    for path in outputs:
        target = Path(path)
        resolved = target.resolve()
        if resolved in resolved_inputs or resolved in seen:
            raise LedgerError("output conflicts with input or another output")
        if target.exists() or target.is_symlink():
            raise LedgerError("output already exists; choose a new path")
        if not target.parent.is_dir():
            raise LedgerError("output parent directory must exist")
        seen.add(resolved)


def _write_new(path, content):
    """Publish a complete 0600 artifact without overwriting any existing target."""
    target = Path(path)
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(prefix=".secret-ledger-", dir=target.parent)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(tmp, target)
    finally:
        if tmp is not None:
            os.unlink(tmp)


def main(argv: list[str] | None = None) -> int:
    try:
        args = parser().parse_args(argv)
        if args.command == "init":
            init_key(args.key_file)
            sys.stdout.write(dumps({"status": "initialized", "key_id": key_id(read_key(args.key_file))}))
            return 0
        if args.command == "import-renames":
            _preflight([args.name_status], [args.output] if args.output else [])
            encoded = dumps(load_renames(args.name_status, allow_non_renames=args.allow_non_renames))
            if args.output:
                _write_new(args.output, encoded)
            else:
                sys.stdout.write(encoded)
            return 0
        inputs = [args.key_file, args.report]
        outputs = [args.output] if args.output else []
        if args.command == "compare":
            inputs.append(args.before)
            if args.path_map is not None:
                inputs.append(args.path_map)
            outputs.extend(p for p in (args.ledger_output, args.markdown) if p)
        _preflight(inputs, outputs)
        key = read_key(args.key_file)
        report = load_json(args.report)
        if args.command == "snapshot":
            result = snapshot(report, key, redacted=args.redacted)
            artifacts = []
        else:
            path_map = load_json(args.path_map) if args.path_map is not None else None
            if args.path_map is not None and not isinstance(path_map, list):
                raise LedgerError("path map must be an array of old_path/new_path objects")
            result, ledger = compare(load_json(args.before), report, key, redacted=args.redacted,
                                     path_map=path_map)
            artifacts = [(args.ledger_output, dumps(ledger))] if args.ledger_output else []
            if args.markdown:
                artifacts.append((args.markdown, markdown(result)))
        # Build/validate every artifact before the first write or stdout emission.
        encoded = dumps(result)
        if args.output:
            artifacts.insert(0, (args.output, encoded))
        for path, content in artifacts:
            _write_new(path, content)
        if not args.output:
            sys.stdout.write(encoded)
        return 0
    except LedgerError as exc:
        sys.stderr.write("vulnwrench secrets: " + str(exc) + "\n")
        return 2
    except (OSError, ValueError, TypeError, OverflowError, RecursionError):
        sys.stderr.write("vulnwrench secrets: input, output or encoding error\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
