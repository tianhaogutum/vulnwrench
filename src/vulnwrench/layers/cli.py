"""CLI boundary: strict local JSON input, atomic file output, quiet errors."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

from . import InputError, __version__, compare, explain
from ._inputs import MAX_INPUT_BYTES, parse_json


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        # argparse normally includes arbitrary user arguments in diagnostics.
        self.exit(2, "vulnwrench layers: error: invalid command-line arguments; use --help\n")


def load_bytes(path: Path, label: str) -> bytes:
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_INPUT_BYTES + 1)
        if len(raw) > MAX_INPUT_BYTES:
            raise InputError(f"{label}: input exceeds 32 MiB limit")
    except OSError:
        raise InputError(f"{label}: unable to read input") from None
    return raw


def load_json(path: Path, label: str) -> dict:
    return parse_json(load_bytes(path, label), label)


def _write_output(path: Path, content: str) -> None:
    temporary = None
    try:
        # A failed write never truncates an existing output.
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                         dir=path.parent, prefix=".vulnwrench-layers-",
                                         delete=False) as stream:
            temporary = stream.name
            stream.write(content)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


_INPUTS = (("report", "report"), ("base_config", "base config"), ("image_config", "image config"),
           ("digest_map", "digest map"), ("image_manifest", "image manifest"),
           ("base_manifest", "base manifest"), ("base_digest_map", "base digest map"))


def _snapshot_arguments(command: argparse.ArgumentParser, prefix: str = "") -> None:
    command.add_argument("--" + prefix + "report", required=True, type=Path,
                         help="Trivy schema-2 container_image JSON")
    command.add_argument("--" + prefix + "report-sha256",
                         help="optional sha256: plus 64 lowercase hex digits; pin exact report bytes")
    command.add_argument("--" + prefix + "base-config", required=True, type=Path,
                         help="local base OCI image config JSON")
    command.add_argument("--" + prefix + "base-config-sha256",
                         help="optional sha256: plus 64 lowercase hex digits; pin exact base config bytes")
    command.add_argument("--" + prefix + "image-config", required=True, type=Path,
                         help="local final OCI image config JSON")
    command.add_argument("--" + prefix + "image-config-sha256",
                         help="optional sha256: plus 64 lowercase hex digits; pin exact final config bytes")
    command.add_argument("--" + prefix + "digest-map", type=Path,
                         help="explicit compressed Digest -> DiffID JSON object")
    command.add_argument("--" + prefix + "digest-map-sha256",
                         help="optional sha256: plus 64 lowercase hex digits; pin exact digest map bytes")
    command.add_argument("--" + prefix + "image-manifest", type=Path,
                         help="local OCI manifest: verify final config bytes and ordered explicit mappings")
    command.add_argument("--" + prefix + "image-manifest-sha256",
                         help="optional sha256: plus 64 lowercase hex digits; pin exact final manifest bytes")
    command.add_argument("--" + prefix + "base-manifest", type=Path,
                         help="local OCI manifest: verify exact base config bytes before the prefix boundary")
    command.add_argument("--" + prefix + "base-manifest-sha256",
                         help="optional sha256: plus 64 lowercase hex digits; pin exact base manifest bytes")
    command.add_argument("--" + prefix + "base-digest-map-sha256",
                         help="optional sha256: plus 64 lowercase hex digits; pin exact base digest map bytes")
    command.add_argument("--" + prefix + "base-digest-map", type=Path,
                         help="complete base descriptor Digest -> DiffID map; requires base manifest")


def _load_snapshot(args: argparse.Namespace, prefix: str = "") -> dict:
    snapshot = {}
    for field, label in _INPUTS:
        path = getattr(args, prefix + field)
        manifest_field = {"image_config": "image_manifest", "base_config": "base_manifest"}.get(field)
        raw_config = manifest_field is not None and getattr(args, prefix + manifest_field) is not None
        raw_config = raw_config or (field in ("base_config", "image_config") and getattr(
            args, prefix + field + "_sha256") is not None)
        raw_manifest = field in ("base_manifest", "image_manifest") and getattr(
            args, prefix + field + "_sha256") is not None
        raw_report = field == "report" and getattr(args, prefix + "report_sha256") is not None
        raw_map = field in ("digest_map", "base_digest_map") and getattr(
            args, prefix + field + "_sha256") is not None
        reader = load_bytes if raw_config or raw_manifest or raw_report or raw_map else load_json
        snapshot[field] = reader(path, label) if path is not None else None
    snapshot["base_manifest_sha256"] = getattr(args, prefix + "base_manifest_sha256")
    snapshot["base_config_sha256"] = getattr(args, prefix + "base_config_sha256")
    snapshot["image_config_sha256"] = getattr(args, prefix + "image_config_sha256")
    snapshot["image_manifest_sha256"] = getattr(args, prefix + "image_manifest_sha256")
    snapshot["report_sha256"] = getattr(args, prefix + "report_sha256")
    snapshot["base_digest_map_sha256"] = getattr(args, prefix + "base_digest_map_sha256")
    snapshot["digest_map_sha256"] = getattr(args, prefix + "digest_map_sha256")
    return snapshot


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(prog="vulnwrench layers", description="Explain Trivy image vulnerabilities using local OCI layer evidence (offline).")
    parser.add_argument("--version", action="version", version=f"vulnwrench layers {__version__}")
    commands = parser.add_subparsers(dest="command", required=True, parser_class=_Parser)
    command = commands.add_parser("explain", help="attribute every vulnerability to base, app, or unknown")
    _snapshot_arguments(command)
    command.add_argument("--gate", choices=("none", "app", "all"), default="none",
                         help="none: explain only; app: app and unknown fail; all: any finding fails")
    comparison = commands.add_parser("compare", help="compare independently attributed base-upgrade snapshots")
    for side in ("before", "after"):
        _snapshot_arguments(comparison, side + "-")
    comparison.add_argument("--target-map", type=Path,
                            help="explicit before Target -> after Target JSON object (partial bijection)")
    comparison.add_argument("--target-map-sha256",
                            help="optional sha256: plus 64 lowercase hex digits; pin exact target map bytes")
    for subcommand in (command, comparison):
        subcommand.add_argument("--output", default="-", help="JSON file (atomic replacement), or - for stdout")
    args = parser.parse_args(argv)
    try:
        prefixes = ("before_", "after_") if args.command == "compare" else ("",)
        sources = [(getattr(args, prefix + field), label)
                   for prefix in prefixes for field, label in _INPUTS
                   if getattr(args, prefix + field) is not None]
        if args.command == "compare" and args.target_map is not None:
            sources.append((args.target_map, "target map"))
        if args.output != "-":
            output = Path(args.output)
            for source, _ in sources:
                if output.resolve() == source.resolve() or (
                        output.exists() and source.exists() and output.samefile(source)):
                    raise InputError("output must not replace an input file")
        if args.command == "compare":
            before = _load_snapshot(args, "before_")
            after = _load_snapshot(args, "after_")
            result = compare(before["report"], before["base_config"], before["image_config"],
                             after["report"], after["base_config"], after["image_config"],
                             before_digest_map=before["digest_map"], after_digest_map=after["digest_map"],
                             before_image_manifest=before["image_manifest"],
                             after_image_manifest=after["image_manifest"],
                             before_base_manifest=before["base_manifest"],
                             after_base_manifest=after["base_manifest"],
                             before_base_digest_map=before["base_digest_map"],
                             after_base_digest_map=after["base_digest_map"],
                             before_base_manifest_sha256=before["base_manifest_sha256"],
                             after_base_manifest_sha256=after["base_manifest_sha256"],
                             before_base_config_sha256=before["base_config_sha256"],
                             after_base_config_sha256=after["base_config_sha256"],
                             before_image_config_sha256=before["image_config_sha256"],
                             after_image_config_sha256=after["image_config_sha256"],
                             before_image_manifest_sha256=before["image_manifest_sha256"],
                             after_image_manifest_sha256=after["image_manifest_sha256"],
                             before_report_sha256=before["report_sha256"],
                             after_report_sha256=after["report_sha256"],
                             before_digest_map_sha256=before["digest_map_sha256"],
                             after_digest_map_sha256=after["digest_map_sha256"],
                             before_base_digest_map_sha256=before["base_digest_map_sha256"],
                             after_base_digest_map_sha256=after["base_digest_map_sha256"],
                             target_map=(load_bytes if args.target_map_sha256 is not None else load_json)(
                                 args.target_map, "target map") if args.target_map is not None else None,
                             target_map_sha256=args.target_map_sha256)
        else:
            snapshot = _load_snapshot(args)
            result = explain(**snapshot, gate=args.gate)
        content = json.dumps(result, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n"
        if args.output == "-":
            sys.stdout.write(content)
        else:
            _write_output(Path(args.output), content)
        return 1 if result.get("gate", {}).get("status") == "failed" else 0
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (OSError, ValueError, RecursionError):
        print("error: unable to process JSON or write output", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
