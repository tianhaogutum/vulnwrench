"""Command line interface; all diagnostics intentionally omit input values."""
from __future__ import annotations

import argparse
import html
import json
import os
import re
from pathlib import Path
import sys
import tempfile

from . import __version__
from .core import InputError, compare

MAX_INPUT_BYTES = 20 * 1024 * 1024


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputError("JSON: duplicate object key")
        result[key] = value
    return result


def _invalid_constant(value):
    raise InputError("JSON: non-finite numbers unsupported")


def load(path, role):
    try:
        with Path(path).open("rb") as stream:
            raw = stream.read(MAX_INPUT_BYTES + 1)
        if len(raw) > MAX_INPUT_BYTES:
            raise InputError(role + ": exceeds 20 MiB limit")
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                          parse_constant=_invalid_constant)
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        if isinstance(exc, InputError):
            raise
        raise InputError(role + ": cannot read valid UTF-8 JSON") from None


def markdown(result):
    def cell(value):
        if isinstance(value, list):
            value = ", ".join(value)
        return html.escape(str(value)).replace("|", "&#124;").replace("\n", " ").replace("\r", " ")
    lines = ["# vulnwrench delta transition matrix", "", result["evidence_notice"], "",
             "Comparable: " + str(result["comparable"]).lower(), "",
             "| Package | Target / package path | Advisory | Before | After | Classification | Fixed | Reasons |",
             "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for t in result["transitions"]:
        p = t["package"]
        values = [p["ecosystem"] + ":" + p["name"], p["target"] + " / " + p["path"],
                  t["advisory"], t["before_versions"], t["after_versions"], t["classification"],
                  str(t["fixed"]).lower(), t["reasons"]]
        lines.append("| " + " | ".join(cell(v) for v in values) + " |")
    if "explanation" in result:
        if "normalized_filter" in result["explanation"]:
            lines.extend(["", "Normalized target filter: " + cell(result["explanation"]["normalized_filter"]["target"])])
            if "package_path" in result["explanation"]["normalized_filter"]:
                path = result["explanation"]["normalized_filter"]["package_path"]
                lines.extend(["", "Normalized package path filter: " + (cell(path) if path else '""')])
        lines.extend(["", "## Finding explanations", "",
                      "Requested advisory: " + cell(result["explanation"]["requested_advisory"]), "",
                      "| Transition index | Decision | Reason | Source pointers |",
                      "| --- | --- | --- | --- |"])
        for finding in result["explanation"]["findings"]:
            for reason in finding["reasons"]:
                values = [finding["transition_index"], finding["decision"]["classification"], reason["code"], reason["sources"]]
                lines.append("| " + " | ".join(cell(v) for v in values) + " |")
        lines.extend(["", "| Transition index | Fix prerequisite | Satisfied | Source pointers |",
                      "| --- | --- | --- | --- |"])
        for finding in result["explanation"]["findings"]:
            for check in finding["fix_prerequisites"]:
                values = [finding["transition_index"], check["code"], str(check["satisfied"]).lower(), check["sources"]]
                lines.append("| " + " | ".join(cell(v) for v in values) + " |")
        if result["explanation"].get("unknown_findings"):
            lines.extend(["", "## Selected unknown evidence", "",
                          "These native matches have no normalized package scope or fix/removal decision."])
            if "unknown_filter" in result["explanation"]:
                selection = result["explanation"]["unknown_filter"]
                lines.extend(["", "Unknown artifact filter: " + cell(selection["side"]) + " / " + cell(selection["artifact_id"])])
                if "reason_code" in selection:
                    lines.extend(["", "Unknown reason filter: " + cell(selection["reason_code"])])
                if "reason_codes_all" in selection:
                    lines.extend(["", "Unknown reason filter (ALL): " + ", ".join(cell(code) for code in selection["reason_codes_all"])])
                if "reason_codes_any" in selection:
                    lines.extend(["", "Unknown reason filter (ANY): " + ", ".join(cell(code) for code in selection["reason_codes_any"])])
                if "match_index" in selection:
                    lines.extend(["", "Native match index: " + cell(selection["match_index"])])
            lines.extend(["",
                          "| Side | Unknown index | Native advisory | Reason | Source pointers |",
                          "| --- | --- | --- | --- | --- |"])
            for finding in result["explanation"]["unknown_findings"]:
                for reason in finding["reasons"]:
                    values = [finding["side"], finding["unknown_index"], finding["advisory"],
                              reason["code"], reason["sources"]]
                    lines.append("| " + " | ".join(cell(v) for v in values) + " |")
    # The appendix retains all unknown source evidence and record references in Markdown too.
    payload = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=True)
    fence = "`" * max(3, max((len(s) for s in re.findall(r"`+", payload)), default=0) + 1)
    lines.extend(["", "## Full evidence and accounting", "", fence + "json", payload, fence, ""])
    return "\n".join(lines)


def write_output(path, content, inputs):
    destination = Path(path)
    for source in inputs:
        candidate = Path(source)
        if destination.resolve() == candidate.resolve() or (destination.exists() and destination.samefile(candidate)):
            raise InputError("output: must not overwrite an input file")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                         dir=destination.parent, prefix=".vulnwrench-delta-", delete=False) as stream:
            temporary = stream.name
            stream.write(content)
        os.replace(temporary, destination)
    finally:
        if temporary is not None and os.path.exists(temporary):
            os.unlink(temporary)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vulnwrench delta", description="Compare offline Trivy or pinned Grype vulnerability evidence with CycloneDX inventories.")
    parser.add_argument("--version", action="version", version=f"vulnwrench delta {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (("compare", "build a conservative transition matrix"),
                            ("explain", "trace batch decisions and exact native unknown evidence for an advisory")):
        cmd = sub.add_parser(name, help=help_text)
        for flag in ("before", "after", "before-bom", "after-bom", "metadata"):
            cmd.add_argument("--" + flag, required=True, metavar="JSON")
        cmd.add_argument("--output", metavar="FILE", help="write atomically; default stdout")
        cmd.add_argument("--format", choices=("json", "markdown"), default="json")
        if name == "explain":
            cmd.add_argument("--advisory", required=True, metavar="ID", help="exact observed ID or explicitly declared alias")
            cmd.add_argument("--target", metavar="TARGET", help="exact normalized package target; excludes unknown explanations and native unknown selectors")
            cmd.add_argument("--package-path", metavar="PATH", help="exact normalized package path, including empty; requires --advisory and --target")
            cmd.add_argument("--side", metavar="before|after", help="report side for an unknown artifact filter; requires --artifact-id")
            cmd.add_argument("--artifact-id", metavar="ID", help="exact native unknown Grype artifact ID; requires --side; suppresses normalized explanations")
            cmd.add_argument("--reason-code", metavar="CODE", help="select whole unknown entries containing this exact adapter reason; requires --side and --artifact-id")
            cmd.add_argument("--reason-code-all", dest="reason_codes_all", action="append", metavar="CODE",
                             help="repeat to require ALL exact reasons; requires --side and --artifact-id; mutually exclusive with scalar/ANY reasons")
            cmd.add_argument("--reason-code-any", dest="reason_codes_any", action="append", metavar="CODE",
                             help="repeat to require ANY exact reason; requires --side and --artifact-id; mutually exclusive with scalar/ALL reasons")
            cmd.add_argument("--match-index", metavar="INDEX", help="zero-based native matches-array index; requires --side and --artifact-id; intersects reason selectors")
        else:
            cmd.add_argument("--fail-on", choices=("introduced",), help="exit 1 after writing evidence if newly observed findings exist")
            cmd.add_argument("--fail-on-unknown", action="store_true",
                             help="exit 3 after writing evidence for incomparability, unknown findings or row evidence blockers; overrides exit 1")
    args = parser.parse_args(argv)
    roles = ("before", "after", "before_bom", "after_bom", "metadata")
    paths = [getattr(args, role) for role in roles]
    try:
        match_index = getattr(args, "match_index", None)
        if match_index is not None:
            # Parse here so invalid values never appear in argparse diagnostics.
            if not re.fullmatch(r"[0-9]+", match_index):
                raise InputError("explain: match index must be a nonnegative integer")
            try:
                match_index = int(match_index)
            except ValueError:
                raise InputError("explain: match index is too large") from None
        documents = [load(path, role) for path, role in zip(paths, roles)]
        result = compare(*documents, explain_advisory=getattr(args, "advisory", None),
                         explain_side=getattr(args, "side", None), explain_artifact_id=getattr(args, "artifact_id", None),
                         explain_reason_code=getattr(args, "reason_code", None), explain_match_index=match_index,
                         explain_reason_codes_all=getattr(args, "reason_codes_all", None),
                         explain_reason_codes_any=getattr(args, "reason_codes_any", None),
                         explain_target=getattr(args, "target", None),
                         explain_package_path=getattr(args, "package_path", None))
        content = (markdown(result) if args.format == "markdown" else
                   json.dumps(result, indent=2, sort_keys=True, ensure_ascii=True) + "\n")
        if args.output:
            write_output(args.output, content, paths)
        else:
            try:
                sys.stdout.write(content)
                sys.stdout.flush()
            except OSError:
                # Shutdown would retry a failed buffered write and replace exit 2
                # with Python's flush-error exit 120. Discard only that failed
                # buffer; the original error still reaches the safe diagnostic.
                with open(os.devnull, "w") as sink:
                    os.dup2(sink.fileno(), sys.stdout.fileno())
                raise
        # Evaluate policy only after successful output. Include row-level inventory
        # blockers: global comparability alone does not establish consistent evidence.
        if getattr(args, "fail_on_unknown", False) and (
                not result["comparable"]
                or any(result.get("unknown_findings", {}).values())
                or any(row["reasons"] for row in result["transitions"])):
            return 3
        fail_on = getattr(args, "fail_on", None)
        return int(bool(fail_on and result["summary"].get(fail_on)))
    except InputError as exc:
        print("vulnwrench delta: " + str(exc), file=sys.stderr)
        return 2
    except (OSError, RecursionError, UnicodeError, ValueError):
        print("vulnwrench delta: input/output or JSON structure error (values omitted)", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
