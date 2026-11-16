"""Offline CLI. Input errors are redacted and outputs never overwrite inputs."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import tempfile

from . import __version__
from .audit import audit, markdown
from .cleanup import cleanup_markdown, cleanup_plan
from .explain import explain
from .inputs import apply_metadata, digest, load_aliases, load_report, load_rules, parse_date, read_bytes
from .model import InputError
from .verification import verify_cleanup_alias_map, verify_cleanup_inputs, verify_cleanup_metadata, verify_cleanup_plan_identity, verify_cleanup_report, verify_cleanup_source


def parser():
    root = argparse.ArgumentParser(prog="vulnwrench ignores", description="Offline exception audit against an explicitly unfiltered report.")
    root.add_argument("--version", action="version", version=f"vulnwrench ignores {__version__}")
    commands = root.add_subparsers(dest="command", required=True)
    for name, help_text in (("audit", "read rules and native JSON; emit an audit without modifying rules"),
                            ("explain", "explain one rule with per-observation evidence (JSON)"),
                            ("cleanup-plan", "export grouped manual cleanup suggestions without modifying rules (JSON or Markdown)")):
        cmd = commands.add_parser(name, help=help_text)
        add_input_arguments(cmd, name)
    verify_plan = commands.add_parser("verify-cleanup-plan-identity", help="verify externally pinned raw plan identity and supported envelope only; no input verification or semantic approval")
    verify_plan.add_argument("--plan", required=True, help="JSON cleanup-plan export (schemaVersion 1)")
    verify_plan.add_argument("--expected-plan-sha256", required=True, help="independently recorded 64 lowercase hexadecimal digest of complete plan bytes; identity only, not authentication")
    verify_plan.add_argument("--output", help="JSON output file; default stdout; never an input path")
    verify = commands.add_parser("verify-cleanup-source", help="verify retained JSON cleanup-plan source identity without modifying inputs")
    verify.add_argument("--plan", required=True, help="JSON cleanup-plan export (schemaVersion 1)")
    verify.add_argument("--expected-plan-sha256", help="externally recorded 64 lowercase hexadecimal digest of complete plan bytes; identity pin only")
    verify.add_argument("--rules", required=True, help="complete retained original rules bytes")
    verify.add_argument("--output", help="JSON output file; default stdout; never an input path")
    verify_report = commands.add_parser("verify-cleanup-report", help="verify retained JSON cleanup-plan report identity without attesting coverage")
    verify_report.add_argument("--plan", required=True, help="JSON cleanup-plan export (schemaVersion 1)")
    verify_report.add_argument("--expected-plan-sha256", help="externally recorded 64 lowercase hexadecimal digest of complete plan bytes; identity pin only")
    verify_report.add_argument("--report", required=True, help="complete retained original native report bytes")
    verify_report.add_argument("--output", help="JSON output file; default stdout; never an input path")
    verify_alias_map = commands.add_parser("verify-cleanup-alias-map", help="verify retained explicit local alias-map identity without re-evaluating matches")
    verify_alias_map.add_argument("--plan", required=True, help="JSON cleanup-plan export (schemaVersion 1)")
    verify_alias_map.add_argument("--expected-plan-sha256", help="externally recorded 64 lowercase hexadecimal digest of complete plan bytes; identity pin only")
    verify_alias_map.add_argument("--alias-map", required=True, help="complete retained original explicit local alias-map bytes")
    verify_alias_map.add_argument("--output", help="JSON output file; default stdout; never an input path")
    verify_metadata = commands.add_parser("verify-cleanup-metadata", help="verify retained rules/metadata identity without authenticating annotations or plan decisions")
    verify_metadata.add_argument("--plan", required=True, help="JSON cleanup-plan export (schemaVersion 1)")
    verify_metadata.add_argument("--expected-plan-sha256", help="externally recorded 64 lowercase hexadecimal digest of complete plan bytes; identity pin only")
    verify_metadata.add_argument("--rules", required=True, help="complete retained original native rules bytes")
    verify_metadata.add_argument("--metadata", required=True, help="complete retained original hash-bound metadata sidecar bytes")
    verify_metadata.add_argument("--output", help="JSON output file; default stdout; never an input path")
    verify_inputs = commands.add_parser("verify-cleanup-inputs", help="verify all retained cleanup inputs and native source references without re-auditing")
    verify_inputs.add_argument("--plan", required=True, help="JSON cleanup-plan export (schemaVersion 1)")
    verify_inputs.add_argument("--expected-plan-sha256", help="externally recorded 64 lowercase hexadecimal digest of complete plan bytes; identity pin only")
    verify_inputs.add_argument("--rules", required=True, help="complete retained original native rules bytes")
    verify_inputs.add_argument("--report", required=True, help="complete retained original native report bytes")
    verify_inputs.add_argument("--metadata", help="complete retained sidecar; required exactly when bound in provenance")
    verify_inputs.add_argument("--alias-map", help="complete retained map; required exactly for explicit_local_groups provenance")
    verify_inputs.add_argument("--output", help="JSON output file; default stdout; never an input path")
    return root


def add_input_arguments(cmd, command):
    if command == "explain":
        cmd.add_argument("--rule-key", required=True, help="exact locator, e.g. line:2 or IgnoredVulns:0; advisory IDs are not locators")
    cmd.add_argument("--format", required=True, choices=("trivy", "osv", "grype"), help="Grype is recognized only to provide an explicit unsupported-format error")
    cmd.add_argument("--rules", required=True)
    cmd.add_argument("--report", required=True)
    cmd.add_argument("--report-unfiltered", action="store_true", help="assert no ignore, severity, VEX, path or other filtering removed vulnerability observations")
    cmd.add_argument("--as-of", help="YYYY-MM-DD; default is today's UTC date")
    cmd.add_argument("--soon-days", type=int, default=30)
    cmd.add_argument("--metadata", help="hash-bound JSON owner/reason sidecar")
    cmd.add_argument("--alias-map", help="explicit local alias groups; report aliases alone never imply equivalence")
    cmd.add_argument("--osv-config-dir", help="exact POSIX directory for local OSV config scope; omit only for a global --config override")
    cmd.add_argument("--output-format", choices=("json",) if command == "explain" else ("json", "markdown"), default="json")
    cmd.add_argument("--output", help="output file; default stdout; never an input path")


def _write_output(path, value, inputs):
    dest = Path(path)
    # Resolve both symlinks and hardlinks before writing. Atomic replace avoids a partial output.
    if dest.is_symlink() or any(dest.resolve() == Path(item).resolve() or
                             (dest.exists() and os.path.samefile(dest, item)) for item in inputs):
        raise InputError("output must not alias an input file or be a symlink")
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=dest.parent, prefix=".vulnwrench-ignores-", delete=False) as stream:
            tmp = stream.name
            stream.write(value)
        os.replace(tmp, dest)
    finally:
        if tmp and os.path.exists(tmp):
            os.unlink(tmp)


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "verify-cleanup-plan-identity":
            inputs = [args.plan]
            result = verify_cleanup_plan_identity(read_bytes(args.plan), expected_plan_sha256=args.expected_plan_sha256)
        elif args.command == "verify-cleanup-source":
            inputs = [args.plan, args.rules]
            result = verify_cleanup_source(read_bytes(args.plan), read_bytes(args.rules),
                                           expected_plan_sha256=args.expected_plan_sha256)
        elif args.command == "verify-cleanup-report":
            inputs = [args.plan, args.report]
            result = verify_cleanup_report(read_bytes(args.plan), read_bytes(args.report),
                                           expected_plan_sha256=args.expected_plan_sha256)
        elif args.command == "verify-cleanup-alias-map":
            inputs = [args.plan, args.alias_map]
            result = verify_cleanup_alias_map(read_bytes(args.plan), read_bytes(args.alias_map),
                                              expected_plan_sha256=args.expected_plan_sha256)
        elif args.command == "verify-cleanup-metadata":
            inputs = [args.plan, args.rules, args.metadata]
            result = verify_cleanup_metadata(read_bytes(args.plan), read_bytes(args.rules), read_bytes(args.metadata),
                                             expected_plan_sha256=args.expected_plan_sha256)
        elif args.command == "verify-cleanup-inputs":
            inputs = [args.plan, args.rules, args.report]
            raw_plan, raw_rules, raw_report = read_bytes(args.plan), read_bytes(args.rules), read_bytes(args.report)
            raw_metadata = raw_aliases = None
            if args.metadata is not None:
                inputs.append(args.metadata)
                raw_metadata = read_bytes(args.metadata)
            if args.alias_map is not None:
                inputs.append(args.alias_map)
                raw_aliases = read_bytes(args.alias_map)
            result = verify_cleanup_inputs(raw_plan, raw_rules, raw_report, raw_metadata, raw_aliases,
                                           expected_plan_sha256=args.expected_plan_sha256)
        else:
            if args.format == "grype":
                raise InputError("Grype YAML/JSON is unsupported; provide Trivy .trivyignore + native JSON or OSV IgnoredVulns TOML + native JSON")
            if not args.report_unfiltered:
                raise InputError("--report-unfiltered acknowledgment is required; do not use filtered scanner output")
            as_of = parse_date(args.as_of) if args.as_of else datetime.now(timezone.utc).date()
            if Path(args.rules).suffix.lower() in {".yaml", ".yml", ".json"}:
                raise InputError("unsupported rule file format; use .trivyignore text or OSV TOML, not YAML/JSON")
            raw_rules, raw_report = read_bytes(args.rules), read_bytes(args.report)
            rules = load_rules(raw_rules, args.format, args.osv_config_dir)
            report = load_report(raw_report, args.format, report_unfiltered=True)
            inputs = [args.rules, args.report]
            provenance = {"format": args.format, "rulesSha256": digest(raw_rules), "reportSha256": digest(raw_report),
                          "ruleScope": "local_config_directory" if args.osv_config_dir else "global",
                          "aliases": "exact_ids_only"}
            if args.metadata:
                raw_metadata = read_bytes(args.metadata)
                rules = apply_metadata(rules, raw_metadata, digest(raw_rules))
                inputs.append(args.metadata)
                provenance["metadataSha256"] = digest(raw_metadata)
            aliases = None
            if args.alias_map:
                raw_aliases = read_bytes(args.alias_map)
                aliases = load_aliases(raw_aliases)
                inputs.append(args.alias_map)
                provenance.update(aliases="explicit_local_groups", aliasMapSha256=digest(raw_aliases))
            options = dict(as_of=as_of, report_unfiltered=True, soon_days=args.soon_days, aliases=aliases)
            result = (explain(rules, report, args.rule_key, **options) if args.command == "explain" else
                      audit(rules, report, **options))
            result["provenance"] = provenance
            if args.command == "cleanup-plan":
                result = cleanup_plan(result, raw_rules, args.format)
        if getattr(args, "output_format", "json") == "json":
            output = json.dumps(result, indent=2, ensure_ascii=True, sort_keys=True) + "\n"
        else:
            output = cleanup_markdown(result) if args.command == "cleanup-plan" else markdown(result)
        if args.output:
            _write_output(args.output, output, inputs)
        else:
            sys.stdout.write(output)
        return 0
    except InputError as exc:
        print("vulnwrench ignores: " + str(exc), file=sys.stderr)
        return 2
    except (OSError, UnicodeError, RecursionError):
        print("vulnwrench ignores: I/O or input nesting error (details withheld)", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
