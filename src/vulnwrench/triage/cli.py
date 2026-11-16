"""Command line entry point. Diagnostics never interpolate input values."""
from __future__ import annotations

import argparse
import json
import sys

from . import (BridgeError, __version__, compile_decisions, finalize_import, load_document,
               load_trivy_ignore, preview_renewal, verify_report_artifacts, verify_report_source,
               write_compilation)
from .compiler import json_bytes
from .import_markdown import render_import_markdown
from .io import _read_input
from .renewal_markdown import render_renewal_markdown


class Parser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's normal errors echo unknown arguments, potentially secrets.
        self.exit(2, "vulnwrench triage: E_ARGUMENT: invalid command line; use --help\n")


def main(argv: list[str] | None = None) -> int:
    parser = Parser(prog="vulnwrench triage", description="Offline decision projections with explicit scope loss and VEX semantics.")
    parser.add_argument("--version", action="version", version=f"vulnwrench triage {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, parser_class=Parser)
    compile_parser = sub.add_parser("compile", help="compile strict JSON decisions into a new directory or validate with --dry-run")
    compile_parser.add_argument("input", help="regular UTF-8 JSON decisions file")
    compile_parser.add_argument("--as-of", required=True, help="YYYY-MM-DD UTC expiry check; expiresOn must be later")
    compile_parser.add_argument("--author", required=True, help="individual or organization issuing the OpenVEX document")
    compile_parser.add_argument("--product-id", required=True, help="absolute product IRI; packages become subcomponents")
    compile_parser.add_argument("--timestamp", required=True, help="RFC3339 issuance time; UTC date must equal --as-of")
    compile_output = compile_parser.add_mutually_exclusive_group(required=True)
    compile_output.add_argument("--out-dir", help="new directory in an existing nonsymlink parent; no overwrites")
    compile_output.add_argument("--dry-run", action="store_true",
                                help="validate and generate artifacts in memory; print the complete report without writing files")
    compile_parser.add_argument("--allow-scope-loss", action="store_true", help="explicitly allow OSV's package-to-global ID widening")
    renewal_parser = sub.add_parser("preview-renewal", help="print a review-only plan; never renew or compile exceptions")
    renewal_parser.add_argument("prior", help="regular prior decisions or conversion report file; every record needs a stable decisionId")
    renewal_parser.add_argument("--prior-format", choices=("decisions", "conversion-report"), default="decisions",
                                help="baseline format (default: decisions); reports are strictly validated")
    renewal_parser.add_argument("--current", help="optional regular current v1 decision JSON file; missing owners become review findings")
    renewal_parser.add_argument("--verify-artifacts", metavar="DIR",
                                help="opt-in saved payload byte verification; requires conversion-report baseline")
    renewal_parser.add_argument("--verify-source", metavar="FILE",
                                help="opt-in original v1 JSON digest and archived compilation verification; requires regular file and conversion-report baseline")
    renewal_parser.add_argument("--prior-as-of", help="UTC baseline date; required for decisions, must match asOf for reports")
    renewal_parser.add_argument("--as-of", required=True, help="YYYY-MM-DD UTC review date; must not precede the baseline")
    renewal_parser.add_argument("--expiring-within-days", type=int, default=30, help="inclusive review horizon, 0–3660 days (default: 30)")
    renewal_parser.add_argument("--fail-on-review", action="store_true",
                                help="exit 1 after printing the complete plan if any decision requires human review")
    renewal_parser.add_argument("--format", choices=("json", "markdown"), default="json",
                                help="review plan output format (default: json); Markdown includes full source records")
    import_parser = sub.add_parser("import-trivy", help="print decision drafts from supported native Trivy ignore YAML; requires human review")
    import_parser.add_argument("input", help="regular native Trivy ignore file; JSON-flow or documented restricted block YAML")
    import_parser.add_argument("--fail-on-unsupported", action="store_true",
                               help="exit 1 after printing the complete draft if any unsupported findings exist; never approves drafts")
    import_parser.add_argument("--format", choices=("json", "markdown"), default="json",
                               help="draft output format (default: json); Markdown includes full copied draft data")
    finalize_parser = sub.add_parser("finalize-import", help="validate explicit native-import review and print decisions with source references")
    finalize_parser.add_argument("draft", help="regular unmodified import-trivy JSON draft report")
    finalize_parser.add_argument("--source", required=True, help="regular original native Trivy file; raw bytes must match the draft")
    finalize_parser.add_argument("--review", required=True, help="regular JSON review: decisionDocument, unsupportedDispositions, and approvedDecisionIndices or decisionDispositions")
    finalize_parser.add_argument("--as-of", required=True, help="YYYY-MM-DD UTC validation date; expiresOn must be later")
    args = parser.parse_args(argv)
    try:
        if args.command == "finalize-import":
            document = finalize_import(load_document(args.draft, regular_only=True),
                                       source=_read_input(args.source, regular_only=True),
                                       review=load_document(args.review, regular_only=True), as_of=args.as_of)
            sys.stdout.write(json_bytes(document).decode("utf-8"))
            return 0
        if args.command == "import-trivy":
            draft = load_trivy_ignore(args.input, regular_only=True)
            output = (render_import_markdown(draft) if args.format == "markdown"
                      else json_bytes(draft).decode("utf-8"))
            sys.stdout.write(output)
            sys.stdout.flush()
            return int(args.fail_on_unsupported and draft["counts"]["unsupported"] != 0)
        if args.command == "preview-renewal":
            if ((args.verify_artifacts is not None or args.verify_source is not None)
                    and args.prior_format != "conversion-report"):
                parser.error("verification requires an explicit conversion report")
            prior = load_document(args.prior, regular_only=True)
            current = {"current": load_document(args.current, regular_only=True)} if args.current is not None else {}
            plan = preview_renewal(prior, prior_as_of=args.prior_as_of,
                                   as_of=args.as_of, prior_format=args.prior_format,
                                   expiring_within_days=args.expiring_within_days, **current)
            if args.verify_source is not None:
                plan["sourceVerification"] = verify_report_source(prior, load_document(args.verify_source, regular_only=True))
            if args.verify_artifacts is not None:
                plan["artifactVerification"] = verify_report_artifacts(prior, args.verify_artifacts)
            output = (render_renewal_markdown(plan) if args.format == "markdown"
                      else json_bytes(plan).decode("utf-8"))
            sys.stdout.write(output)
            sys.stdout.flush()
            return int(args.fail_on_review and plan["counts"]["reviewRequired"] != 0)
        result = compile_decisions(load_document(args.input, regular_only=True), as_of=args.as_of, author=args.author,
                                   product_id=args.product_id, timestamp=args.timestamp,
                                   allow_scope_loss=args.allow_scope_loss)
        if args.dry_run:
            sys.stdout.write(result.files["conversion-report.json"].decode("utf-8"))
            sys.stdout.flush()
            return 0
        write_compilation(result, args.out_dir)
    except BridgeError as exc:
        print(f"vulnwrench triage: {exc.code}: {exc}", file=sys.stderr)
        return 2
    except (RecursionError, UnicodeError):
        print("vulnwrench triage: E_INPUT: unsupported input encoding or nesting", file=sys.stderr)
        return 2
    print(json.dumps({"files": sorted(result.files), "counts": result.report["counts"],
                      "losses": len(result.report["losses"])}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
