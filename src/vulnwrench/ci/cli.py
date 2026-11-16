"""``vulnwrench ci`` command line. Exit 0 gate passed, 1 gate failed, 2 usage or input error."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
import shlex
import sys

from . import SCHEMA, __version__
from ..exploitgate.validation import InputError as ExploitInputError
from ..fuse import InputError as FuseInputError
from ..ignoreaudit import InputError as RuleInputError
from ..ignoreaudit.inputs import parse_date
from .core import FAIL_ON, load_baseline, load_current, load_exceptions, run

INPUT_ERRORS = (FuseInputError, RuleInputError, ExploitInputError, OSError, UnicodeError, RecursionError)

EPILOG = """\
pipeline: fuse the reports -> drop findings already in --baseline -> drop findings
covered by an unexpired --ignores rule -> gate the rest on --epss/--kev.

exit status: 0 gate passed, 1 findings at --fail-on, 2 usage or input error.
Read-only: nothing is written and no scanner or network is used.

examples:
  vulnwrench ci --trivy trivy.json --grype grype.json --osv osv.json
  vulnwrench ci --trivy trivy.json --osv osv.json --baseline main.fuse.json \\
      --ignores .trivyignore --epss epss.csv --kev kev.json --reports-unfiltered
  vulnwrench fuse merge --trivy trivy.json --osv osv.json --output main.fuse.json   # make a baseline on main
"""


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # usage errors exit 2, like the other tools
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: error: {message}\n")


def parser() -> argparse.ArgumentParser:
    cli = Parser(prog="vulnwrench ci", formatter_class=argparse.RawDescriptionHelpFormatter, epilog=EPILOG,
                 description="One CI gate over Trivy, Grype and OSV-Scanner reports: only new, unsuppressed, "
                             "exploitable findings fail, and every finding and stale exception comes with "
                             "the command that explains it.")
    cli.add_argument("--version", action="version", version=f"vulnwrench ci {__version__}")
    reports = cli.add_argument_group("scanner reports (at least one; each repeatable)")
    for scanner, label in (("trivy", "Trivy"), ("grype", "Grype"), ("osv", "OSV-Scanner")):
        reports.add_argument(f"--{scanner}", action="append", default=[], metavar="REPORT.json",
                             help=f"{label} JSON report")
    stages = cli.add_argument_group("stages (each optional)")
    stages.add_argument("--baseline", metavar="MERGED.json",
                        help="saved `vulnwrench fuse merge` output from the base branch; its findings are not new")
    stages.add_argument("--ignores", action="append", default=[], metavar="FILE",
                        help=".trivyignore (text) or osv-scanner.toml [[IgnoredVulns]]; repeatable")
    stages.add_argument("--epss", metavar="EPSS.csv", help="local EPSS snapshot (needs --kev)")
    stages.add_argument("--kev", metavar="KEV.json", help="local CISA KEV catalog snapshot (needs --epss)")
    stages.add_argument("--policy", metavar="POLICY.json",
                        help="vulnwrench exploit policy (default: KEV, or EPSS >= 0.1, snapshots at most 7 days old)")
    stages.add_argument("--aliases", metavar="ALIASES.json", help="dated alias map for findings without a CVE ID")
    gate = cli.add_argument_group("gate")
    gate.add_argument("--fail-on", choices=tuple(FAIL_ON), default="exploitable",
                      help="exploitable (default): KEV/EPSS hits; unknown: also findings without exploit data; "
                           "new: any new unsuppressed finding; none: never fail")
    gate.add_argument("--as-of", metavar="YYYY-MM-DD", help="date for expiry and snapshot freshness (default: today, UTC)")
    gate.add_argument("--reports-unfiltered", action="store_true",
                      help="assert the reports were produced without ignore files, so an exception that "
                           "matches nothing can be reported as an orphan")
    gate.add_argument("--soon-days", type=int, default=30, metavar="N",
                      help="warn about exceptions expiring within N days (default 30)")
    out = cli.add_argument_group("output")
    out.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    out.add_argument("--show", type=int, default=5, metavar="N", help="other new findings to list in text (default 5)")
    out.add_argument("--no-color", action="store_true", help="disable color (also: NO_COLOR, non-TTY stdout)")
    return cli


class Style:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        return f"\x1b[{code}m{text}\x1b[0m" if self.enabled and text else text

    def bold(self, t): return self._wrap("1", t)
    def dim(self, t): return self._wrap("2", t)
    def red(self, t): return self._wrap("31", t)
    def green(self, t): return self._wrap("32", t)
    def yellow(self, t): return self._wrap("33", t)
    def cyan(self, t): return self._wrap("36", t)


def _cmd(argv: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in argv)


def _evidence(row: dict, threshold: float | None) -> str:
    exploit = row["exploit"]
    if exploit is None:
        return "not assessed"
    if exploit["kev"]:
        return "in KEV"
    if exploit["epss"] is not None:
        return f"EPSS {exploit['epss']:.2f}"
    reasons = exploit["reasons"]
    if "no_cve_mapping" in reasons:
        return "no CVE ID"
    if any(r.endswith(("_stale", "_future")) for r in reasons):
        return "snapshot not fresh"
    return "no EPSS score" if "epss_missing" in reasons else ", ".join(reasons)


def _fix(row: dict) -> str:
    if not row["fixVersions"]:
        return "no fix reported"
    versions = ", ".join(row["fixVersions"])
    return f"fix {versions}" + (" (scanners disagree)" if row["fixConflict"] else "")


def render_text(doc: dict, s: Style, show: int) -> str:
    f, rows, out = doc["funnel"], doc["findings"], []
    threshold = doc["exploit"]["policy"]["epssThreshold"] if doc["exploit"] else None
    inputs = doc["inputs"]
    facts = [f"{f['reports']} report{'s' * (f['reports'] != 1)} ({', '.join(f['scanners'])})"]
    facts.append(f"baseline {inputs['baseline']}" if inputs["baseline"] else "no baseline")
    facts.append(f"{len(inputs['ignores'])} exception file{'s' * (len(inputs['ignores']) != 1)}")
    facts.append(f"as of {doc['asOf']}")
    out += [s.bold("vulnwrench ci") + "  " + s.dim(" · ".join(facts)), ""]

    def stage(number, text, removed=""):
        out.append(f"  {s.bold(f'{number:>4}')}  {text:<52}{s.dim(removed)}".rstrip())

    out.append(s.bold("Noise funnel"))
    stage(f["rawFindings"], f"raw findings from {len(f['scanners'])} scanner{'s' * (len(f['scanners']) != 1)}")
    stage(f["fused"], "unique after fuse (same package + advisory alias)", f"-{f['rawFindings'] - f['fused']} duplicates")
    if inputs["baseline"]:
        stage(f["new"], "new since the baseline", f"-{f['baselineKnown']} already in baseline")
    if inputs["ignores"]:
        stage(f["unsuppressed"], "not covered by an unexpired exception", f"-{f['suppressed']} suppressed")
    if doc["exploit"]:
        stage(f["needAction"], f"exploitable: in KEV or EPSS >= {threshold:g}",
              f"-{f['low']} below threshold, -{f['unknown']} no exploit data")
    else:
        stage(f["needAction"], "need action (no --epss/--kev: not filtered)")

    def finding(row, mark, colour):
        scanners = ", ".join(row["scanners"])
        out.append(f"  {mark} {s.bold(row['package'])}  {colour(row['advisory'])}  {row['severity'] or 'severity ?'}"
                   f"  {colour(_evidence(row, threshold))}  {s.dim(_fix(row))}")
        detail = f"seen by {scanners}" + (f" · {row['paths'][0]}" if row["paths"] else "")
        if row["expiredExceptions"]:
            detail += " · exception expired: " + ", ".join(row["expiredExceptions"])
        out.append("     " + s.dim(detail))
        out.append("     " + s.cyan(_cmd(row["command"])))

    action = [r for r in rows if r["outcome"] == "action"]
    unknown = [r for r in rows if r["outcome"] == "unknown"]
    low = [r for r in rows if r["outcome"] == "low"]
    for name in doc["gate"]["staleSnapshots"]:
        snap = doc["exploit"]["snapshots"][name]
        out.append(s.yellow(f"  ! {name.upper()} snapshot is {snap['status']} ({snap['date']}, max age "
                            f"{doc['exploit']['policy']['maxAgeDays']} days): findings without exploit data fail the gate"))
    out += ["", s.bold(f"Needs action ({len(action)})")]
    if not action:
        out.append("  " + s.green("Nothing new and exploitable."))
    for row in action:
        finding(row, s.red("✗"), s.red)
    if unknown:
        out += ["", s.bold(f"No exploit data ({len(unknown)})")
                + s.dim("  map non-CVE IDs with --aliases, refresh old snapshots, or review by hand")]
        for row in unknown:
            finding(row, s.yellow("?"), s.yellow)
    if doc["staleExceptions"]:
        out += ["", s.bold(f"Stale exceptions ({len(doc['staleExceptions'])})")]
        for item in doc["staleExceptions"]:
            out.append(f"  {s.yellow('!')} {s.bold(item['file'] + ' ' + item['key'])}  {item['rule']}  "
                       + s.yellow(_stale_text(item, rows)))
            if item["command"]:
                out.append("     " + s.cyan(_cmd(item["command"])))
    hygiene = doc["exceptionHygiene"]
    if hygiene["missingOwner"]:
        out.append(s.dim(f"  {hygiene['missingOwner']} of {hygiene['rules']} exceptions name no owner: "
                         "`vulnwrench triage` keeps owner, reason and expiry in one decision file."))
    if hygiene["unverifiedOrphans"]:
        out.append(s.dim(f"  {hygiene['unverifiedOrphans']} exception(s) match nothing here; add --reports-unfiltered "
                         "if the scanners ran without ignore files to report them as orphans."))
    if low:
        out += ["", s.bold(f"New but below the exploit threshold ({len(low)})") + s.dim("  not gated")]
        for row in low[:max(show, 0)]:
            out.append(s.dim(f"  · {row['package']}  {row['advisory']}  {row['severity'] or '?'}  "
                             f"{_evidence(row, threshold)}  {_fix(row)}"))
        if len(low) > show:
            out.append(s.dim(f"  … {len(low) - show} more in --format json"))
    if doc["baselineGone"]:
        out += ["", s.dim(f"{len(doc['baselineGone'])} baseline finding(s) are no longer reported. Not reported is not "
                          "fixed: confirm upgrades with `vulnwrench delta compare` and both SBOMs.")]
    out.append("")
    gate = doc["gate"]
    head = s.red if f["needAction"] else s.green
    out.append(f"{f['rawFindings']} raw findings from {len(f['scanners'])} scanner{'s' * (len(f['scanners']) != 1)} -> "
               + head(f"{f['needAction']} need{'s' * (f['needAction'] == 1)} action") + ".")
    verdict = s.red(f"FAIL (exit 1, {gate['failing']} finding{'s' * (gate['failing'] != 1)})") if gate["exitCode"] \
        else s.green("pass (exit 0)")
    out.append(f"--fail-on {gate['failOn']}: {verdict}")
    return "\n".join(out) + "\n"


def _stale_text(item: dict, rows: list[dict]) -> str:
    outcome = {r["findingId"]: r for r in rows}
    parts = []
    status = item["status"]
    if "expired" in status:
        parts.append(f"expired {item['expires']}")
        hits = [outcome[i] for i in item["matches"] if i in outcome]
        if hits:
            parts.append("no longer suppresses " + ", ".join(f"{r['package']} ({_label(r)})" for r in hits))
    if "soon_expiring" in status:
        parts.append(f"expires in {item['daysUntilExpiry']} day{'s' * (item['daysUntilExpiry'] != 1)}")
        hits = [outcome[i] for i in item["matches"] if i in outcome and outcome[i]["outcome"] == "suppressed"]
        if hits:
            parts.append("then unhides " + ", ".join(f"{r['package']} ({_evidence(r, None)})" for r in hits))
    if "orphan_candidate" in status:
        parts.append("matches nothing in these reports")
    if "overly_broad" in status:
        parts.append(f"matches {len(item['matches'])} packages")
    if "duplicate" in status:
        parts.append("duplicate rule")
    return "; ".join(parts)


def _label(row: dict) -> str:
    return {"baseline": "already in baseline", "action": "now blocking", "unknown": "now unassessed",
            "low": "now below threshold", "suppressed": "still suppressed elsewhere"}[row["outcome"]]


def render_sarif(doc: dict) -> dict:
    levels = {"action": "error", "unknown": "warning", "low": "note"}
    results, rules = [], {}
    for row in doc["findings"]:
        if row["outcome"] not in levels:
            continue
        rules.setdefault(row["advisory"], {"id": row["advisory"], "shortDescription": {"text": row["advisory"]}})
        result = {"ruleId": row["advisory"], "level": levels[row["outcome"]],
                  "message": {"text": f"{row['package']}: {row['advisory']} ({row['severity'] or 'unknown severity'}; "
                                      f"{_evidence(row, None)}; {_fix(row)}; seen by {', '.join(row['scanners'])})"},
                  "partialFingerprints": {"vulnwrench/package-advisory": f"{row['package']}|{row['advisory']}"},
                  "properties": {"outcome": row["outcome"], "ids": row["ids"]}}
        if row["paths"]:
            result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": row["paths"][0].lstrip("/")}}}]
        results.append(result)
    driver = {"name": "vulnwrench ci", "version": __version__, "informationUri": "https://github.com/tianhaogutum/vulnwrench",
              "rules": sorted(rules.values(), key=lambda r: r["id"])}
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": driver}, "results": results}]}


def _use_color(args) -> bool:
    if args.no_color or args.format != "text" or os.environ.get("NO_COLOR"):
        return False
    try:
        return sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


def main(argv: list[str] | None = None) -> int:
    cli = parser()
    args = cli.parse_args(argv)
    scanner_args = [(scanner, path) for scanner in ("trivy", "grype", "osv") for path in getattr(args, scanner)]
    if not scanner_args:
        cli.error("give at least one report: --trivy, --grype or --osv")
    if (args.epss is None) != (args.kev is None):
        cli.error("--epss and --kev go together")
    if (args.policy or args.aliases) and args.epss is None:
        cli.error("--policy and --aliases need --epss and --kev")
    if args.soon_days < 0:
        cli.error("--soon-days must be >= 0")
    try:
        as_of = parse_date(args.as_of, "--as-of") if args.as_of else datetime.now(timezone.utc).date()
        current = load_current(scanner_args)
        result = run(current, load_baseline(args.baseline), load_exceptions(args.ignores), as_of=as_of,
                     scanner_args=scanner_args, unfiltered=args.reports_unfiltered, soon_days=args.soon_days,
                     epss=args.epss, kev=args.kev, policy=args.policy, aliases=args.aliases, fail_on=args.fail_on)
    except INPUT_ERRORS as exc:
        print(f"vulnwrench ci: {exc}", file=sys.stderr)
        return 2
    doc = {"schema": SCHEMA, "vulnwrench_version": __version__, "asOf": as_of.isoformat(),
           "inputs": {"reports": [{"scanner": r.scanner, "input": r.input_name, "sha256": r.sha256} for r in current],
                      "baseline": args.baseline, "ignores": args.ignores, "epss": args.epss, "kev": args.kev,
                      "policy": args.policy, "aliases": args.aliases, "reportsUnfiltered": args.reports_unfiltered},
           **result}
    try:
        if args.format == "json":
            sys.stdout.write(json.dumps(doc, ensure_ascii=False, indent=2) + "\n")
        elif args.format == "sarif":
            sys.stdout.write(json.dumps(render_sarif(doc), ensure_ascii=False, indent=2) + "\n")
        else:
            sys.stdout.write(render_text(doc, Style(_use_color(args)), args.show))
        sys.stdout.flush()
    except BrokenPipeError:
        try:
            sys.stdout = open(os.devnull, "w")
        except OSError:
            pass
    return doc["gate"]["exitCode"]


__all__ = ["main", "parser"]

if __name__ == "__main__":
    raise SystemExit(main())
