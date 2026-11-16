# vulnwrench ci

Run Trivy, Grype and OSV-Scanner in CI and the job log fills with hundreds of lines:
the same vulnerability under three IDs, findings that were already on `main`, findings
someone already accepted, and findings nobody will ever exploit. The few that matter are
easy to miss. Meanwhile exceptions in `.trivyignore` expire or go stale without anyone
noticing.

`vulnwrench ci` is one gate over the reports you already have. It fuses them, drops what is
already in the base branch's baseline, applies your exception files, and gates what is
left on local EPSS and CISA KEV snapshots. It prints one report: the new, unsuppressed,
exploitable findings, the stale exceptions, and the exact command that explains each one.
It reads local files only; it never runs a scanner, writes a file or uses the network.

## Quick start

```sh
pip install vulnwrench
cd examples/ci      # synthetic fixtures, see examples/ci/README.md
vulnwrench ci --trivy trivy.json --grype grype.json --osv osv.json \
  --baseline baseline.json --ignores .trivyignore --ignores osv-scanner.toml \
  --epss epss.csv --kev kev.json --as-of 2026-11-12 --reports-unfiltered
```

Real output (recorded in [`benchmarks/ci/report.txt`](../benchmarks/ci/report.txt)):

```text
Noise funnel
    37  raw findings from 3 scanners
    14  unique after fuse (same package + advisory alias)   -23 duplicates
     8  new since the baseline                              -6 already in baseline
     6  not covered by an unexpired exception               -2 suppressed
     2  exploitable: in KEV or EPSS >= 0.1                  -3 below threshold, -1 no exploit data

Needs action (2)
  ✗ pkg:npm/acme-router@4.2.0  CVE-2099-2001  HIGH  in KEV  fix 4.2.3
     seen by grype, osv, trivy · package-lock.json
     vulnwrench fuse explain --trivy trivy.json --grype grype.json --osv osv.json --advisory CVE-2099-2001 --package pkg:npm/acme-router@4.2.0
  ...
Stale exceptions (3)
  ! .trivyignore line:2  CVE-2099-1004  expired 2026-10-31; no longer suppresses pkg:pypi/acme-xml@0.9.1 (already in baseline)
  ! .trivyignore line:3  CVE-2099-2006  expires in 18 days; then unhides pkg:pypi/acme-zip@3.3.3 (EPSS 0.71)
  ! .trivyignore line:4  CVE-2099-0777  matches nothing in these reports
  ...
37 raw findings from 3 scanners -> 2 need action.
--fail-on exploitable: FAIL (exit 1, 2 findings)
```

`python3 scripts/ci/verify_examples.py` reruns the example, the baseline merge and all
three output formats and compares them with the recordings in
[`benchmarks/ci/`](../benchmarks/ci/). The data is synthetic: fictional packages and
advisory IDs, so the ratio says what the pipeline removes on this example, not what it
will remove on your repository.

## In a pipeline

On the base branch, save the fused scan as the baseline (keep it as a CI artifact or cache):

```sh
vulnwrench fuse merge --trivy trivy.json --grype grype.json --osv osv.json --output baseline.json
```

On every pull request, gate against it:

```sh
vulnwrench ci --trivy trivy.json --grype grype.json --osv osv.json --baseline baseline.json \
  --ignores .trivyignore --epss epss.csv --kev known_exploited_vulnerabilities.json \
  --format sarif > vulnwrench.sarif
```

Download the EPSS CSV and KEV JSON in a separate step (`ci` never fetches them), and run
the scanners without their own ignore files if you pass `--reports-unfiltered`.

## Pipeline

Each stage is an existing vulnwrench library, called directly; `ci` adds no matching or
scoring rules of its own.

| Stage | Library call | What it removes |
| --- | --- | --- |
| Fuse | `vulnwrench.fuse.merge_reports` | Duplicates: one finding per exact package identity and alias component (Trivy CVE, Grype GHSA with `relatedVulnerabilities`, OSV `aliases`) |
| Baseline | the same `merge_reports` call over the current reports **and** the reports embedded in `--baseline` (read with `vulnwrench.fuse.read_merged`) | Findings that have an observation in a baseline source. Baseline-only findings are counted as "no longer reported" |
| Exceptions | `vulnwrench.ignoreaudit.load_rules` and `audit`, once per `--ignores` file | Findings with an observation whose exact ID is named by an unexpired rule. The same audit reports expired, soon-expiring, orphaned, duplicate and over-broad rules |
| Exploitability | `vulnwrench.exploitgate.evaluate_findings` (the policy engine behind `vulnwrench exploit check`) | Findings whose CVEs are not in KEV and score below the EPSS threshold |

Each current finding ends with exactly one outcome:

| Outcome | Meaning | Fails with `--fail-on` |
| --- | --- | --- |
| `action` | New, not suppressed, and in KEV or at/above the EPSS threshold (or not assessed because no `--epss`/`--kev` was given) | `exploitable` (default), `unknown`, `new` |
| `unknown` | New, not suppressed, but no fresh exploit data: no CVE ID, no EPSS score, or a stale snapshot | `unknown`, `new` |
| `low` | New, not suppressed, below the threshold | `new` |
| `suppressed` | New, but an unexpired exception covers it | never |
| `baseline` | Already observed in the baseline | never |

`--fail-on none` never fails. If the EPSS or KEV snapshot is older than the policy's
`maxAgeDays` (or dated after `--as-of`), `unknown` findings fail the gate too, so a
forgotten feed download cannot turn the gate green.

## Options

| Option | Default | Notes |
| --- | --- | --- |
| `--trivy`, `--grype`, `--osv` | | At least one; each repeatable. The same profiles as `vulnwrench fuse` |
| `--baseline FILE` | none | A saved `vulnwrench fuse merge` file; it is fully revalidated before use |
| `--ignores FILE` | none | Repeatable. `*.toml` is read as `osv-scanner.toml` `[[IgnoredVulns]]`, anything else as `.trivyignore` text (`ID [exp:YYYY-MM-DD]`) |
| `--epss`, `--kev` | none | Both or neither. Without them every new, unsuppressed finding needs action |
| `--policy FILE` | KEV, or EPSS >= 0.1, snapshots at most 7 days old | A [`vulnwrench exploit`](exploit.md) policy file. Its `unknownIsFailure` is ignored: `--fail-on` decides |
| `--aliases FILE` | none | Dated alias map for exploitability lookups, as in `vulnwrench exploit` |
| `--fail-on` | `exploitable` | `exploitable`, `unknown`, `new` or `none` |
| `--as-of YYYY-MM-DD` | today (UTC) | Exception expiry and snapshot freshness |
| `--reports-unfiltered` | off | Asserts the scanners ran without ignore files. Only then is a rule that matches nothing reported as an orphan |
| `--soon-days N` | 30 | Window for "expires in N days" |
| `--format` | `text` | `text`, `json` (`vulnwrench.ci/v1`) or `sarif` (2.1.0) |
| `--show N` | 5 | Below-threshold findings listed in text output |

Exit status: `0` gate passed, `1` findings at `--fail-on`, `2` usage or input error (a
missing or malformed report, baseline, exception file, snapshot or date). Errors never
echo file contents.

## Output

The text report has a noise funnel, then "Needs action", "No exploit data", "Stale
exceptions", "New but below the exploit threshold" and a two-line verdict. Every finding
line carries the package identity, the preferred advisory ID (a CVE when one is known),
the highest reported severity, the exploit evidence and the reported fix versions,
flagged when scanners disagree. The follow-up commands are:

- `vulnwrench fuse explain ... --advisory ID --package PURL` for a finding: every
  observation, alias edge and severity/fix conflict behind it.
- `vulnwrench ignores explain ... --rule-key KEY` for an expired or soon-expiring rule, and
  `vulnwrench ignores cleanup-plan ...` for an orphan. They use the first report of the
  rule's format (`--trivy` for `.trivyignore`, `--osv` for `osv-scanner.toml`).

`--format json` keeps everything: the funnel, one record per current finding (IDs,
scanners, paths, outcome, the exploit decision and its reasons, the exceptions that
suppress it or expired on it, the follow-up command as an argument list), baseline-only
findings, stale exceptions, exception hygiene counts, the exploit policy and snapshot
provenance, and the gate. `--format sarif` emits one result per new, unsuppressed finding:
`error` for `action`, `warning` for `unknown`, `note` for `low`.

## Limits

- **A changed version is a different package.** Fuse identities include the version, so
  `acme-qs@6.0.0` in the baseline and `acme-qs@6.0.1` now are two findings: one "no longer
  reported", one new. To tell "still affected after the upgrade" from a new finding, run
  [`vulnwrench delta compare`](delta.md) with both CycloneDX inventories.
- **Not reported is not fixed.** Baseline findings that disappeared may have been fixed,
  removed, or simply not scanned. `ci` counts them and says so; `delta` can prove a fix.
- **Exceptions match exact IDs.** A rule suppresses a fused finding when its ID equals the
  original ID of one of the finding's observations, from any scanner. Rules are not
  expanded through aliases, and `.trivyignore.yaml` and Grype ignore rules are not read.
  To keep one decision file for all scanners, see [`vulnwrench triage`](triage.md).
- **Exploit data is what you supply.** EPSS is a probability, KEV is a list of observed
  exploitation; neither says your code path is reachable. A finding below the threshold
  is listed, not dismissed.
- Severity is the highest value any scanner reported; the per-scanner values stay in JSON.

## Library

```python
from datetime import date
from vulnwrench.ci.core import load_baseline, load_current, load_exceptions, run

reports = [("trivy", "trivy.json"), ("osv", "osv.json")]
result = run(load_current(reports), load_baseline("baseline.json"), load_exceptions([".trivyignore"]),
             as_of=date(2026, 11, 12), scanner_args=reports, epss="epss.csv", kev="kev.json")
print(result["funnel"], result["gate"]["exitCode"])
```

Tests: `tests/ci/test_ci.py`. Fixtures: [`examples/ci/`](../examples/ci/).
