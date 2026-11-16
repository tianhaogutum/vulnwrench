# `vulnwrench ci` example

Synthetic inputs for [`vulnwrench ci`](../../docs/ci.md). Every package (`acme-*`) and every
advisory ID (`CVE-2099-*`, `GHSA-w*-c4hq-*`, `PYSEC-2099-*`) is fictional; the EPSS and KEV
files are made-up snapshots in the real formats, not FIRST or CISA data.

| File | What it is |
| --- | --- |
| `trivy.json`, `grype.json`, `osv.json` | Current scans of a fictional `acme-shop` repo (npm `package-lock.json`, PyPI `requirements.txt`) |
| `baseline/*.json` | The same three scanners on the base branch |
| `baseline.json` | `vulnwrench fuse merge` of `baseline/*.json`: what CI would cache from `main` |
| `.trivyignore` | One expired rule, one rule expiring in 18 days, one rule that matches nothing |
| `osv-scanner.toml` | One active `[[IgnoredVulns]]` rule with a reason |
| `epss.csv`, `kev.json` | Local exploitability snapshots dated 2026-11-11 and 2026-11-10 |
| `generate.py` | Rebuilds every file above except `baseline.json` |

What is planted:

| Package | Advisory | Baseline | Exception | Exploit data | Outcome |
| --- | --- | --- | --- | --- | --- |
| acme-router 4.2.0 | CVE-2099-2001 | new | none | in KEV | needs action |
| acme-session 1.8.0 | CVE-2099-2002 | new | none | EPSS 0.62 | needs action (scanners disagree on the fix) |
| acme-color 0.3.0 | GHSA-w2bb-c4hq-2005 | new | none | no CVE ID | listed for review |
| acme-auth, acme-csv, acme-log | CVE-2099-2007/2003/2004 | new | none | EPSS 0.09, 0.03, 0.01 | below threshold |
| acme-zip 3.3.3 | CVE-2099-2006 | new | `.trivyignore` line 3 (expires in 18 days) | EPSS 0.71 | suppressed |
| acme-dns 1.1.0 | CVE-2099-2008 | new | `osv-scanner.toml` | EPSS 0.02 | suppressed |
| six more packages | CVE-2099-1001..1006 | known | `.trivyignore` line 2 expired for acme-xml | | already in baseline |
| acme-old, acme-qs | CVE-2099-0901/0902 | baseline only | | | no longer reported |

Run it from this directory:

```sh
vulnwrench ci --trivy trivy.json --grype grype.json --osv osv.json \
  --baseline baseline.json --ignores .trivyignore --ignores osv-scanner.toml \
  --epss epss.csv --kev kev.json --as-of 2026-11-12 --reports-unfiltered
```

It exits 1: 37 raw findings from 3 scanners, 2 that need action. The recorded text, JSON and
SARIF outputs are in [`benchmarks/ci/`](../../benchmarks/ci/); from the repository root,
`python3 scripts/ci/verify_examples.py` reruns everything (including the baseline merge) and
checks the recordings byte for byte.

To rebuild `baseline.json` after `generate.py`:

```sh
vulnwrench fuse merge --trivy baseline/trivy.json --grype baseline/grype.json --osv baseline/osv.json --output baseline.json
```
