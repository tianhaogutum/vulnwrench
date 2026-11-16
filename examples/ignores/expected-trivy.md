# Ignore audit

As of 2026-11-11 (UTC). Coverage: asserted_unfiltered.

Orphans are candidates within this report, never certified unused rules.

| Locator | Advisory | Matches | Unknown | Expiry | Status |
| --- | --- | ---: | ---: | --- | --- |
| line:2 | CVE-2025-0001 | 2 | 0 | 2026-11-10 | duplicate, expired, overly_broad |
| line:3 | CVE-2025-0001 | 2 | 0 | 2026-11-11 | duplicate, soon_expiring, overly_broad |
| line:4 | CVE-2025-9999 | 0 | 0 | — | orphan_candidate, missing_reason, missing_owner |
| line:5 | GHSA-synthetic-alias | 0 | 0 | — | orphan_candidate, missing_reason, missing_owner |

## Evidence

```json
{
  "aliases": "exact_ids_only",
  "format": "trivy",
  "metadataSha256": "2326d3155065e0bfef8a625a6dbba3fda89da80aa1bdf3fa06eb806857508dcb",
  "reportSha256": "e40074eccbec090e6662353f70abeb73fdfeff4d989c103c6caf33bfe75fc329",
  "ruleScope": "global",
  "rulesSha256": "9538b4eaafa1b6928f3d679bcff4469d701c142fdbe6327bade271f74306b89d"
}
```

- Coverage is a caller assertion, not independently verifiable; candidates are limited to this report.
- Matching uses exact advisory IDs unless an explicit local alias map is supplied; unmatched aliases are not proof of unused suppressions.

Uninterpreted descriptive fields: Results[].Class, Results[].Type, Results[].Vulnerabilities[].Severity, report.ArtifactName, report.ArtifactType
