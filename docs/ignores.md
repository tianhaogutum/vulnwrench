# vulnwrench ignores

Exception files rot: `.trivyignore` and `osv-scanner.toml` entries outlive the
vulnerability they hid, expire silently, lack an owner or reason, or match far more
packages than intended. `vulnwrench ignores` audits those rules against an explicitly
**unfiltered** local Trivy or OSV-Scanner JSON report and reports per-rule observation
counts, orphan candidates, duplicates, expired or soon-expiring entries, missing
owner/reason and over-broad matches. Use it in a periodic hygiene job or before a
release review; it never deletes exceptions or generates suppression files.

_Formerly the standalone `ignore-audit` tool._

## Quick start

```sh
pip install vulnwrench
# Audit Trivy rules against a report produced without any ignore/severity/VEX filtering
vulnwrench ignores audit --format trivy --rules examples/ignores/.trivyignore \
  --report examples/ignores/trivy.json --report-unfiltered --as-of 2026-11-11
# Same for OSV-Scanner IgnoredVulns, with a hash-bound owner/reason sidecar, as Markdown
vulnwrench ignores audit --format osv --rules examples/ignores/osv-scanner.toml \
  --report examples/ignores/osv.json --report-unfiltered --as-of 2026-11-11 \
  --metadata examples/ignores/osv-metadata.json --output-format markdown
# One rule, every matching observation
vulnwrench ignores explain --format osv --rules examples/ignores/osv-scanner.toml \
  --rule-key IgnoredVulns:2 --report examples/ignores/explain-osv.json \
  --report-unfiltered --as-of 2026-11-11 --alias-map examples/ignores/aliases.json
# Review-only grouped cleanup suggestions
vulnwrench ignores cleanup-plan --format trivy --rules examples/ignores/.trivyignore \
  --report examples/ignores/trivy.json --report-unfiltered --as-of 2026-11-11 --output cleanup.json
```

`--report-unfiltered` is a required acknowledgment: a report that was already filtered
by the rules under audit cannot show which rules still match. Generate it with, for
example, `trivy fs --format json --ignorefile /dev/null .` or OSV-Scanner's JSON output
with no ignore config applied. `--as-of` defaults to today's UTC date. Python 3.11+;
standard library only. Run the quick start from a clone of the repository so the
`examples/ignores/` paths resolve.

Subcommands: `audit`, `explain`, `cleanup-plan`, and the read-only retained-plan checks
`verify-cleanup-plan-identity`, `verify-cleanup-source`, `verify-cleanup-report`,
`verify-cleanup-alias-map`, `verify-cleanup-metadata` and `verify-cleanup-inputs`.
Saved JSON keeps the original format identifiers (`"tool": "ignore-audit"`,
`schemaVersion` 1), so plans exported by the standalone tool still verify.

## Commands and actual synthetic output

All IDs/package names in `examples/ignores/` are synthetic. This command reads only
local files and writes an audit to `out.json`:

```sh
vulnwrench ignores audit --format trivy --rules examples/ignores/.trivyignore --report examples/ignores/trivy.json --report-unfiltered --as-of 2026-11-11 --output out.json
```

The first rule is `CVE-2025-0001 exp:2026-11-10`. Its actual output projection
(the complete result is [expected-trivy.json](../examples/ignores/expected-trivy.json)):

```json
{"key":"line:2","rule":"CVE-2025-0001","matchCount":2,"status":["duplicate","expired","missing_reason","missing_owner","overly_broad"]}
```

Two different synthetic packages carry that ID. Counts are observations, not
unique IDs, and duplicate report records are not collapsed. A repeated rule
with a different expiry is still flagged as the same matching scope. Duplicate
rules continue to receive their own counts; this is not allocation among rules.

OSV with an owner sidecar and explicit alias mapping:

```sh
vulnwrench ignores audit --format osv --rules examples/ignores/osv-scanner.toml --report examples/ignores/osv.json --report-unfiltered --as-of 2026-11-11 --metadata examples/ignores/osv-metadata.json
vulnwrench ignores audit --format osv --rules examples/ignores/osv-scanner.toml --report examples/ignores/osv.json --report-unfiltered --as-of 2026-11-11 --alias-map examples/ignores/aliases.json
vulnwrench ignores audit --format trivy --rules examples/ignores/.trivyignore --report examples/ignores/trivy.json --report-unfiltered --as-of 2026-11-11 --metadata examples/ignores/trivy-metadata.json --output-format markdown
```

See [OSV output](../examples/ignores/expected-osv.json),
[explicit-alias output](../examples/ignores/expected-osv-aliases.json), and
[Markdown output](../examples/ignores/expected-trivy.md). `scripts/ignores/verify_examples.py` runs
these four CLI cases and byte-compares outputs; `--write` regenerates them by
running the CLI. No output is hand-fabricated.

## Explain a selected rule

Select the exact rule **locator**, so duplicate advisory IDs remain unambiguous.
`explain` accepts the same input, coverage, date, metadata and scope options as
`audit`; its output is JSON only. For example:

```sh
vulnwrench ignores explain --format osv --rules examples/ignores/osv-scanner.toml --rule-key IgnoredVulns:2 --report examples/ignores/explain-osv.json --report-unfiltered --as-of 2026-11-11 --alias-map examples/ignores/aliases.json --osv-config-dir app
```

The synthetic report contains observations at `app/package-lock.json`,
`app/sub/package-lock.json`, `other/package-lock.json`, and an unknown path.
The command returns `matchedEvidenceIds: ["finding:0"]` and
`unknownEvidenceIds: ["finding:3"]`. Its decisions, in report order, are
`match`, `no_match`, `no_match`, `unknown`. For the nested path, the evidence
includes this exact check:

```json
{"selector":"source_dir","expected":"app","actual":"app/sub","outcome":"mismatch"}
```

The third observation also has an advisory mismatch. Missing path evidence in
the fourth observation cannot establish a match or an orphan candidate.
Other combinations using the same fixtures are covered by regression tests:

| Selected rule and options | Matched evidence IDs | Unknown evidence IDs | Interpretation |
| --- | --- | --- | --- |
| `IgnoredVulns:2`, no alias map, global | none | none | Alias-only rule: every advisory check mismatches; report aliases are descriptive. |
| `IgnoredVulns:2`, explicit alias map, global | `finding:0`, `finding:1`, `finding:3` | none | Explicit alias equivalence; no directory restriction. |
| `IgnoredVulns:2`, explicit alias map, directory `app` | `finding:0` | `finding:3` | Exact parent directory only; descendants do not inherit scope. |
| `IgnoredVulns:0`, global | `finding:0`, `finding:1`, `finding:3` | none | Expired on the audit date, with -1 days remaining; still matched for auditing. |

Each `evidence` entry includes the full supported finding fields, native report
locator, decision, reason codes, and advisory/package/path/ecosystem/version/
directory checks. `unrestricted` means no selector was supplied; `unknown`
means a required value is missing. A definite mismatch takes precedence over
missing evidence. Exact library selectors use the same checks and AND semantics.
Private owner/reason text is not emitted.

Each observation also has `reportAliasHints`. OSV `vulnerabilities[].aliases`
are attached only to the declaring observation; package `groups[].aliases`
are attached only to observations in the same package whose advisory is listed
in that group's `ids`. A group cannot manufacture findings or restore missing
coverage. Group membership alone does not establish equivalence. No report-wide,
reverse or transitive alias inference is performed. Hints appear in declaration
order (vulnerability first, then groups), preserving repeated alias IDs. Absent
or empty alias arrays produce no hints; a present alias field must be an array
of supported advisory IDs. Nulls, wrong types and malformed IDs exit 2.

For the command above **without** `--alias-map`, `finding:0` includes:

```json
{"reportAliasHints":[{"aliases":["GHSA-synthetic-alias"],"locator":"results[0].packages[0].vulnerabilities[0].aliases","trust":"untrusted","affectsMatching":false,"ruleAdvisoryListed":true}]}
```

`ruleAdvisoryListed` means only that the selected rule's exact, case-sensitive ID
occurs in the declaration. The advisory check still says `mismatch`, its
`acceptedIds` contains only `GHSA-synthetic-alias`, and `matchCount` stays 0.
The other three observations have empty hint arrays, including those sharing
the same primary ID. With the explicit map, the same hint remains untrusted;
the advisory check says `explicit_alias` and `matchCount` becomes 3 in global
scope (1 with `--osv-config-dir app`). Hints never change matching, scope checks,
coverage, orphan status or `unusedRuleAssertionAllowed: false`. Trivy observations
have empty hint arrays; `VendorIDs` is retained as descriptive data.

OSV group declarations with no listed ID observed in that exact package appear
separately in `unboundReportAliasHints`, even if the same package name or ID
occurs elsewhere in the report. Run the group-only synthetic example:

```sh
vulnwrench ignores explain --format osv --rules examples/ignores/unbound-osv.toml --report examples/ignores/unbound-osv.json --report-unfiltered --as-of 2026-11-11 --rule-key IgnoredVulns:0
```

Its input package has `groups: [{"ids":["CVE-1"],"aliases":["GHSA-local"]}]`
and no `vulnerabilities` field. The actual output projection is:

```json
{
  "unboundReportAliasHints": [{
    "ids": ["CVE-1"],
    "aliases": ["GHSA-local"],
    "locator": "results[0].packages[0].groups[0].aliases",
    "trust": "untrusted",
    "affectsMatching": false,
    "ruleAdvisoryListed": true,
    "reason": "vulnerability_collection_absent_or_null"
  }],
  "coverage": "unknown",
  "coverageGaps": [{
    "locator": "results[0].packages[0].vulnerabilities",
    "state": "absent"
  }],
  "evidence": [],
  "matchedEvidenceIds": [],
  "unknownEvidenceIds": [],
  "unusedRuleAssertionAllowed": false
}
```

`vulnerabilities: null` changes the gap's `state` to `"null"`; the other fields
in this projection stay the same. An explicit `[]` produces `coverageGaps: []`,
keeps coverage `asserted_unfiltered` and changes the unbound hint reason to
`no_same_package_id_observation`; it permits only a report-local orphan candidate,
never an unused-rule assertion. That reason also covers complete collections
with unrelated observations or groups with no declared IDs. Adding an observation
in another package cannot bind a declaration, even with an explicit alias map.
If any literal group ID is observed in its own package, the declaration appears
only on the corresponding observations, including duplicates; unobserved group
members do not also create an unbound copy. Declarations and repeated IDs/aliases
retain source order. Empty/absent aliases produce no hints; malformed IDs/aliases
still reject the report, including group-only input. The collection is empty for
Trivy and reports without unbound declarations. Hint locators resolve against
the original report bound by `provenance.reportSha256`. These hints never add
observations or change counts, decisions, scope, coverage or cleanup groups.

`coverageGaps` always appears in explain output. It lists absent/null OSV package
`vulnerabilities` collections in report order, including packages without groups
or aliases. Absent/null root `results` produces one gap at `"results"`; an
explicit `results: []` produces no gap. Trivy uses `"Results"` for root gaps;
its optional per-result `Vulnerabilities` arrays retain their existing known-empty
interpretation. Missing/null OSV `packages` remains an invalid report, not a gap.
Malformed collections still exit 2 without replacing an existing destination.

Gap locators resolve against the complete retained report identified by
`provenance.reportSha256`: `"null"` identifies an explicit JSON null, while
`"absent"` identifies a missing field on the referenced object. They do not
create `finding:N` evidence or change observation order, alias hints, checks,
counts, scope, notes, coverage or cleanup suggestions. Empty gap diagnostics do
not attest completeness: library-created reports may carry unknown coverage
without native locators. Unknown coverage and the prohibition on unused-rule
assertions remain independent of these diagnostics.

Evidence IDs are `finding:N` coordinates in normalized report observation order,
qualified by `provenance.reportSha256`. They distinguish duplicate observations
and are deterministic for fixed input bytes; they are not cross-report identities.
Retain the report to resolve the native locators. `expiry` states the inclusive
UTC date interpretation, while `nativeSuppressionActivity` remains
`not_evaluated`. `coverageAssumptions` records the caller assertion and matching
limits. `unusedRuleAssertionAllowed` is always false, including for complete
reports: an orphan candidate never certifies an unused native suppression.

An unknown `--rule-key`, malformed input or missing coverage acknowledgment
exits 2 without emitting a result or replacing an existing output file. For
Trivy, use a physical locator such as `--rule-key line:2`. Explanations include
every supplied observation, so their size grows with the report.

## Export a review-only cleanup plan

`cleanup-plan` accepts the same input, coverage, metadata, date and scope options
as `audit` and emits JSON by default, or Markdown with `--output-format markdown`.
It reads the original rules and exports a plan;
it never edits an ignore file or generates replacement suppression syntax.

```sh
vulnwrench ignores cleanup-plan --format trivy --rules examples/ignores/.trivyignore --report examples/ignores/trivy.json --report-unfiltered --as-of 2026-11-11 --output cleanup.json
vulnwrench ignores cleanup-plan --format trivy --rules examples/ignores/.trivyignore --report examples/ignores/trivy.json --report-unfiltered --as-of 2026-11-11 --output-format markdown --output cleanup.md
```

For these synthetic inputs, the actual group projection is:

```json
{
  "expired": ["line:2"],
  "ownerless": ["line:2", "line:3", "line:4", "line:5"],
  "broad": ["line:2", "line:3"],
  "report_local_orphans": ["line:4", "line:5"]
}
```

Each group contains candidate objects with the complete audit `rule` row,
`suggestedManualAction`, `assumptions` and `sourceReference`. Expired entries
request owner reassessment; ownerless entries request metadata assignment;
broad entries request package-scope review; report-local orphans request
independent coverage/alias verification before considering manual removal.
A rule can appear in multiple groups. `summary.candidateRuleCount` counts unique
rules, while `summary.groupCounts` counts each group's entries. Ownerless means
no owner in the supplied sidecar, not proof that nobody owns the exception.

Markdown renders the same plan with a counted section for every group and
`excludedFromOrphanReview`, including empty sections marked `None.`. Each
candidate retains its manual action, every assumption, the complete audit rule
as a JSON evidence block, and a `sha256:<rulesSha256>#<locator>` source reference
with byte length, format and locator convention. Excluded entries retain their
reasons and the same review safeguards. The Context JSON block preserves summary
counts, coverage, audit date, expiry convention, provenance, descriptive-field
inventory, notes and all safety flags. Source-resolution instructions follow it.
Report strings remain literal JSON data; HTML and backticks are escaped without
losing their original values. Private owner/reason text and comments are omitted
in both formats. Markdown uses the existing atomic file export and input-alias
protections; omitting `--output` writes it to stdout. `explain` remains JSON only.

Every source reference includes the original rule locator, format, SHA-256 of
the **complete original rules bytes**, byte length and locator convention.
Retain that exact file: after verifying its digest and length, resolve `line:N`
with UTF-8 `splitlines()[N-1]`, or `IgnoredVulns:N` with the parsed TOML
`IgnoredVulns[N]`. This is a lossless document reference, not a reconstructed rule
or isolated TOML byte span. Comments, CRLF endings, whitespace, quoted TOML keys
and private reason text remain available in the original source without being
copied into the export. Rule order and duplicate IDs keep their original locators.
The plan cannot recover source bytes if the retained file is lost.

`reviewOnly` is true, `automaticChangesAllowed` and
`unusedRuleAssertionAllowed` are false, and every candidate has
`definiteRemovalRecommended: false`. An orphan is always report-local. Unknown
report coverage or missing selector evidence excludes the zero-match rule from
`report_local_orphans` and lists it in `excludedFromOrphanReview` with reasons.
For example, an OSV package with groups but an absent/null `vulnerabilities`
array yields **no orphan suggestions**, even if its rule is separately expired
or ownerless. An explicit empty array permits report-local review, never a claim
that a native suppression is unused. Exact-ID mode still requires manual alias
verification; `--alias-map` applies the same explicit equivalence as `audit`.

Missing `--report-unfiltered`, malformed input, invalid dates and output paths
aliasing any input exit 2 without emitting a plan or replacing an existing
output. Symlink outputs are rejected.

## Verify a retained cleanup plan without scanner inputs

`verify-cleanup-plan-identity` reads **only the complete retained JSON plan**.
It requires an independently recorded SHA-256 and checks the existing supported
identity/review envelope. **Digest equality is not authentication, semantic plan
approval, completeness, input verification, removability or edit permission.**
`automaticChangesAllowed` always remains false. A reviewer can check the retained
plan's identity even when every original rules/report/metadata/map file is lost:

```sh
# Obtain this value from a separate trusted record retained before potential edits.
vulnwrench ignores verify-cleanup-plan-identity --plan cleanup.json --expected-plan-sha256 "$EXPECTED_PLAN_SHA256"
# Optional atomic JSON export:
vulnwrench ignores verify-cleanup-plan-identity --plan cleanup.json --expected-plan-sha256 "$EXPECTED_PLAN_SHA256" --output verified-plan.json
```

Exit 0 returns exactly these four fields (the placeholder is the complete verified
64-character digest); no rule, report, metadata, map or source-reference claims.
The CLI pretty-prints them with two-space indentation and sorted keys; the compact
form below shows the same fields:

```json
{"command":"verify-cleanup-plan-identity","planIdentityVerified":true,"planSha256":"<verified complete raw plan digest>","automaticChangesAllowed":false}
```

The external digest is required and must be exactly 64 lowercase ASCII hexadecimal
characters. One complete raw plan snapshot is hashed before parsing: whitespace,
context and manual-suggestion edits all fail under the old pin. Recomputing a pin
from a potentially edited plan detects no earlier edit. There is no signature or
origin verification.

Only JSON cleanup-plan schema 1 with `tool=ignore-audit`, `command=cleanup-plan`,
`reviewOnly=true`, `automaticChangesAllowed=false`,
`unusedRuleAssertionAllowed=false` and supported `provenance.format` (`trivy` or
`osv`) is accepted. These are envelope checks, **not full plan validation**.
Both `exact_ids_only` and `explicit_local_groups` exports work, including empty
groups and incomplete coverage, without opening bound inputs. Context, input
provenance digests/alias declarations, references, counts, decisions, matching,
coverage and group equivalence are uninterpreted. Changed or inconsistent values
outside the envelope can pass with a new matching pin; success does not approve
them. Use the input/source/report/metadata/map verifiers separately when those
retained files are available. No verifier attests completeness or removability.

An absent, malformed, noncanonical or mismatched pin, invalid/duplicate-key JSON,
unsupported identity/review envelope/native format, missing plan or protected
output exits 2 with no success output or destination replacement. Errors withhold
input values and paths. Direct, symlink and hardlink aliases to the plan are
protected; all symlink outputs are rejected. Inputs remain unchanged. The plan
bytes and parsed JSON are held in memory.

The manifest maps retained original plan paths to independently recorded complete
raw SHA-256 values. The script copies unchanged plans into isolated plan-only
sets, checks both native formats/modes, empty groups and unknown coverage, and
retains exact commands, exit codes and raw stdout/stderr. It also checks raw edits,
required pins, malformed/unsupported envelopes and protected destinations.

## Verify retained cleanup source

Verify a JSON cleanup plan against the **complete original rules bytes** before
resolving its references for manual review. No scanner report, metadata, alias
map or unfiltered-coverage acknowledgment is needed for this identity check:

```sh
vulnwrench ignores verify-cleanup-source --plan cleanup.json --rules examples/ignores/.trivyignore
```

For `cleanup.json` exported by the Trivy example above, success has these fields
(`rulesSha256` is the digest of the complete retained file):

```json
{"command":"verify-cleanup-source","sourceVerified":true,"rulesSha256":"<verified complete rules digest>","verifiedReferenceCount":4,"automaticChangesAllowed":false}
```

Optionally bind the **complete raw plan bytes** to a SHA-256 recorded independently
before verification:

```sh
vulnwrench ignores verify-cleanup-source --plan cleanup.json --expected-plan-sha256 "$EXPECTED_PLAN_SHA256" --rules retained.rules --output verified-source.json
```

The expected digest must be exactly 64 lowercase ASCII hexadecimal characters.
Syntax and digest equality are checked before parsing the same single plan
snapshot used for source verification. After **all** source checks pass, pinned
success adds only `planSha256`; no flag preserves the existing serialized output
byte for byte. The library equivalent is
`verify_cleanup_source(raw_plan, raw_rules, expected_plan_sha256=expected_digest)`.
Rules are still required and fully parsed, including zero-reference plans.
Report, metadata and map files are neither required nor read, even when bound in
plan provenance; matching and plan decisions are not re-evaluated.

Wrong/noncanonical pins or any plan byte edits, including whitespace, context or
manual suggestions, exit 2 with redacted stderr and no success or destination
replacement. A correct pin cannot bypass unsupported schema/native rules,
inconsistent source references or output protections. This pins identity only:
it grants no signature verification, authentication, trust, coverage attestation
or removal/edit permission. Retain the digest separately; recomputing it from a
possibly edited plan at verification time cannot detect earlier changes.

Only JSON `cleanup-plan` schema version 1 is supported. The verifier checks the
provenance digest even when all groups and exclusions are empty. It parses the
complete retained source using the supported native format and checks **every**
candidate and exclusion reference's full SHA-256, integer byte length, format,
locator convention and exact entry key. Locators must resolve to native rules:
`line:N` uses canonical ASCII positive physical line numbers; `IgnoredVulns:N`
uses canonical ASCII nonnegative TOML entry indices. Leading zeros, signs,
whitespace and comment/blank-line locators are invalid. Candidate advisory IDs
must equal the resolved native ID. Exclusions in schema 1 record only a key;
the native parser validates their resolved IDs, with no separate advisory field
to compare. Distinct duplicate advisory locators remain distinct. Repeated
references across groups/exclusions are all checked and count once only in
`verifiedReferenceCount`.

A comment-byte change or CRLF-to-LF conversion invalidates the digest even if
parsed rules appear identical. Digest, length, locator, advisory or safety-flag
mismatches, malformed input and unsupported schemas exit 2 with redacted errors,
no result and no replacement of an existing destination. Rules and plans are
never modified. `--output verified.json` uses atomic JSON export and rejects
paths, symlinks or hardlinks aliasing either input; stdout is the default.

`sourceVerified` certifies retained source identity only. It does not authenticate
the plan, revalidate audit evidence or summary counts, verify the retained report,
attest scan coverage, establish unused suppressions or recommend definite removal.
A mutually edited plan/source pair is not authenticated by a self-declared hash.
Automatic changes remain forbidden. Markdown exports are for review; retain the
JSON plan for machine verification. Inputs and results are held in memory.

## Verify retained cleanup report

Verify a JSON cleanup plan against the **complete original native report bytes**
before manual review:

```sh
vulnwrench ignores verify-cleanup-report --plan cleanup.json --report retained-original-report.json
# optional --output verified.json exports atomically:
```

Success emits exactly these fields, with the digest of the complete retained
report (including descriptive text and whitespace):

```json
{"command":"verify-cleanup-report","reportVerified":true,"reportSha256":"<verified complete report digest>","automaticChangesAllowed":false}
```

Optionally bind the plan to a SHA-256 recorded independently before verification:

```sh
vulnwrench ignores verify-cleanup-report --plan cleanup.json --expected-plan-sha256 "$EXPECTED_PLAN_SHA256" --report retained-original-report.json
```

`--expected-plan-sha256` requires exactly 64 lowercase hexadecimal characters.
The shared pin check hashes the complete raw plan snapshot before parsing; that
same snapshot is used for report verification. Every plan byte is bound, including
whitespace, audit context and manual suggestions. Invalid syntax or a mismatch
exits 2 with redacted stderr, no success output and no destination replacement.
Only after the pin and all report checks pass does success add `planSha256`.
Omitting the flag preserves byte-identical default JSON. The library equivalent is
`verify_cleanup_report(raw_plan, raw_report, expected_plan_sha256=expected_digest)`.

The pin checks identity only: it provides no signature verification,
authentication, trust, decision validation, coverage/completeness attestation or
removal/edit permission. Computing a digest from a possibly edited plan at
verification time cannot detect earlier edits. A correct pin never bypasses the
existing schema, safeguards, report digest, native parsing or destination checks.
Report verification still reads only plan and report, even when the plan binds
rules, metadata or alias maps whose files are unavailable. Unknown coverage stays
unknown and `automaticChangesAllowed` remains `false`.

Only JSON cleanup-plan schema version 1 with the `ignore-audit` / `cleanup-plan`
identity and review-only safeguards is accepted. The verifier checks
`provenance.reportSha256` against all retained report bytes, even when candidates
and exclusions are empty. It then parses the complete report using the declared
`provenance.format` (`trivy` or `osv`) and the existing strict native subset.
An absent or null result collection, or OSV package vulnerability collection,
can still verify retained identity. Verification never repairs unknown coverage,
manufactures observations or changes the plan's coverage, groups or exclusions.

One descriptive text byte or whitespace edit invalidates identity. Missing or
wrong digests, unsupported schemas/formats and malformed plan envelopes or native
reports exit 2 with redacted stderr and no success output. A matching digest does
not make malformed native input acceptable. Neither input is modified, and
failures preserve an existing destination. `--output` uses atomic JSON export
and rejects direct, symlink and hardlink aliases to either input; stdout is the
default. File paths, private report text and raw parser errors are withheld from
error messages.

This certifies retained report identity only. No rules, metadata or alias map
are read; audit context, summary counts and source references are not revalidated.
Use `verify-cleanup-source` separately for retained rule references. No
`--report-unfiltered` assertion is needed or made by report verification: native
parsing does not attest that the scanner output was unfiltered or complete.
Success never certifies unused suppressions, removability or automatic edit
permission. A mutually edited plan/report pair with an updated self-declared
hash is not authenticated. Keep the JSON plan and complete original inputs;
Markdown exports cannot be used as machine-verification input. All bytes and
parsed report data are held in memory.

## Verify retained cleanup alias map

Retain the **complete original alias-map bytes** when exporting a JSON cleanup
plan with `--alias-map`. Verify their identity before manual review:

```sh
vulnwrench ignores cleanup-plan --format osv --rules examples/ignores/osv-scanner.toml --report examples/ignores/osv.json --report-unfiltered --as-of 2026-11-11 --alias-map examples/ignores/aliases.json --output cleanup-with-aliases.json
vulnwrench ignores verify-cleanup-alias-map --plan cleanup-with-aliases.json --alias-map retained-original-aliases.json
# optional --output verified.json exports atomically:
vulnwrench ignores verify-cleanup-alias-map --plan cleanup-with-aliases.json --alias-map examples/ignores/aliases.json
```

Here `retained-original-aliases.json` must be an unchanged byte-for-byte copy of
`examples/ignores/aliases.json`. Success emits exactly:

```json
{"command":"verify-cleanup-alias-map","aliasMapVerified":true,"aliasMapSha256":"<verified complete alias-map digest>","automaticChangesAllowed":false}
```

To bind the complete plan bytes to a digest recorded independently before
review, optionally supply a plan pin:

```sh
# EXPECTED_PLAN_SHA256 was independently recorded when retaining cleanup.json.
vulnwrench ignores verify-cleanup-alias-map --plan cleanup.json --expected-plan-sha256 "$EXPECTED_PLAN_SHA256" --alias-map retained.aliases.json --output verified-alias-map.json
```

`--expected-plan-sha256` requires exactly 64 lowercase hexadecimal characters.
It checks the complete raw single plan snapshot before JSON parsing, including
whitespace, context and manual suggestions. Success adds only `planSha256` to
the existing result after all map checks pass; omitting the flag preserves the
exact default output bytes. The library API
`verify_cleanup_alias_map(raw_plan, raw_aliases, expected_plan_sha256=expected_digest)`
accepts the same keyword-only option (default `None`). Invalid syntax or a
mismatch exits 2 with redacted stderr and preserves inputs and destinations.
A correct pin cannot bypass any envelope, provenance, schema or group check.
Only the plan and map are read, even when unavailable rules, report or metadata
are bound in the plan. Independently retain the expected digest: recomputing it
from a possibly edited plan detects no earlier edit. Pin equality is identity
only, never a signature, authentication, trusted equivalence, annotation or
decision approval, completeness attestation, removal/edit permission or
authorization for automatic changes.

Only JSON cleanup-plan schema 1 with the existing identity/review-only safeguards
and supported `provenance.format` (`trivy` or `osv`) is accepted.
`provenance.aliases` must be `explicit_local_groups`, and
`provenance.aliasMapSha256` must equal the digest of **all** retained map bytes,
even when candidates and exclusions are empty or no plan rule uses those groups.
Exact-ID plans cannot verify an alias map, even if a matching digest is added.
The complete map must pass the existing strict schema-1 parser: disjoint groups
of at least two distinct single-token, case-sensitive IDs. An empty `groups: []`
map is valid and still requires matching explicit provenance.

Whitespace or member edits, missing/wrong digests, unsupported schemas, malformed
JSON and hash-matching invalid/overlapping groups exit 2 with redacted stderr and
no success output. Both inputs and existing destinations are preserved on errors.
`--output` rejects direct, symlink and hardlink aliases to either input; stdout
is the default. Private values, file paths and raw parser errors are withheld.

Success verifies retained input identity only. It does not infer trusted
equivalence from report hints, rerun matching, validate audit counts or source
references, repair incomplete coverage, or certify unused/removable rules or
automatic edits. No rules, report or metadata files are read. Use the source and
report verifiers separately for their identity checks. A mutually edited
plan/map pair with an updated self-declared digest is not authenticated. Keep the
JSON plan and complete original inputs; Markdown plans are not accepted. All
input bytes and parsed groups are held in memory.

Focused plan-pin contracts and unchanged retained-map checks:

## Verify retained cleanup metadata

Retain the **complete original native rules and metadata sidecar bytes** when
exporting a JSON cleanup plan with `--metadata`. Verify their identity before
manual review:

```sh
vulnwrench ignores cleanup-plan --format osv --rules examples/ignores/osv-scanner.toml --report examples/ignores/osv.json --report-unfiltered --as-of 2026-11-11 --metadata examples/ignores/osv-metadata.json --output cleanup-with-metadata.json
vulnwrench ignores verify-cleanup-metadata --plan cleanup-with-metadata.json --rules retained-original-rules --metadata retained-original-metadata.json
# optional --output verified.json exports atomically:
vulnwrench ignores verify-cleanup-metadata --plan cleanup-with-metadata.json --rules examples/ignores/osv-scanner.toml --metadata examples/ignores/osv-metadata.json
```

The retained files must be unchanged byte-for-byte copies of the two example
inputs. Success emits exactly:

```json
{"command":"verify-cleanup-metadata","metadataVerified":true,"metadataSha256":"<verified complete sidecar digest>","rulesSha256":"<verified complete retained rules digest>","automaticChangesAllowed":false}
```

To bind the complete plan to a SHA-256 recorded independently before verification:

```sh
vulnwrench ignores verify-cleanup-metadata --plan cleanup.json --expected-plan-sha256 "$EXPECTED_PLAN_SHA256" --rules retained.rules --metadata retained.metadata.json --output verified-metadata.json
```

`--expected-plan-sha256` requires exactly 64 lowercase hexadecimal characters.
The shared pin check validates syntax and hashes the complete raw single plan
snapshot before parsing it. Only after the pin and all existing rules/sidecar
checks pass does success add `planSha256`; all other fields stay as above.
Omitting the option preserves the exact existing output bytes. The library API
accepts keyword-only `expected_plan_sha256=None` with the same behavior.
Whitespace, context and manual-suggestion edits all invalidate a prior pin,
even if retained rules and metadata still match. Record the expected digest
separately; recomputing it from the plan at verification time cannot detect
earlier edits. Equality is identity only, not a signature, authentication,
annotation or decision approval, completeness attestation or edit permission.
A correct pin cannot bypass any validation below. Only plan, rules and metadata
are read, even when the plan binds report/map files that are unavailable.

Only JSON cleanup-plan schema 1 with the existing identity/review-only safeguards
and supported `provenance.format` (`trivy` or `osv`) is accepted. Both
`provenance.metadataSha256` and `provenance.rulesSha256` must equal the complete
retained input digests, including whitespace/comments. This is required even
when the plan has zero candidates/exclusions or both rules and sidecar entries
are empty. A plan exported without metadata cannot verify a sidecar through an
absent digest. Complete native rules are parsed using the declared format; the
sidecar must pass the same strict schema-1 metadata validator used at export:
its `rulesSha256` must match, locators must name parsed native rules, annotations
must be single-line strings, and sidecar reasons must not conflict with native
OSV reasons. A matching digest cannot legitimize malformed inputs.

Whitespace or owner/reason edits, missing/wrong digests, unsupported schemas or
formats, malformed JSON/TOML, unknown locators and reason conflicts exit 2 with
redacted stderr and no success output. Every input and existing destination is
preserved on errors. `--output` rejects direct, symlink and hardlink aliases to
any of the three inputs; stdout is the default. Private annotations, file paths
and raw parser errors are withheld.

Success verifies retained input identity only. It does not authenticate owners,
reasons or plan decisions, rerun matching, validate counts/source references,
repair incomplete report coverage, infer trusted aliases, or certify unused or
removable rules or automatic edit permission. No report or alias map is read.
Use the other verifiers separately for their identity/reference checks. A
mutually edited plan/rules/sidecar set with updated self-declared hashes is not
authenticated. Keep the JSON plan and complete original inputs; Markdown plans
are not accepted. All bytes and parsed rules/annotations are held in memory.

## Verify all retained cleanup inputs

Use one command to verify the complete retained set and every native source
reference against the same JSON plan snapshot:

```sh
vulnwrench ignores verify-cleanup-inputs --plan cleanup.json --rules retained.rules --report retained.report.json
# Include each optional input exactly when bound by plan provenance:
vulnwrench ignores verify-cleanup-inputs --plan cleanup-with-metadata.json --rules retained.rules --report retained.report.json --metadata retained.metadata.json --alias-map retained.aliases.json --output verified.json
```

The second command requires a plan exported with **both** metadata and an explicit
alias map. For the metadata-only example above, omit `--alias-map`.
Success emits exactly the required fields below, adding `metadataSha256` and/or
`aliasMapSha256` only for bound, supplied and verified optional inputs:

```json
{"command":"verify-cleanup-inputs","inputsVerified":true,"rulesSha256":"<verified complete rules digest>","reportSha256":"<verified complete report digest>","verifiedReferenceCount":4,"automaticChangesAllowed":false}
```

To pin the **complete plan bytes** to a digest recorded independently before
verification, optionally supply `--expected-plan-sha256`:

```sh
vulnwrench ignores verify-cleanup-inputs --plan cleanup.json --expected-plan-sha256 "$EXPECTED_PLAN_SHA256" --rules retained.rules --report retained.report.json
```

`EXPECTED_PLAN_SHA256` must contain exactly 64 lowercase ASCII hexadecimal
characters. Include `--metadata` and/or `--alias-map` when bound by that plan.
The command checks syntax and complete raw plan SHA-256 before plan parsing or
composition, using the same single plan snapshot for every verifier. A match
adds only `planSha256` to the success above, after **all** existing checks pass.
Without the flag, success fields and serialized bytes are unchanged.

Wrong or noncanonical digests exit 2 with redacted stderr and no success or
replacement of an existing destination. Any plan byte change requires a new
expected digest, including whitespace and otherwise unverified context or manual
suggestions whose retained-input hashes still match. A matching expected digest
cannot make an unsupported schema, inconsistent provenance, invalid native
input or source reference valid. This is an identity pin, **not signature
verification, authentication or trust**; it does not validate plan decisions,
attest report coverage or grant removal/edit permission. Record the digest
separately from the retained plan; recomputing it from the plan at verification
time does not detect prior plan edits.

Rules and report are required. A present `provenance.metadataSha256` requires
`--metadata`; an unbound metadata input is rejected. `aliases: exact_ids_only`
requires no map digest or map input. `aliases: explicit_local_groups` requires
both `aliasMapSha256` and `--alias-map`. Missing/unknown alias modes, missing or
unexpected optional inputs and inconsistent exact-ID/map provenance exit 2.
Null/empty/invalid digests never mean that an input may be silently skipped.

The command composes the existing source, report, metadata and alias-map checks
above using one retained plan byte snapshot. It reuses their schema, digest,
native parser, sidecar/map and source-reference rules, including unique locator
counting. Complete digests and strict parsing remain required for empty plans,
empty rules and empty sidecar/map entries. Nonempty rules with zero references
still verify identity. Incomplete reports may verify; coverage stays unverified.

Any failed check produces redacted stderr, exit 2 and no partial success. Every
input and existing destination is preserved. `--output` writes JSON atomically
and rejects direct, symlink and hardlink aliases to **any supplied input**,
including optional inputs; stdout is the default. This verifies identity and
native references only, without rerunning matching or validating audit context,
summary counts or plan decisions. It authenticates neither annotations nor alias
trust, attests no completeness/unfilteredness, and certifies no unused/removable
rules or automatic edits. Self-declared hashes do not authenticate mutually
edited input sets. Keep the JSON plan and complete original inputs. Bytes and
parsed inputs are held in memory; this is not a filesystem-wide atomic snapshot.

## Precisely supported input modes

| Input | Supported subset and field mapping |
| --- | --- |
| Trivy rules | UTF-8 `.trivyignore`: blank lines, `#` comments, one exact single-token advisory ID per line, optional `exp:YYYY-MM-DD`. Stable locator `line:N` uses physical 1-based line numbers. Comments are not inferred as reasons. |
| Trivy report | Native JSON with integer `SchemaVersion: 2`, `Results[]`, `Vulnerabilities[]`. `VulnerabilityID` → advisory, `PkgName` → package, `InstalledVersion` → version, `PkgPath` (otherwise result `Target`) → effective path. Ecosystem stays unknown; it is not guessed from scanner type. |
| OSV rules | TOML containing only `[[IgnoredVulns]]` with `id`, optional `effectiveUntil` (TOML date or date string), and `reason`. Locator `IgnoredVulns:N` is a 0-based entry index. An empty config is a valid empty rule set. |
| OSV report | Native JSON `results[].source.{path,type}`, `packages[].package.{name,version,ecosystem,commit,purl}`, and `packages[].vulnerabilities[].id`. Every vulnerability/package observation becomes a finding; `source.path` is its path. |
| OSV config scope | Default treats the supplied config as a global scanner `--config` override. For a per-directory config, supply `--osv-config-dir app` with a POSIX directory in the **report's path coordinate system**. It applies to `app/lock`, not `app/sub/lock`. No filesystem lookup or recursive inheritance is inferred. |
| Sidecar | Optional, tool-owned metadata JSON described below, carrying owner/reason only; it cannot change the native rule's matching scope. |
| Alias map | Optional, tool-owned JSON `{"schemaVersion":1,"groups":[["CVE-2025-0001","GHSA-synthetic-alias"]]}`. Groups must be disjoint with at least two distinct IDs. IDs are case-sensitive. No network resolution or fuzzy matching. |

JSON **reports** are native scanner formats; JSON rule files, Trivy YAML,
Grype YAML/JSON, SARIF, VEX, regex/glob selectors, `purls` rule selectors,
OSV `PackageOverrides`, scanner configuration options, and non-vulnerability
Trivy findings are unsupported and return exit 2. Do not rename unsupported
schemas and expect them to work. Advisory IDs must be single tokens made of
letters, digits, `.`, `_`, `:`, `-`, starting and ending in a letter/digit;
SPDX license expressions and non-vulnerability rules are outside this command.

Structural keys are allowlisted in [inputs.py](../src/vulnwrench/ignoreaudit/inputs.py).
Unsupported structural fields, duplicate JSON keys, malformed dates and wrong
container types fail closed. Known descriptive fields (e.g. severity, full OSV
advisory details, Trivy artifact metadata, OSV groups/call analysis and license
annotations) do not affect matching. Their field paths are listed explicitly in
`uninterpretedFields` (uninterpreted for matching), and SHA-256 provenance binds
the complete original report. Opaque descriptive subobjects are retained by that digest, not copied
into the output or interpreted as selectors. OSV alias declarations additionally
appear as untrusted hints in `explain`. Retain the input report for review.
This is a format subset, not universal scanner-version compatibility.

## Coverage, aliases and dates

`--report-unfiltered` is mandatory. Supply a vulnerability-only report produced
without ignore files/config, ignore-unfixed, severity/path filters, VEX, or other
suppression. The flag is **your assertion**, not scanner attestation. The tool
cannot detect a plausible report from which a caller removed records. Trivy
nonempty `ExperimentalModifiedFindings` and nonempty OSV `experimental_config`
are rejected rather than assuming that suppressed records restore coverage.

An explicit empty `Results: []` / `results: []` is an acknowledged empty report.
An absent/null result collection has unknown coverage and cannot yield orphan
candidates. In OSV reports, an absent/null **package vulnerability array** also
makes coverage unknown for the whole report, even when `groups` contains IDs
or other packages contain complete observations. Available findings are retained;
the missing collection locators appear in `notes`. Only an explicit
`vulnerabilities: []` is an acknowledged empty package observation collection.
Neither case proves an exception unused across other targets,
versions, scanner databases, or time. Missing evidence for a library selector
also blocks an orphan candidate for that rule. No output ever certifies
“unused” or recommends automatic deletion.

Report-provided aliases are **not** automatically trusted as equivalence.
`explain` exposes supported OSV declarations as observation-local, source-located
untrusted hints, separately from the advisory check and explicit equivalence.
Without `--alias-map`, an alias-only rule has zero exact-ID matches; that
candidate is especially not proof of an unused native OSV suppression. Native
OSV supports alias suppression; supply an explicit local map to audit that
relationship. This tool does not claim to reimplement all upstream engines.

`--as-of YYYY-MM-DD` defaults to the current UTC calendar date. Audit dates are
**inclusive**: an expiry equal to the as-of date has 0 days remaining and is
`soon_expiring`; it becomes `expired` on the next UTC date. The default soon
window is 0–30 days inclusive (`--soon-days` changes it). Timestamps and time
zones in expiry fields are rejected. This is an explicit date-level audit
convention, not reproduction of upstream wall-clock expiry behavior.

`overly_broad` means a rule matches more than one distinct `(ecosystem, name)`
pair; versions and paths alone do not inflate breadth. It is a review signal,
not proof of bad policy. Unknown package names yield `package_breadth_unknown`.

## Metadata and library selectors

Reasons come from native OSV rules or a sidecar; owners come from a sidecar.
Bind metadata to exact rule bytes, so edits cannot silently reassign owners:

```json
{
  "schemaVersion": 1,
  "rulesSha256": "<sha256 of the complete rules file bytes>",
  "rules": {"line:2": {"owner": "team-name", "reason": "Reviewed exception"}}
}
```

Use `IgnoredVulns:0` for OSV. Unknown locators, hash mismatches, extra fields,
and conflicting native/sidecar reasons fail. Metadata is not suppression
syntax. Outputs include only `hasReason`/`hasOwner`, not the private text.
Owner/reason annotations must be single-line strings; whitespace-only native
optional strings represent missing information. Timestamps are not expiry dates.
Error messages omit input values, raw parser exceptions, and file paths.
Advisory IDs, matched package names and rule selectors remain audit data in
successful outputs; treat these local output files accordingly.

The library additionally supports **exact**, case-sensitive package, ecosystem,
version and POSIX path selectors on `Rule`, with AND semantics. These are a
library model for callers with their own already-authorized rule subsets;
there is no invented native-file selector syntax or suppression compilation.
Glob patterns and `..` paths fail. For example:

```python
from datetime import date
from vulnwrench.ignoreaudit import Rule, audit, load_report

report = load_report(open("examples/ignores/trivy.json", "rb").read(), "trivy",
                     report_unfiltered=True)
result = audit([Rule("local:1", "CVE-2025-0001", package="demo-a",
                     path="app/package-lock.json")], report,
               as_of=date(2026, 11, 11), report_unfiltered=True)
assert result["rules"][0]["matchCount"] == 1
```

## Validation and reproducible comparison

```sh
python -m pytest tests/ignoreaudit
vulnwrench ignores --help
vulnwrench ignores cleanup-plan --help
python scripts/ignores/verify_examples.py
python scripts/ignores/benchmark.py --findings 10000 --rules 1000
```

The CLI/cleanup tests compare every Markdown group and exclusion against
JSON, including complete rule evidence, actions, assumptions and source hashes.
They cover CRLF/UTF-8 sources, duplicate IDs, explicit alias maps, absent/null
versus empty OSV observations, unknown directory-scope evidence, empty plans,
private metadata, Markdown/HTML-like report text and rejected exports.
The unbound-hint regressions cover literal missing/null/empty contracts,
same-package binding, partial groups, duplicate declarations/observations,
reverse/transitive isolation, exact versus explicit-map matching, unknown scope,
cleanup parity and 42 malformed unbound declaration controls.
The coverage-gap regressions distinguish literal absent/null/empty root and
package collections, interleaved gaps and actual observations, exact versus
explicit-map matching, directory scope, unchanged notes/audit/cleanup outputs,
and 20 malformed collection controls. The `verify-cleanup-*` suites cover raw plan
edits, pin syntax, correct-pin non-bypass, empty and incomplete-coverage plans,
missing inputs and protected destinations.

The generated equivalence test uses 60 deterministic seeds, including aliases,
empty reports, exact package/path/version/ecosystem selectors and unknown
selector evidence. The benchmark compares complete match **and unknown** index
sets against the straightforward rule-by-finding reference. Timings include
index construction, model validation and matching, excluding imports and
fixture creation. It never benchmarks scanner startup or target code.

One measured run (Linux x86_64, three repetitions):

| Matcher | Median seconds | Counted operations |
| --- | ---: | ---: |
| reference | 1.041177 | 10,000,000 |
| indexed | 0.024478 | 15,000 |

Both produced exactly **3,664 matching pairs**. Raw runs and operation
definitions are in [benchmark.json](../examples/ignores/benchmark.json). The indexed count
includes posting insertions and candidate checks; it is not a count of every
CPU instruction or dictionary operation. The reference count is rule/finding
checks. This selective synthetic workload favors indexing. A common ID matching
every finding can approach the baseline's work, and memory for postings/results
is additional overhead. There is no general speedup guarantee. Re-running on a
busy machine changes wall times; equality must still hold.

## Upstream relationship and limits

Trivy and OSV already support expiring exceptions. Grype's public
[unused-rule request #3050](https://github.com/anchore/grype/issues/3050) and
[expiry discussion #452](https://github.com/anchore/grype/issues/452) motivate
this audit, but this command does not parse Grype rules. The difference is a shared
offline hygiene report with explicit coverage caveats and an equivalence-tested
indexed matcher, not a new scanning or suppression engine. Format references
and upstream licenses are listed in [THIRD_PARTY.md](../THIRD_PARTY.md).

Only synthetic/authorized local inputs should be used. No keys, servers, target
execution, package-manager lifecycles, remote queries, automatic deletions,
production modifications, gates, or scanner invocation are implemented. Exit 0
means processing succeeded even if review flags exist; exit 2 means unsupported
or invalid input/I/O failure. Exit 1 is reserved for a possible future policy
gate and is not emitted by the audit CLI. Output is deterministic for fixed
inputs, as-of date and options, with SHA-256 provenance and no runtime timestamp.
Input files cannot be selected as output, including symlink/hardlink aliases.
Inputs/results are held in memory; this command does not stream multi-gigabyte scans.
