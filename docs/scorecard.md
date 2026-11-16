# vulnwrench scorecard

Before you ship, you may want to know whether the open-source projects behind your
SBOM are maintained and follow security practices, using OpenSSF Scorecard results
you already saved. `vulnwrench scorecard` joins CycloneDX components to local
Scorecard JSON snapshots through an explicit, exact PURL-to-repository map, applies a
per-check policy with freshness and unknown handling, and can compare two dated
snapshot bundles to flag score decreases in CI.

_Formerly the standalone `scorecard-join` tool._

It does not scan repositories, call APIs, guess repository URLs, run targets, or
calculate a new security score. Standard library only. Output is JSON or Markdown with
component decisions, timestamp-aware coverage and complete original evidence.

## Quick start

Run from a clone of the repository (the inputs are the synthetic fixtures under
[`examples/scorecard/`](../examples/scorecard/)):

```sh
# Component decisions and policy result (add --gate to exit 1 unless the decision is pass)
vulnwrench scorecard check examples/scorecard/bom.json \
  --map examples/scorecard/repos.json --scorecards examples/scorecard/scorecards \
  --policy examples/scorecard/policy.json --as-of 2026-11-11 --output out.json

# Find unmapped, missing-PURL and ambiguous components before joining
vulnwrench scorecard lint-mappings examples/scorecard/lint-mappings/bom.json \
  --map examples/scorecard/lint-mappings/repos.json --format markdown

# Compare two dated snapshot bundles; --fail-on-decrease exits 1 on any comparable score decrease (none here)
vulnwrench scorecard compare examples/scorecard/compare/bom.json \
  --map examples/scorecard/compare/repos.json \
  --before examples/scorecard/compare/before --after examples/scorecard/compare/after \
  --before-as-of 2026-11-01 --after-as-of 2026-11-11 --max-age-days 2 --fail-on-decrease
```

| Subcommand | Purpose | Exit codes |
| --- | --- | --- |
| `check` | Component-level evidence and policy decisions | 0 report written (with `--gate`: 1 unless the decision is pass), 2 invalid input |
| `lint-mappings` | Mapping issues before a join; no policy or snapshots needed | 0, or 1 with `--strict` / `--fail-on-unmapped` findings, 2 invalid input |
| `compare` | Compare two dated snapshot bundles for the same inventory and mapping | 0, or 1 with `--fail-on-decrease` on a decrease, 2 invalid input |

## Commands and actual synthetic output

```sh
vulnwrench scorecard check examples/scorecard/bom.json \
  --map examples/scorecard/repos.json --scorecards examples/scorecard/scorecards \
  --policy examples/scorecard/policy.json --as-of 2026-11-11 --output out.json

vulnwrench scorecard check examples/scorecard/bom.json \
  --map examples/scorecard/repos.json --scorecards examples/scorecard/scorecards \
  --policy examples/scorecard/policy.json --as-of 2026-11-11 \
  --format markdown --output out.md
```

With no `--output`, the report goes to stdout. `--output` atomically replaces a
local report; its parent directory must exist. Input files, their hardlinks, and
output symlinks cannot be overwritten. Keep reports outside the snapshot directory.

[examples/scorecard/expected.json](../examples/scorecard/expected.json) and
[examples/scorecard/expected.md](../examples/scorecard/expected.md) were produced by these CLI commands,
not handwritten. Their seven component rows are:

| Component | Decision | Reason | Snapshot age, UTC days |
| --- | --- | --- | --- |
| `pkg:npm/demo@1.0` | pass | checks_passed | 1 |
| `pkg:npm/demo-helper@2.0` | pass | checks_passed | 1 |
| `pkg:pypi/legacy@1.0` | unknown | stale_snapshot | 102 |
| `pkg:npm/unchecked@1.0` | unknown | unknown_check | 0 |
| `pkg:generic/unlisted@1` | unknown | unmapped_component | — |
| `local-file` | unknown | missing_purl | — |
| `release` | unknown | missing_purl | — |

There are **4 mapped, 4 joined, 3 fresh, 1 stale, 3 unmapped** components and
**3 selected repositories**. The two demo packages reuse the same snapshot ID.
`unchecked` retains both a `-1` Code-Review observation and a missing Security-Policy
check. A fresh snapshot is not necessarily a passing or complete snapshot.

For a release gate, add `--gate`. The sample above exits **1**, because its overall
decision is unknown. It still writes the full report. Without `--gate`, successful
processing exits **0** even when policy results fail or remain unknown.

| Exit | Meaning |
| --- | --- |
| 0 | Report written successfully; with `--gate`, every component passes |
| 1 | `--gate` withheld: at least one fail/unknown, or an empty inventory |
| 2 | Invalid/unsupported input, ambiguity, I/O, or invalid CLI arguments |

`report.gate.exitCode` always gives the exit code that **would** apply with `--gate`.
`missing: "unknown"` retains the distinction from failure; it does not grant a gate
pass without evidence. Aggregate decisions use `fail > unknown > pass`.

## Lint mappings before a join

Inspect the SBOM and mapping without loading Scorecard snapshots or policy:

```sh
vulnwrench scorecard lint-mappings examples/scorecard/lint-mappings/bom.json \
  --map examples/scorecard/lint-mappings/repos.json --output lint.json

# Writes the same report, exits 1 because the fixture has an ambiguous assignment:
vulnwrench scorecard lint-mappings examples/scorecard/lint-mappings/bom.json \
  --map examples/scorecard/lint-mappings/repos.json --strict --output lint.json
```

Advisory lint exits **0** on successfully analyzed inputs, including mappings with
conflicts. `--strict` exits **1** when any exact PURL assigns multiple distinct
canonical repositories, including unused PURLs. Malformed JSON, invalid PURLs,
unsupported SBOMs, invalid repository URLs and I/O errors exit **2**, preserving
any existing output. The command accepts `--output` with the same atomic output
protection as `check`, or writes to stdout. JSON remains the default and is
byte-identical to previous versions; `--format json` explicitly selects it. Select `--format markdown` for a
human-readable report:

```sh
vulnwrench scorecard lint-mappings examples/scorecard/lint-mappings/bom.json \
  --map examples/scorecard/lint-mappings/repos.json --format markdown --strict --output lint.md
```

[The literal Markdown contract](../examples/scorecard/lint-mappings/expected.md) specifies a
summary, one component row per occurrence (including ambiguous, unmapped and
missing-PURL rows), and one issue row per source location. Locations show the
input basename, JSON Pointer and 1-based repeated-key occurrence when present;
`—` means absent. The JSON evidence appendix decodes to the complete lint JSON,
including every mapping assignment, issue and input digest. It is the lint report,
not a copy of the original SBOM. Table text escapes HTML and Markdown punctuation
and flattens line breaks; the appendix retains original report strings losslessly
with HTML-safe JSON escapes and a backtick fence longer than any supplied run.
The human summary describes coverage, not a security decision.

Format selection never changes gate exit codes or report data. Malformed inputs,
invalid formats, protected output paths and failed writes exit **2**, without a
partial report or replacing existing output. A gate failure still writes the
complete Markdown report, just as for JSON. Empty inventories retain tables with
no component rows; `No issues.` is shown when there are no diagnostics.

To gate on mapping coverage, add `--fail-on-unmapped`. It exits **1** if any
component has `mappingStatus: "unmapped"` or `"missing_purl"` (the existing
`summary.unmappedComponents` count), and still writes the **same complete report**:

```sh
# Three components lack mappings/PURLs: exits 1, without loading any snapshots.
vulnwrench scorecard lint-mappings examples/scorecard/bom.json \
  --map examples/scorecard/repos.json --fail-on-unmapped --output lint.json

# Require both coverage and unambiguous assignments:
vulnwrench scorecard lint-mappings examples/scorecard/lint-mappings/bom.json \
  --map examples/scorecard/lint-mappings/repos.json --fail-on-unmapped --strict
```

The two flags are independent; neither changes advisory lint or report contents.
Ambiguous assignments are diagnosed separately and require `--strict` to withhold
success, including conflicts on unused PURLs. All enumerated component roles and
occurrences count, including subjects, nested components, pedigree and formulation.
An empty inventory has no coverage gaps and passes `--fail-on-unmapped`; this is a
mapping preflight, not the `check --gate` release policy.

| Valid input | Advisory | `--strict` | `--fail-on-unmapped` | Both flags |
| --- | --- | --- | --- | --- |
| All components mapped; only unused/same-repository duplicate warnings | 0 | 0 | 0 | 0 |
| Unmapped or missing-PURL component, no ambiguity | 0 | 0 | 1 | 1 |
| Ambiguous assignments only | 0 | 1 | 0 | 1 |
| Both ambiguity and coverage gaps | 0 | 1 | 1 | 1 |
| Empty inventory, no ambiguous assignments | 0 | 0 | 0 | 0 |

Invalid inputs, invalid arguments and output I/O/protection errors take precedence
over either gate: exit **2**, no partial report, and existing output preserved.

Lint reports `unused_mapping`, `unmapped_component`, `missing_purl`,
`ambiguous_mapping`, `duplicate_mapping` and `duplicate_repository_identifier`
issues, with an explanation and `locations[]`. A location names the input basename
and a JSON Pointer. Mapping locations also have a **1-based occurrence** number
for that exact decoded key in file order, so repeated keys remain distinguishable.
For example, `/pkg:npm~1demo@1.0` occurrences 1 and 2 identify the two conflicting
entries in [the mapping fixture](../examples/scorecard/lint-mappings/repos.json), while
`/components/0` identifies their affected component. JSON Pointer escapes `/` as
`~1` and `~` as `~0`. `inputs` records basenames and byte SHA-256 digests.

[The recorded CLI output](../examples/scorecard/lint-mappings/expected.json) contains:

| Input | Expected lint result |
| --- | --- |
| Two `pkg:npm/demo@1.0` entries assigning `example/demo` and `example/other` | `ambiguous_mapping`; component repository stays null |
| Helper assignment using `github.com/EXAMPLE/DEMO` | Same canonical repository as `https://GitHub.com/Example/Demo.git/`; duplicate identifier reported |
| Mapping for exact `pkg:npm/demo@2.0` | `unused_mapping` |
| Component `pkg:npm/demo@3.0`, with a VCS external reference | `unmapped_component`; repository stays null |
| Component without a PURL | `missing_purl`; component retained |

All four components remain in `components[]`; one is mapped, one ambiguous and two
unmapped (including the missing PURL). Lint never chooses a conflicting assignment
or infers repositories from component names, external references or other PURL
versions. `mappings[]` retains every entry with its canonical repository and source
location. `mappingStatus` describes mapping coverage, not a security decision.
Summary mapping counts use distinct PURLs; duplicate repository counts use distinct
canonical repositories with multiple mapping entries.

Repeated entries assigning the **same** canonical repository produce
`duplicate_mapping`, without ambiguity. Multiple entries sharing a repository
produce `duplicate_repository_identifier`, including legitimate many-to-one joins;
these are advisory and do not cause strict failure. Remove repeated JSON keys
before running `check`: its existing input validation still rejects **all** repeated
keys, and its unknown-component handling and evidence output are unchanged. Lint
intentionally retains repeated keys only in the top-level mapping object so that
all conflicts can be diagnosed together. Mapping values must still be strings.

The library API is `from vulnwrench.scorecard import lint_mappings`, followed by
`lint_mappings(bom_path, mapping_path)`. It returns the advisory report and raises
`InputError` for invalid inputs; use `report["summary"]["ambiguousMappings"]` for
a strict preflight. Lint reports can expose supplied PURLs and repository identities;
invalid-input stderr diagnostics do not echo input values.

## Compare two dated snapshot bundles

Use **one SBOM and one exact dependency mapping** for both bundles. Each bundle
is a native Scorecard JSON file or flat directory under the same input contract
as `check`. No policy is required: comparison covers the union of observed check
names, including future check names, and computes no overall security score or
release gate.

```sh
vulnwrench scorecard compare examples/scorecard/compare/bom.json \
  --map examples/scorecard/compare/repos.json \
  --before examples/scorecard/compare/before --before-as-of 2026-11-01 \
  --after examples/scorecard/compare/after --after-as-of 2026-11-11 \
  --max-age-days 2 --output comparison.json
```

Both cutoffs and the nonnegative age limit are explicit and required. The after
cutoff must be strictly later than the before cutoff, after UTC normalization.
Each bundle independently selects its newest snapshot at or before its cutoff;
there is **no fallback from an absent newer bundle to the older bundle**. Snapshot
age uses UTC calendar days relative to that side's cutoff; age equal to the limit
is fresh. Date-only cutoffs include the whole UTC day. No wall clock is consulted.

[The synthetic input](../examples/scorecard/compare/bom.json) has seven component occurrences and
four mapped repositories. Demo and helper share one repository comparison; two
components remain explicitly unmapped/missing-PURL. The
[complete recorded CLI output](../examples/scorecard/compare/expected.json) includes these
results, also specified in [hand-authored expectations](../examples/scorecard/compare/expected-changes.json):

| Repository / check | Raw change | Score comparison | Independent evidence |
| --- | --- | --- | --- |
| demo / Code-Review | 3 → 8; reason changed | increased | Fresh snapshots; repository commit changed |
| demo / License | Reason changed, score remains 5 | unchanged | Reason-only change stays visible |
| demo / Security-Policy | Deleted from newer checks | not_comparable | Whole newer snapshot exists |
| demo / Maintained | -1 → 10 | not_comparable | Baseline score was unknown |
| demo / Future-Check | Added | not_comparable | No baseline check |
| scanner / Code-Review | 3 → 8; reason changed | increased | Same repository commit; scanner version and revision changed |
| stale / Code-Review | 1 → 10 | not_comparable | Newer snapshot is 9 days old; commit changed |
| missing / Code-Review | Newer snapshot absent | not_comparable | Check deletion cannot be established |

The `scanner` fixture retains repository commit `3333333333333333333333333333333333333333`
on both sides. Scanner `v5.0.0` at `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` becomes
`v5.1.0` at `bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`. Its expected section is:

```json
"scannerChange": {
  "before": {"version": "v5.0.0", "commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
  "after": {"version": "v5.1.0", "commit": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
  "versionChange": "changed",
  "commitChange": "changed"
}
```

`summary.scannerChanges` counts the existing scanner classifications once per
canonical mapped repository, independently for `version` and `commit`. For the
command above, the literal [summary contract](../examples/scorecard/compare/expected-summary.json)
includes:

```json
"scannerChanges": {
  "version": {"changed": 1, "unchanged": 2, "not_comparable": 1},
  "commit": {"changed": 1, "unchanged": 2, "not_comparable": 1}
}
```

Each field's three counts sum to `summary.comparedRepositories` (four here).
Repeated/shared mapped components and duplicate snapshot files do not increase
counts; unused mappings, unmapped components and unselected snapshots do not add
repositories. Empty mapped inventories have all six counts zero, even when the
bundles contain evidence. Missing/future-only selections count `not_comparable`
for both fields. Missing, null, blank or non-string metadata counts
`not_comparable` for that field alone: a known partial field can still count
`changed` or `unchanged`. Stale, regressed or ambiguous evidence keeps its scanner
classifications in these counts while score direction remains withheld. Counts
establish neither score direction nor causal attribution. Invalid inputs still
fail before a report is emitted and preserve existing output as described below.

`summary.comparisonStatuses` counts each repository's existing `comparison`
classification once, using the same canonical mapped repository population as
`scannerChanges`. The command above includes this literal partition:

```json
"comparisonStatuses": {
  "comparable": 2,
  "missing_both": 0,
  "missing_after": 1,
  "missing_before": 0,
  "stale_after": 1,
  "stale_before": 0,
  "snapshot_time_regressed": 0,
  "snapshot_time_ambiguous": 0
}
```

All eight keys are always present and sum to `summary.comparedRepositories`.
Empty mapped inventories have eight zero counts. Shared/repeated components,
unused mappings and unselected/unmapped evidence follow the same counting rules
as the scanner summary. Missing/future-only selections count as missing; when
multiple blockers apply, only the existing first blocker counts: missing both,
missing after, missing before, stale after, stale before, regressed time, then
ambiguous time. A repository with none of these blockers counts as `comparable`,
even if a check's score is unknown or absent. These counts describe evidence
availability and chronology; they establish no aggregate score or causal claim.
Per-repository scanner/check classifications and score-direction rules remain
independent. Invalid inputs still preserve existing output.

`summary.snapshotChanges` counts the existing `snapshotChange` classifications
once per canonical mapped repository. For the command above, its literal partition
is:

```json
"snapshotChanges": {
  "advanced": 3,
  "unchanged": 0,
  "regressed": 0,
  "same_timestamp_changed": 0,
  "not_comparable": 1
}
```

All five keys remain present, including five zeros for empty mapped inventories,
and sum to `summary.comparedRepositories`. Shared/repeated components, unused
mappings and unselected snapshots follow the same population rules as the other
summaries. Missing or future-only selections on either side count
`not_comparable`; they never imply advancement or regression. Both selected
snapshots retain their chronology classification even when stale evidence takes
priority in `comparisonStatuses`. `unchanged` means the same complete snapshot
document, not merely the same timestamp or repository commit. Changed documents
at the same UTC instant count `same_timestamp_changed`. These counts describe
selected evidence chronology without establishing freshness, check-score direction,
scanner authenticity, repository ancestry or causality. Per-repository and raw
check/score semantics and invalid-input/output preservation remain unchanged.

`summary.checkChanges` partitions the existing raw `checks[].change` rows, once
per observed canonical mapped repository/check-name pair. The command above has
eight pairs, with this literal partition:

```json
"checkChanges": {
  "changed": 5,
  "unchanged": 0,
  "added": 1,
  "deleted": 1,
  "not_comparable": 1
}
```

All five keys are always present. Their sum equals the total number of check rows
across `repositories[]`, rather than `comparedRepositories` or component occurrences.
A name occurring in two repositories counts twice; repeated/shared components,
duplicate snapshot files, unused mappings and unselected snapshots add no pairs.
Names come from the union of checks in each repository's selected snapshots.
An empty union contributes no pairs: empty mapped inventories, two missing/future-only
selections and two selected snapshots with empty checks all retain five zero counts.

These are raw document changes: `unchanged` means the complete check objects are
equal; `changed` includes reason-only, extension-only and absent-versus-null changes.
Unknown/absent/null/negative scores retain their raw change classification while
score direction remains `not_comparable`. `added`/`deleted` require both snapshots;
if either selected snapshot is missing/future-only, every observed name counts
`not_comparable`, never an addition/deletion. Stale, regressed and ambiguous evidence
retains its raw changes while score direction remains withheld. The Markdown
coverage view presents this same partition in a separate table labeled
**Repository/check pairs**; its complete JSON appendix retains identical summary
and raw evidence. Counts imply no score direction, score quality, security gate or
causal attribution. Existing invalid-input, protected-path and atomic-output exits
are unchanged. This summary is additive under `reportVersion: "1"`.

`summary.checkScoreChanges` partitions the same observed repository/check pairs
using only their existing `checks[].scoreChange` classifications. The fixture has:

```json
"checkScoreChanges": {
  "increased": 2,
  "decreased": 0,
  "unchanged": 1,
  "not_comparable": 5
}
```

All four keys are always present, including four zeros for empty observations.
Their sum equals `checkChanges`' total. Canonical mapping, selected-snapshot and
pair deduplication rules are identical to the raw partition above. Known scores
on both fresh, chronologically comparable sides establish numeric direction;
zero is known. Unknown/absent/null/negative scores, added/deleted check names,
missing/future-only selections and stale/regressed/ambiguous evidence keep
`not_comparable`. Reason/extension changes can retain an `unchanged` score direction.
The separate Markdown **Check score direction** / **Repository/check pairs**
table shows the same four buckets, including zeros, with the full JSON appendix.
Counts describe supplied numeric score directions, without inferring score quality,
security, causality or a gate. This is additive under `reportVersion: "1"`; raw
check-change counts, records, evidence and input/output exits remain unchanged.

`summary.checkScoreChangesByCheck` groups those same existing score directions
by exact observed check name. Its name-sorted array has one object per name, with
`name`, `increased`, `decreased`, `unchanged` and `not_comparable` always present,
including zeros. The fixture has:

```json
"checkScoreChangesByCheck": [
  {
    "name": "Code-Review",
    "increased": 2,
    "decreased": 0,
    "unchanged": 0,
    "not_comparable": 2
  },
  {
    "name": "Future-Check",
    "increased": 0,
    "decreased": 0,
    "unchanged": 0,
    "not_comparable": 1
  },
  {
    "name": "License",
    "increased": 0,
    "decreased": 0,
    "unchanged": 1,
    "not_comparable": 0
  },
  {
    "name": "Maintained",
    "increased": 0,
    "decreased": 0,
    "unchanged": 0,
    "not_comparable": 1
  },
  {
    "name": "Security-Policy",
    "increased": 0,
    "decreased": 0,
    "unchanged": 0,
    "not_comparable": 1
  }
]
```

For each name, all four counts sum to its canonical repository/check pairs;
each direction column recovers `summary.checkScoreChanges`. Increased + decreased
+ unchanged equals that name's `checkScoreComparabilityByCheck.comparable` count;
not_comparable equals its evidence_blocked + observation_blocked counts. Repeated
names across distinct repositories combine. Exact case, whitespace and Unicode
remain distinct. Canonical aliases, shared/repeated components and duplicate
snapshots do not multiply counts; unused mappings and unselected evidence add
no names. An empty selected-name union returns `[]`, without an expected check list.

This reuses `scoreChange` without reclassifying unknown, missing, future-only,
stale, regressed or ambiguous evidence. Markdown adds a **Check** / **Score
direction** / **Repository/check pairs** table with four rows per name including
zeros, or only the labeled header for no names. Counts describe supplied numeric
direction, without inferring score quality, security, causality or a gate. The
array and table are additive under `reportVersion: "1"`; previous JSON/Markdown,
raw evidence and input/protected/atomic-output exits remain unchanged.

`summary.checkScoreComparability` explains support for numeric direction over the
same selected canonical repository/check pairs. The fixture has:

```json
"checkScoreComparability": {
  "comparable": 3,
  "evidence_blocked": 2,
  "observation_blocked": 3
}
```

Classification reuses existing rows in this priority order: a `scoreChange` other
than `not_comparable` counts `comparable`; otherwise an owning repository
`comparison` other than `comparable` counts `evidence_blocked`; all remaining pairs
count `observation_blocked`. Evidence blockers take priority over observation gaps
when both apply. These disjoint counts do not enumerate every simultaneous blocker.
Stale, regressed and ambiguous known-to-known rows are evidence blocked; unknown,
negative or missing scores and absent checks in comparable repositories are
observation blocked. Missing/future-only selections are evidence blocked when a
selected check name exists on the other side.

All three keys always appear, including zeros for empty observed name unions.
Each pair counts once. The total equals `checkChanges`, `checkScoreChanges` and
`checkObservationTransitions` totals (eight here); the two blocked buckets sum to
`checkScoreChanges.not_comparable` (five here). Canonical aliases, shared/repeated
components and duplicate snapshots add no pairs; unused mappings and unselected
evidence remain excluded from counts and retained as evidence. Comparable means
support for supplied numeric direction, not security, score quality, causality or
a gate. Markdown includes a **Check score comparability** / **Repository/check
pairs** table and the complete JSON appendix. This is additive under
`reportVersion: "1"`; existing classifications, evidence and input/protected-path/
atomic-output exits remain unchanged.

`summary.checkScoreComparabilityByCheck` breaks down that same partition by exact
observed check name. Its check-name-sorted array contains one object per name,
with `name`, `comparable`, `evidence_blocked` and `observation_blocked` always
present, including zero counts. The fixture has:

```json
"checkScoreComparabilityByCheck": [
  {"name": "Code-Review", "comparable": 2, "evidence_blocked": 2, "observation_blocked": 0},
  {"name": "Future-Check", "comparable": 0, "evidence_blocked": 0, "observation_blocked": 1},
  {"name": "License", "comparable": 1, "evidence_blocked": 0, "observation_blocked": 0},
  {"name": "Maintained", "comparable": 0, "evidence_blocked": 0, "observation_blocked": 1},
  {"name": "Security-Policy", "comparable": 0, "evidence_blocked": 0, "observation_blocked": 1}
]
```

For each name the three counts sum to its canonical repository/check pairs;
each classification column sums to `summary.checkScoreComparability`. Repeated
names across distinct repositories combine, while aliases, shared/repeated
components and duplicate snapshots do not multiply counts. Names retain exact
case, whitespace and Unicode; no expected check list or names from unused or
unselected evidence are inferred. An empty selected-name union returns `[]`.
The existing priority applies unchanged, including simultaneous evidence and
observation blockers. Comparable supports numeric direction and does not imply
security or causality. Markdown adds a **Check** / **Comparability** /
**Repository/check pairs** table with three rows per name, including zeros;
empty observations retain only the labeled header. The full appendix includes
the additive array under `reportVersion: "1"`.

`summary.checkObservations` counts the existing `beforeObservation` and
`afterObservation` labels separately over those same observed repository/check
pairs. The fixture's literal partitions are:

```json
"checkObservations": {
  "before": {"known": 6, "negative_score": 1, "missing_score": 0, "missing_check": 1, "missing_snapshot": 0},
  "after": {"known": 6, "negative_score": 0, "missing_score": 0, "missing_check": 1, "missing_snapshot": 1}
}
```

Both sides always contain all five keys. Each side sums to both `checkChanges`
and `checkScoreChanges` totals (eight here), with all zeros when no check names
are observed. The same canonical mapping, selected-snapshot and deduplication
rules apply. `known` includes zero; `negative_score` is the supplied -1 sentinel;
`missing_score` includes absent and null scores on an existing check. An absent
name in an available snapshot is `missing_check`; a missing/future-only selected
snapshot is `missing_snapshot`. Unsupported score types remain invalid input,
rather than becoming a new unknown bucket. Stale, regressed and ambiguous
snapshots retain their raw observations, even when both scores are known and
score direction is withheld. Thus these marginal counts explain coverage gaps
without establishing pairwise score comparability, score quality, causality or a
gate. Markdown shows the same partitions in a **Side** / **Observation** /
**Repository/check pairs** table and retains the complete JSON appendix. This
is additive under `reportVersion: "1"`; raw changes, score directions, evidence
and input/protected-path/atomic-output exits remain unchanged.

`summary.checkObservationTransitions` adds the joint distribution of the same
pairs, indexed first by before observation and then by after observation. All five
labels above appear on both axes: all 25 cells are always present, including zeros
and empty inventories. For the fixture, only known→known=4,
known→missing_check=1, known→missing_snapshot=1, negative_score→known=1 and
missing_check→known=1 are nonzero. The complete literal matrix is in
[expected-summary.json](../examples/scorecard/compare/expected-summary.json).

Each canonical mapped repository/check row counts exactly once. The matrix total
is eight here and equals both check partitions; row sums equal the before
`checkObservations` and column sums equal the after partition. Missing/null scores,
-1, absent checks and unavailable snapshots retain their existing labels. Unused
mappings, unselected evidence, aliases and duplicate/shared component occurrences
do not add pairs. No observed check names means 25 zeros, even for mapped
repositories. In particular, missing→missing cells can remain zero because names
come from the union of selected checks, rather than an expected check list.

The matrix identifies persistent, resolved and new observation gaps. Known→known
also includes stale, regressed and ambiguous pairs and does not establish score
direction, freshness, security or causality. Markdown shows all 25 cells in a
**Before observation** / **After observation** / **Repository/check pairs** table.
This is additive under `reportVersion: "1"`; the marginal counts, raw records,
score directions, evidence appendix and input/protected/atomic-output exits remain
unchanged.

`repositories[]` is sorted by canonical repository; each entry separates:

- `before`/`after`: selected snapshot ID, UTC timestamp, age, repository commit and
  status (`fresh`, `stale`, `missing_scorecard` or `no_snapshot_as_of`). Future-only
  snapshots are unavailable at the cutoff, and remain in the evidence appendix.
- `commitChange`: `changed`, `unchanged` or `not_comparable` when either snapshot
  is absent. This compares supplied `repo.commit` strings, including for stale
  evidence; it does not infer ancestry, inspect code or attest a package release.
- `scannerChange`: `before`/`after` scanner identities (`version` and `commit`),
  plus independent `versionChange`/`commitChange` classifications. Each is
  `changed` or `unchanged` only when both selected snapshots supply a nonblank
  string for that field; otherwise it is `not_comparable`. Strings compare
  exactly, without version ordering, trimming or commit-prefix expansion.
  An absent selected snapshot has a null identity; absent, null, blank or
  non-string metadata values become null fields. A missing/non-object
  `scorecard` becomes an identity with both fields null. These optional metadata
  gaps remain valid inputs, and the original values stay in the full documents.
  Only selected snapshots contribute; stale or ambiguous scan times do not hide
  scanner identity differences. Extra scanner fields are not classified.
- `snapshotChange`: `advanced`, `unchanged`, `regressed`, `same_timestamp_changed`
  or `not_comparable`. Reused snapshots are explicit even if they become stale.
- `comparison`: `comparable`, `missing_both`, `missing_after`, `missing_before`,
  `stale_after`, `stale_before`, `snapshot_time_regressed` or
  `snapshot_time_ambiguous`, in that blocker priority. Both side statuses remain
  visible when there is more than one blocker.
- `checks[]`: sorted check names with raw `before`/`after` check objects,
  `change` (`added`, `deleted`, `changed`, `unchanged`, `not_comparable`),
  `scoreChanged` and `reasonChanged`. Field changes distinguish absent fields from
  JSON null. Whole-check changes include details and extension fields. When a
  snapshot is missing, field-change flags are null and no deletion/addition is
  inferred. Observations distinguish `known`, `negative_score`, `missing_score`,
  `missing_check` and `missing_snapshot` independently of snapshot freshness.

`scoreChange` is `increased`, `decreased` or `unchanged` **only when both snapshots
are fresh, both check scores are known (0–10), and snapshot time has not regressed
or become ambiguous**. Otherwise it is `not_comparable`; raw differences remain
visible. Missing or stale newer evidence can never establish an increase. A score
increase is an observation from the supplied scans, not a security certification;
scanner version, permissions and configuration may differ. `scannerChange` exposes
the supplied version/revision differences without attributing check changes to
them or changing score-direction rules. Equal scanner strings do not prove equal
configuration or permissions. No new aggregate score is computed. Upstream
aggregate scores remain only in the original documents.

Conflicting snapshots at the same repository/time **within a bundle** are invalid,
as for `check`. Different documents at the same timestamp **across the two
bundles** are retained as `same_timestamp_changed`, with directional comparisons
withheld. Full documents, byte digests, unselected snapshots and source basenames
are retained in `before.snapshots` and `after.snapshots`; the shared original SBOM
and mapping are in `inputs`. Component rows preserve every inventory occurrence
and reference the repository comparison through `repository`.

By default, successful comparison exits **0**, including missing/stale evidence.
Add `--fail-on-decrease` to exit **1** if at least one observed canonical
repository/check pair has the existing `scoreChange: "decreased"` classification
(`summary.checkScoreChanges.decreased > 0`). It still writes the same complete
report to stdout or an atomic `--output` file, byte for byte, in JSON or Markdown.
This flag adds no policy or numeric reclassification. Repeated components and
canonical repository aliases do not multiply pairs; an increase elsewhere does
not cancel a decrease.

With the flag, exit **0** means **no comparable decrease observed**. Empty
observations, unknown/negative/absent/null scores, added/deleted checks,
missing/future selections and stale/regressed/ambiguous evidence cannot create a
decrease. Exit 0 does not establish complete evidence or a security pass. The
sample above has zero decreases and exits 0 with the flag; a comparable known
score falling from 10 to 0 exits 1. The library `compare` API remains advisory.

```sh
# No comparable decrease in this fixture: exits 0; same complete JSON report.
vulnwrench scorecard compare examples/scorecard/compare/bom.json \
  --map examples/scorecard/compare/repos.json \
  --before examples/scorecard/compare/before --after examples/scorecard/compare/after \
  --before-as-of 2026-11-01 --after-as-of 2026-11-11 --max-age-days 2 \
  --fail-on-decrease --output comparison.json
```

### Focusing on selected check names

Add the repeatable `--check NAME` to focus the check-level view on explicitly
named checks. Names match **exactly** (case, whitespace and Unicode normalization
form are significant; no inference). They are separate from the join's policy
check list, may name future checks not yet observed, and may repeat without
multiplying rows. A name that no selected snapshot observes creates no synthetic
row. Selectors must be nonempty and may not contain control characters (such
names cannot be observed, because snapshot check names reject them); the library
equivalent is `compare(..., checks=[...])`, where an empty list selects nothing.

With at least one selector, the JSON report gains `checkSelection.names` (sorted,
deduplicated) and Markdown prints a "Check scope" paragraph with the names as JSON
literals. Repository check rows and every check-level summary
(`checkChanges`, `checkScoreChanges`, `checkObservations`,
`checkObservationTransitions`, `checkScoreComparability` and the two per-check
arrays) then use the one selected population; no match yields zero partitions and
empty arrays. Repository, component, snapshot and scanner counts keep their
mapped-repository population, and the complete before/after snapshots, including
unselected checks, remain in the report. Existing `scoreChange`, unknown, stale,
regressed and ambiguous classifications are unchanged. Without `--check`, report
bytes and exit codes are unchanged.

With `--fail-on-decrease`, only selected comparable pairs can fail: an unselected
decrease does not fail the command, and zero selected observations means no
comparable decrease observed, not complete evidence or a security pass.

```sh
vulnwrench scorecard compare examples/scorecard/compare/bom.json \
  --map examples/scorecard/compare/repos.json \
  --before examples/scorecard/compare/before --after examples/scorecard/compare/after \
  --before-as-of 2026-11-01 --after-as-of 2026-11-11 --max-age-days 2 \
  --check License --check Not-Observed --check Future-Check   # == examples/scorecard/compare/expected-selected.json
```

Invalid input, non-increasing cutoffs, conflicts within a bundle and I/O errors exit **2**, with
no partial report and any existing output preserved. Both formats support
stdout/`--output` and atomic input/hardlink/symlink protection as for `check`,
covering both bundles. There is no comparison `--gate`.

JSON remains the default; `--format json` produces identical bytes. For Markdown:

```sh
vulnwrench scorecard compare examples/scorecard/compare/bom.json \
  --map examples/scorecard/compare/repos.json \
  --before examples/scorecard/compare/before --after examples/scorecard/compare/after \
  --before-as-of 2026-11-01 --after-as-of 2026-11-11 --max-age-days 2 \
  --format markdown --output out.md
```

The literal [Markdown contract](../examples/scorecard/compare/expected.md) was established
before the renderer and is checked byte for byte. Its coverage tables retain all
comparison-status, snapshot-change, scanner version/commit, raw-check-change and
check-score-direction buckets, including zeros and `not_comparable`. Raw changes,
score directions, global/per-check score comparability, observations and joint
transitions have separate repository/check-pair coverage tables.
Component rows retain every occurrence and its role,
mapping status and JSON Pointer. Each canonical mapped repository has a summary
row plus before/after evidence status, timestamp, age and repository commit;
scanner identity/change rows; and raw per-check score/reason changes, observations,
field-change flags and score direction. Empty mapped inventories show zero
coverage and an explicit empty repository section.

Missing evidence (`missing_scorecard`), future-only evidence (`no_snapshot_as_of`),
staleness, regressed time and same-time ambiguity stay explicit. Scanner/status
counts never imply score direction, a gate or causal attribution. Missing scanner
metadata is an em dash and remains `not_comparable`. Raw score/reason fields use
JSON literals: `absent` differs from supplied `null` or a quoted string; an em dash
means there was no check/snapshot. Unknown or negative scores retain their
observations and withhold direction.

Supplied Markdown punctuation and HTML are escaped. Table line separators are
flattened; raw score/reason literals escape control characters. The complete
comparison JSON appendix preserves exact strings, all original inputs and
snapshots (including future/unselected evidence), metadata, raw check extensions
and source digests. Its fence grows beyond supplied backtick runs, and HTML-sensitive
characters use lossless JSON Unicode escapes. This is an evidence view and retains
any secrets present in supplied documents, as JSON does.

The library API is:

```python
from vulnwrench.scorecard import compare

report = compare("examples/scorecard/compare/bom.json", "examples/scorecard/compare/repos.json",
                 "examples/scorecard/compare/before", "examples/scorecard/compare/after",
                 "2026-11-01", "2026-11-11", max_age_days=2)
# Invalid input raises InputError; the library never prints or exits.
```

## Supported input contract

All inputs are local UTF-8 JSON objects (optional UTF-8 BOM accepted). Repeated
JSON keys (except mapping entries inspected by lint), non-finite numbers, malformed
encoding, and unpaired Unicode surrogates are errors. Each file is limited to
**16 MiB**, all inputs together to **128 MiB**.
Non-regular input files and excessively nested documents are rejected. This is a
validator of the fields consumed below, not a complete CycloneDX JSON Schema
validator. Unknown extension fields are retained in the original documents, not
used to infer security decisions.

### CycloneDX 1.4, 1.5 or 1.6 JSON

Require `bomFormat: "CycloneDX"`, string `specVersion` in `1.4`, `1.5`, `1.6`, and a
positive integer BOM `version`. Read every component in top-level `components`,
recursive child `components`, and `metadata.component`. Also enumerate component
`pedigree.ancestors/descendants/variants` and 1.5/1.6 `formulation[].components`, with
explicit `role` and JSON Pointer `path`. All these roles count toward the gate;
the root subject and components without PURLs are deliberately **not skipped**.

Require component `name` and `type` strings. `bom-ref` and `purl` are optional;
duplicate `bom-ref` values are errors. Each occurrence gets its own row, including
repeated PURLs. A component identifier is its PURL, otherwise `bom-ref`, otherwise
its structural path. Services and dependency edges are preserved as source data;
they are not packages or evidence of repository identity.

Syft's **CycloneDX JSON output** and CycloneDX CLI's **CycloneDX JSON output** can
be supplied within this contract. Native Syft JSON, SPDX, XML, JSONL, wrappers or
other schema versions are not supported and result in exit 2. No format converter
is invoked. Unsupported versions are never accepted as a best-effort approximation.

### Exact mapping JSON

```json
{
  "pkg:npm/demo@1.0": "https://github.com/example/demo"
}
```

Keys are exact PURLs: version, qualifiers, case and escaping are not rewritten.
Validation checks only the `pkg:type/name` structure and absence of whitespace;
this is **not** a complete PURL canonicalizer. Supply canonical PURLs in both inputs
if that is required for your workflow. `check` rejects contradictory/repeated
mapping keys, including repeated keys with the same value; use `lint-mappings`
to inspect them before a join. In join reports, unused keys are listed in
`summary.unusedMappings`.

Repository identifiers must explicitly contain an HTTPS host and at least two path
segments. Native Scorecard's scheme-less `github.com/owner/repo` form is also
accepted. Host names are lowercased, a trailing slash and `.git` suffix removed,
and GitHub owner/repository case folded. GitHub URLs require exactly two path
segments. Other DNS hosts support nested namespaces and retain path case; redirects,
renames and cross-host aliases are not inferred. SSH/HTTP URLs, credentials, ports,
query/fragment data, percent escapes, non-ASCII path segments, empty/dot segments
and shorthand `owner/repo` are unsupported and rejected. No repository lookup occurs.
`externalReferences`, package names and homepage fields never create mappings.

### Native Scorecard JSON snapshots

`--scorecards` accepts either a single JSON file or a flat directory containing
only regular `.json` files. An empty directory is valid missing evidence.
Subdirectories, symlinks in directories and other file types are errors, not
silently ignored. Every supplied snapshot is validated, including unmapped repos.

```json
{
  "date": "2026-11-10T12:00:00Z",
  "repo": {"name": "github.com/example/demo", "commit": "1111111111111111111111111111111111111111"},
  "scorecard": {"version": "v5.0.0", "commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
  "score": 8.4,
  "checks": [{"name": "Code-Review", "score": 8, "reason": "Synthetic evidence"}]
}
```

Require `repo.name`, a nonempty `repo.commit`, `date`, and a `checks` array with
unique nonempty names. Check scores are integers from **-1 through 10**; null or
absent score values remain unknown. Absent checks also remain unknown. Optional
upstream aggregate `score` is a finite number from -1 through 10. It is preserved
verbatim as `upstreamScore`, never substituted for individual checks or recomputed.
All other native fields, including details, documentation, scorecard version,
annotations, metadata and future check names, are retained in `snapshots[].document`.

Snapshot `date` accepts an ISO date or timezone-aware RFC3339 timestamp, with at most
six fractional second digits. Date-only snapshots mean midnight UTC. `--as-of` is
**required** and accepts the same syntax; a date means the inclusive end of that
UTC day. Offsets are normalized to UTC. No wall clock is consulted.

For each normalized repository, select the newest snapshot **at or before** the
instant. Future snapshots remain in evidence and are excluded from evaluation.
If only future snapshots exist, the component reason is `no_snapshot_as_of`; no
snapshots means `missing_scorecard`. Identical parsed documents (ignoring key order
and whitespace) are stored once with all source digests. Different documents at
the same normalized repository and timestamp are an error, even if older than the
selected snapshot. Different timestamps have a deterministic newest selection.

### Policy JSON

```json
{
  "checks": {"Code-Review": 7},
  "maxAgeDays": 30,
  "missing": "unknown"
}
```

All three fields are required; extra policy fields are errors. `checks` must be
nonempty; thresholds are finite JSON numbers in **[0, 10]**, with an inclusive
`score >= threshold` comparison. Booleans and numeric strings are not thresholds.
Supported policy names are:

```text
Binary-Artifacts, Branch-Protection, CI-Tests, CII-Best-Practices,
Code-Review, Contributors, Dangerous-Workflow, Dependency-Update-Tool,
Fuzzing, License, Maintained, Packaging, Pinned-Dependencies, SAST,
SBOM, Security-Policy, Signed-Releases, Token-Permissions,
Vulnerabilities, Webhooks
```

An unknown policy check name is an error to catch typos. Future names in evidence
are preserved but cannot yet be selected by policy. `maxAgeDays` is a nonnegative
integer: age is the difference in **UTC calendar dates**, not elapsed 24-hour
periods. An age exactly equal to the limit is fresh. Stale snapshots remain joined
and visible; they cannot establish current threshold compliance.

`missing` is either `unknown` or `fail`. It applies to unmapped components, absent
PURLs/snapshots, stale evidence, absent checks/scores and score `-1`. The raw unknown
observation remains visible even when policy converts its decision to `fail`.
Known below-threshold fresh checks fail independently of this missing setting.

## Report and library

`components[]` holds identities, paths, roles, repository, snapshot reference,
original aggregate score, age, per-check observed score/threshold/decision/reason,
and the configured component decision. `repositoryIndex` records available,
selected and future snapshot IDs. `snapshots` indexes complete native documents
once for reuse. Unselected and unmapped snapshots remain in that evidence list.

`inputs` includes **complete original SBOM, mapping and policy objects**, each with
a SHA-256 of its original file bytes. Snapshot sources likewise include original
file-byte digests; snapshot IDs hash deterministic JSON with sorted object keys.
Only snapshot basenames are recorded, so relocating the inputs does not change
output. Digests establish input identity, not signatures, authenticity or trust.

Markdown provides a component table and a lossless JSON evidence appendix. JSON
and Markdown are deterministic for the same input bytes/names and `--as-of`.
Diagnostics intentionally omit input values and operating-system error details.
**Reports retain supplied content and can contain secrets present in source data**;
only error diagnostics are designed not to echo them.

```python
from vulnwrench.scorecard import InputError, check, gate_exit_code, render_markdown

report = check("examples/scorecard/bom.json", "examples/scorecard/repos.json",
               "examples/scorecard/scorecards", "examples/scorecard/policy.json", "2026-11-11")
assert report["summary"]["components"] == 7
assert gate_exit_code(report) == 1
markdown = render_markdown(report)
# Catch InputError for invalid inputs. The library does not print or exit.
```

## Verify

The unittest suite in `tests/scorecard/` covers real CLI JSON/Markdown and gate
behavior, all three supported CycloneDX versions, repository reuse, date/age
boundaries, unknown observations, preservation, conflicting evidence, unsupported
inputs, secret-safe errors, atomic output protection, mapping-lint locations, exact
PURLs, retained ambiguity and strict/advisory exits. The comparison tests cover
score/reason/detail changes, added/deleted checks, missing/stale/future evidence,
unknown scores, scanner version/commit changes, time regression/ambiguity,
provenance, the shared input budget, every comparison-status and snapshot-change
summary, the 36 score-state pairs, per-check breakdowns, `--fail-on-decrease` exit
contracts and `--check` selection.

The executable verifier compares actual CLI output byte for byte with the recorded
JSON/Markdown under `examples/scorecard/`, and exercises passing, failing, missing and
invalid inputs:

```sh
python3 scripts/scorecard/verify_examples.py
```

## Relationship to upstream and limits

[Scorecard](https://github.com/ossf/scorecard) already implements its own checks and
scores. [Dependency-Track #3048](https://github.com/DependencyTrack/dependency-track/issues/3048)
already proposes showing Scorecard evidence and defining policies. This command's
specific scope is an **offline evidence join for a supplied release SBOM**, with
explicit package-to-repository mapping, temporal coverage and unknown handling.
It is not a replacement for those projects or a claim of novel scoring.

[Syft](https://github.com/anchore/syft) and
[CycloneDX CLI](https://github.com/CycloneDX/cyclonedx-cli) produce/transform SBOMs;
this command consumes their documented CycloneDX JSON format. No upstream executable
or API key is needed. See [THIRD_PARTY.md](../THIRD_PARTY.md) for licensing. No upstream source code
was used to implement the tool.

Repository health snapshots do **not** prove that a package version was built from
the recorded repository commit. Mapping correctness, snapshot authenticity, scan
permissions and completeness are the caller's responsibility. This MVP has no
signature verification, general schema conversion, remote freshness guarantees,
repository scanning, holistic trust certification or release-commit attestation.
Large reports retain full evidence and are intended for bounded local inputs.
