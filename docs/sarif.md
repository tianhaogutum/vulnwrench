# vulnwrench sarif

Most CI gates count SARIF results at `warning` or `error` and fail the build, which blocks on
findings a reviewer already accepted as suppressed, misses results that only inherit a level from
their rule, and passes silently when the scanner itself crashed. `vulnwrench sarif check` applies
an explicit policy to a SARIF 2.1.0 file and explains, result by result, why each one does or does
not block: accepted suppressions, rule default levels, an optional baseline report, and scanner
execution failures. Use it as the final gate after any SARIF-producing scanner (Semgrep, CodeQL,
Trivy, Gitleaks and others).

_Formerly the standalone `sarif-gate` tool._

It never runs a scanner, target code, or report-specified commands, and reads only the files you
name. Standard library only.

## Quick start

From a clone of the repository (synthetic fixtures under [`examples/sarif/`](../examples/sarif/)):

```sh
vulnwrench sarif check examples/sarif/semgrep.sarif --level warning --output out.json --markdown out.md
vulnwrench sarif check examples/sarif/baseline/current.sarif \
  --baseline examples/sarif/baseline/before.sarif --fingerprint primary/v1
```

The first command exits **0**, writes JSON plus Markdown, and has no stdout.
Without `--output`, the report goes to stdout. `-` reads UTF-8 JSON from stdin.
`--format markdown` selects Markdown for the main output. `--markdown PATH`
always writes an additional summary; use JSON as the durable audit artifact.
Parent output directories must already exist. The second command compares against a
prior report by one explicit `result.fingerprints` key
([details below](#optional-two-report-baseline-view)).

In CI, put it after the scanner step:

```sh
semgrep scan --sarif --output semgrep.sarif || true   # any SARIF producer
vulnwrench sarif check semgrep.sarif --level error --require-execution-success --markdown gate.md
```

## Commands and policy

```sh
# Gate at error level, requiring explicit successful scanner execution evidence:
vulnwrench sarif check examples/sarif/clean.sarif --level error --require-execution-success

# Explicitly opt out of gating unchanged baseline results (exits 0):
vulnwrench sarif check examples/sarif/unchanged.sarif --ignore-unchanged

# No findings, but scanner failure: exits 1 and emits a failed decision:
vulnwrench sarif check examples/sarif/failed-invocation.sarif

# Unsupported version: exits 2 with a sanitized diagnostic:
vulnwrench sarif check examples/sarif/invalid-version.sarif
```

Exit **0** means the chosen gate policy passed; **1** means a blocking finding or
scan-status policy violation; **2** means malformed/unsupported input, invalid
arguments, size limit, or I/O failure. A policy failure still emits the report.
An input error emits no report, and does not replace an existing report file.
Each file write is atomic, but writing JSON and Markdown together is not a
transaction: one file can exist if the other destination fails. Input/output
aliases, including baseline/manifest inputs and hard links, are rejected.

The default blocking threshold is `warning`; `note` and `error` are also valid.
`none` never blocks. `actionable` counts **blocking results at the configured
threshold**, not scanner failures. `eligible` counts results before threshold
filtering. A failed invocation blocks independently of suppression and threshold.

## Optional two-report baseline view

Use one explicit **full** `result.fingerprints` key from both reports:

```sh
vulnwrench sarif check examples/sarif/baseline/current.sarif \
  --baseline examples/sarif/baseline/before.sarif --fingerprint primary/v1
```

This synthetic SARIF 2.1.0 example exits **1** because current finding C blocks.
The baseline has A/B/D; the reordered current report has C/D/A. The JSON adds
`baselineComparison` with this expected subset:

```json
{
  "status": "compared",
  "counts": {"newly_observed": 1, "retained": 2, "absent": 1, "ambiguous": 0}
}
```

A remains accepted-suppressed on both sides. D is below threshold. B is absent
from the current report. The baseline's blocking B does not enter the current
gate. Every comparison entry retains separate baseline/current result traces,
including suppression statuses and source pointers; full original evidence and
byte digests are retained for both inputs. Markdown includes the comparison and
separate execution statuses; JSON holds the full audit detail.

Matching is exact and conservative:

- Tool identity is driver `name` plus `guid`, `version`, and `semanticVersion`
  when supplied. Presence and values must agree. Without a run-pairing manifest,
  exactly one run per tool identity per report is supported; run order does not
  matter. Unpaired or duplicate tool runs remain ambiguous, including tool
  version changes. An explicit manifest can distinguish same-tool runs, as below.
- The caller selects one nonempty fingerprint key. Only that key in full
  `fingerprints` is used; there is no fallback to `partialFingerprints`, messages,
  locations, result positions, or a generated hash. Fingerprint maps must have
  nonempty string values. Rule identity uses the resolved rule ID plus catalog
  `guid` when supplied, never the rule's array index. Rule/result/catalog ordering
  can change. A shared fingerprint with a different rule identity is ambiguous.
- Duplicate selected fingerprint values within a tool run are ambiguous, even
  across different rules. Every colliding trace is retained. Missing selected
  fingerprints, missing rule identity, or explicit `baselineState: absent`
  placeholders make the entire tool-run pair ambiguous. This prevents an
  unidentified current result from making a baseline result appear absent.
- Both reports need explicit successful invocation evidence, at least one run,
  and explicit result collections. An execution failure or error notification in
  either report makes the whole view `invalid`; unknown execution or missing
  collections makes it `ambiguous`. These states emit no absent classifications.
  Explicit empty `results: []` with successful execution can yield an
  observational absence. Even then, **absence never proves a vulnerability fixed
  or full scan coverage**. `retained` means identity matched; severity, message,
  location, and suppression status may have changed.

`counts` count grouped comparison entries; an ambiguous collision entry can
contain multiple results. `issues` and per-entry `reasons` explain uncertainty.
For an executable failure example, replace `current.sarif` above with
`examples/sarif/baseline/failed.sarif`: it exits **1**, has zero actionable findings,
one scan failure, comparison status `invalid`, and **zero absent** entries.

The view does **not** rewrite `baselineState`, ignore retained findings, carry
forward suppressions, or change the current gate decision/exit code. In
particular, an invalid/ambiguous view can accompany exit 0 when only the baseline
failed or current execution is unknown under the default permissive gate policy.
Inspect `baselineComparison.status` when consuming the view; use
`--require-execution-success` to require current execution evidence for the gate.
Malformed baseline JSON or consumed fields exit **2** without replacing outputs.
Both CLI flags must be supplied together. The baseline must be a file; the
current input may still use stdin. `--max-bytes` bounds each input separately.

Library equivalent:

```python
from vulnwrench.sarifgate import compare_bytes

report = compare_bytes(current_bytes, baseline_bytes, fingerprint="primary/v1")
```

Without baseline options the existing single-report output is unchanged.
`evidence.uninterpretedFields` inventories fields unused by the **gate policy**;
selected fingerprints and identity metadata are interpreted separately by the
comparison view. No report's authenticity, target identity, or scan scope is
verified. Different targets using identical tool identities cannot be detected;
provide reports for the same intended target. Multiple same-tool runs require
the explicit run correspondence described below.

## Explicit run-pairing manifest

For repeated runs from the same tool, supply `--run-pairing FILE` together with
`--baseline` and `--fingerprint`. The manifest is a separate UTF-8 JSON object:

```json
{
  "baseline": [{"runIndex": 0, "pairId": "api"}, {"runIndex": 1, "pairId": "web"}],
  "current": [{"runIndex": 1, "pairId": "api"}, {"runIndex": 0, "pairId": "web"}]
}
```

Indexes select runs **within each input**, starting at zero. Equal `pairId`
strings declare correspondence; neither run order nor finding content chooses a
partner. Every run must appear exactly once; each pair ID must occur exactly
once per side and have a counterpart on the other side. Lists may be reordered.
Pair IDs are caller assertions of target/scope correspondence, not verification.
Exact tool identity, rule identity, fingerprint and execution requirements still
apply. Fingerprint collisions are checked within each declared pair.

```sh
vulnwrench sarif check examples/sarif/baseline/multi-current.sarif \
  --baseline examples/sarif/baseline/multi-before.sarif --fingerprint primary/v1 \
  --run-pairing examples/sarif/baseline/run-pairing.json
```

This synthetic example reverses two same-tool runs and reuses fingerprint A in
both pairs. It exits **1** for current warnings and emits comparison status
`compared` with `newly_observed: 1`, `retained: 2`, `absent: 1`, `ambiguous: 0`.
Entries include `pairId` and separate per-side result source pointers. The JSON
retains the manifest under `baselineComparison.runPairing.document`; `applied`
records whether all mappings were complete and unique. Markdown shows pair IDs.
The library accepts the same parsed object as `compare_bytes(...,
run_pairing=manifest)`; neither the object nor the SARIF evidence is modified.

To bind the indexes to the exact input files, optionally add `inputSha256`
alongside the two arrays. When present, this object must contain **both**
`baseline` and `current`, each exactly 64 lowercase hexadecimal characters;
extra or missing sides, null, other types and invalid hex are input errors.
Generate the values from the original bytes before declaring correspondence:

```python
import hashlib

manifest["inputSha256"] = {
    "baseline": hashlib.sha256(baseline_bytes).hexdigest(),
    "current": hashlib.sha256(current_bytes).hexdigest(),
}
report = compare_bytes(current_bytes, baseline_bytes,
                       fingerprint="primary/v1", run_pairing=manifest)
```

The included `examples/sarif/baseline/run-pairing-bound.json` binds the repeated-tool
fixtures used above. Replacing `run-pairing.json` with that file in the command
produces the same classifications and exit **1**. It also works with current
bytes from stdin:

```sh
cat examples/sarif/baseline/multi-current.sarif | vulnwrench sarif check - \
  --baseline examples/sarif/baseline/multi-before.sarif --fingerprint primary/v1 \
  --run-pairing examples/sarif/baseline/run-pairing-bound.json
```

Digests use exact SARIF bytes, including stdin bytes, without JSON
canonicalization or newline conversion. Valid JSON reformatting, whitespace,
line-ending changes and run reordering change the digest. If either digest
differs, the whole view has issue `run_pairing_input_digest_mismatch` and
`runPairing.applied: false`: every result trace remains ambiguous, no pair IDs
are applied and all new/retained/absent counts are zero, even for empty runs.
Successful scans yield status `ambiguous`; failed scanner execution still takes
precedence as `invalid`. The current gate policy and exit code are independent.
The supplied digests remain in `runPairing.document.inputSha256`; actual digests
remain in each input's evidence. Binding detects stale bytes, not authenticity
or correct target/scope assertions. Omitting `inputSha256` keeps the existing
unbound behavior.

Duplicate run assignments, duplicate pair IDs on either side, omitted runs, or
pair IDs without counterparts make the **whole** view ambiguous. No mapping is
applied, no automatic fallback classification is allowed, and every result trace
is retained in ambiguous entries, with zero retained/new/absent classifications.
Entry `pairId` is null when mappings were not applied. This also applies to
explicit empty mapping lists for nonempty reports and to missing counterparts
whose runs have no results. Failed scanner execution still
makes the view invalid. The gate decision/exit code remains based on the current
report; mapping ambiguity by itself does not block it.

Both side arrays and exactly the two fields per assignment are required; extra
fields (apart from optional top-level `inputSha256`), wrong types,
empty/non-string pair IDs, boolean/negative/out-of-range
indexes, malformed JSON and duplicate JSON object keys are input errors (**exit
2**, no report, existing outputs preserved). Missing one side is malformed;
omitting run assignments within valid side arrays is incomplete and ambiguous.
The manifest must be a file, is bounded separately by `--max-bytes`, and cannot
alias either output (including hard links). Without a manifest, automatic
one-run-per-tool matching and existing output remain unchanged.

## Inline rule packs and numeric references

Driver and extension rule catalogs are read independently, following
[SARIF 2.1.0 sections 3.27.5–7, 3.52 and 3.54](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html).
`result.rule.index` selects a rule in the component chosen by
`result.rule.toolComponent.index`, a zero-based index into `tool.extensions`.
Omitting the component (or its index) selects `tool.driver`; a component name
never performs lookup. Index `-1` means not set, including a component index
that defaults to driver. All other indexes must be in range and integer-valued
JSON numbers; booleans and floats are rejected.

```sh
vulnwrench sarif check examples/sarif/rule-components.sarif --level warning
```

This synthetic example exits **1** with **one** actionable result. Both driver
and extension have a rule named `shared`: the driver default is `error`, the
extension default is `note`. The first result uses
`{"rule": {"index": 0, "toolComponent": {"index": 0}}}` and receives the
extension's `note`, below the warning threshold. The second uses the same
reference with explicit `level: "error"` and blocks. Supplying only the first
result passes with exit **0**. Suppressions, execution status, baseline-state
exclusion and threshold policy apply as usual.

Each JSON result records `ruleComponent` with `kind` (`driver` or `extension`),
actual extension `index` (null for driver), `name` and catalog `sourcePointer`.
`ruleIndex` is the resolved rule position in that component, and
`ruleSourcePointer` points to its descriptor (null when unlisted).
`levelSource` keeps the existing result/rule/SARIF precedence;
`levelSourcePointer` identifies the explicit result level or catalog default,
and is null for the implicit SARIF warning. Full original references/catalogs
remain in `evidence.document`.

Redundant fields are checked before policy evaluation, even for suppressed
results. `ruleIndex` and `rule.index` must be equal if both are supplied;
otherwise the latter inherits the former. `ruleId` and `rule.id` must be equal
if both are supplied. An indexed ID must equal the selected descriptor ID or
append exactly one slash-separated hierarchical component (which may be empty).
The supplied ID, including that suffix, is retained in the trace and baseline
identity. A supplied component `name` must equal the selected component name.
Conflicts, malformed catalogs and unsupported references raise `InputError`
(**CLI exit 2**, sanitized diagnostic, no report, existing outputs preserved).
All inline rule catalogs are validated, including unused ones; duplicate rule
IDs within one component remain unsupported. Equal IDs in different components
are allowed.

The legacy `ruleId`-only path still looks up the driver by exact ID, with an
unlisted ID allowed only when the driver catalog is empty. It never searches
extensions. New `result.rule` objects require an effective numeric rule index
when metadata exists; an ID-only object is allowed only for an unlisted rule
without component metadata. GUID fields in rule/component **references** are
explicitly rejected, even alongside an index; descriptor GUID metadata is still
retained and used by baseline comparison. External properties, configuration
overrides and id-only message expansion remain unsupported.

Baseline comparison reads the actual selected descriptor GUID and includes
extension `name` plus supplied `guid`/`version`/`semanticVersion` in rule identity.
Component and rule array positions are provenance, never stable identity:
reordering them preserves matches. Driver and extension rules stay distinct;
changed extension identity makes shared fingerprints ambiguous. Indistinguishable
extension identities within a run taint its comparison pair with
`rule_component_identity_ambiguous`, rather than choosing a pack by position.

## Local source location display

Primary `result.locations[].physicalLocation.artifactLocation` objects resolve
inline `uri` values through that run's `originalUriBaseIds`, or use an explicit
`index` into the same run's `artifacts` array. This is a local subset of
[SARIF 2.1.0 sections 3.4, 3.14.14 and 3.24](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html).
Resolution is lexical: no artifact, directory, symlink, environment variable,
working directory, network URI or report-specified command is accessed.

```sh
vulnwrench sarif check examples/sarif/locations/nested.sarif
vulnwrench sarif check examples/sarif/locations/nested.sarif --format markdown
```

Both commands exit **1** for the fixture's unsuppressed warning. Its bases are
`ROOT: {"uri": "file:///workspace/"}` and
`SRC: {"uri": "src/", "uriBaseId": "ROOT"}`. The artifact
`{"uri": "../lib/a%20b.py", "uriBaseId": "SRC"}` produces this entry in
`results[0].resolvedLocations`:

```json
{
  "sourcePointer": "/runs/0/results/0/locations/0/physicalLocation/artifactLocation",
  "resolvedUri": "file:///workspace/src/../lib/a%20b.py",
  "displayPath": "/workspace/src/../lib/a b.py"
}
```

The fixture's second artifact, `./plain.py`, produces `resolvedUri` and
`displayPath` of `plain.py`. Without a base, relative references stay relative;
all literal `..` segments are preserved, including those following a named
segment. Nested bases are run-scoped and independent of object order. Base
directory references concatenate before artifact resolution; a rooted relative
artifact such as `/link/../a.py` replaces the base path with `/link/../a.py`.
Only literal `.` segments are removed. Repeated separators and trailing directory
markers remain, including a final `/.` becoming `/`. Relative references retain
`./` where needed to avoid becoming rooted or acquiring a URI scheme.
No parent removal or filesystem canonicalization is performed: a symlink at
`link` could change the meaning of `link/../a.py`.

Percent escapes stay encoded in `resolvedUri` with uppercase hex. `displayPath`
is decoded exactly once as UTF-8, without further normalization. For example,
`link/%2e%2e/../a%2fb%2520.py` resolves to
`link/%2E%2E/../a%2Fb%2520.py` and displays as `link/../../a/b%20.py`.
Escaped separators and dots never become resolution steps or prove URI
agreement. Display paths are readable labels, not filesystem identity keys.
`file://localhost/` is normalized to `file:///`; Windows file URIs display
portably as `/C:/...`, without platform-specific path conversion.

`examples/sarif/locations/parent-segments.sarif` demonstrates absolute, relative,
rooted, based, index-only and agreeing dual references plus escaped dots and
separators. Both JSON and Markdown commands exit **1** for its warning:

```sh
vulnwrench sarif check examples/sarif/locations/parent-segments.sarif
vulnwrench sarif check examples/sarif/locations/parent-segments.sarif --format markdown
```

All supplied base entries are checked, including unused entries. Bases must have
a nonempty URI ending in a single `/`, without `..` segments. A base is either an
absolute local `file:` URI without `uriBaseId`, or a relative directory reference
with a parent base; rooted relative base directories are unsupported. Missing or
redacted base URIs, missing parents, cycles, non-string references and malformed
URI escapes raise `InputError` (**CLI exit 2**, no report, existing outputs kept).
`examples/sarif/locations/cycle.sarif` is an executable failure example.

Only nonempty ASCII URI references with valid percent-encoded UTF-8 are supported.
Queries, fragments, raw spaces/backslashes/non-ASCII, decoded ASCII controls,
remote file authorities, network-path references and schemes other than `file`
are explicit errors in the consumed location/base fields. Encode spaces and
non-ASCII filenames, for example `a%20b.py` and `%E2%98%83.py`. Primary and related
physical artifact locations use this subset. Code flows and other URI-bearing
metadata remain uninterpreted evidence.

### Explicit artifact indexes

```sh
vulnwrench sarif check examples/sarif/locations/indexed.sarif
vulnwrench sarif check examples/sarif/locations/indexed.sarif --format markdown
```

Both exit **1** for an unsuppressed warning. The first primary location is
`{"index": 0}`. The selected `artifacts[0].location` has
`{"uri": "a%20b.py", "uriBaseId": "SRC", "index": 0}`; this fixture's `SRC` base
is `lib/` under `file:///workspace/`. The second primary location supplies both index 0 and the agreeing URI
`file://localhost/workspace/lib/./a%20b.py`. Each resolves to
`file:///workspace/lib/a%20b.py`, displayed as `/workspace/lib/a b.py`. Indexed
entries retain the primary `sourcePointer` and add
`"artifactSourcePointer": "/runs/0/artifacts/0/location"`. Raw catalog entries,
primary objects and regions remain in `evidence.document`.

Indexes must be nonnegative JSON integers; booleans, negative values (including
`-1`), missing catalogs and out-of-range indexes are errors. The selected entry
must be an object with an explicit `location.uri` in the same local URI subset.
Its location may omit `index` or repeat its own index; cross-entry/recursive
index references are rejected. Selected entries containing `parentIndex`,
`offset` or `length` are rejected whenever those fields are present: nested
containers and byte-offset artifacts are unsupported. No archive is opened.
`examples/sarif/locations/indexed-container.sarif` demonstrates this failure.

When the primary object supplies both `uri` and `index`, its URI and the catalog
URI expand independently through their own base IDs and must agree as encoded
references after local file/localhost, percent-hex and `.` segment normalization.
Literal `..` segments are preserved for both display and comparison: a catalog URI
`file:///workspace/link/../a.py` does **not** agree with inline
`file:///workspace/a.py` or `file:///workspace/other/../a.py`. A symlink could
make them different artifacts. Parent removal cannot prove agreement; no
filesystem access is needed to reject this ambiguity.
Different bases cannot silently override one another. This is a conservative
subset of URI agreement: no path case folding, unreserved percent-escape decoding
or filesystem equivalence check is performed. Display-decoded separators and
dot segments never establish agreement. An index-only primary object cannot
supply `uriBaseId` without `uri`. Malformed selected locations, disagreement and
unsupported container references raise `InputError` (**CLI exit 2**, no report,
existing JSON and Markdown outputs preserved), with sanitized diagnostics.

Catalog lookup is explicit and run-scoped. Only selected entries are validated;
unselected entries remain uninterpreted evidence. Inline-only locations do not
trigger catalog inference. Indexes in `originalUriBaseIds` remain unsupported.

Nonempty primary location arrays gain `resolvedLocations`; entries point to the
original artifact objects in `evidence.document`. Raw URIs, base IDs, regions and
all other location data remain intact there. Logical/address-only locations have
no resolved path and continue to count as located. Markdown adds a Locations
table with escaped plain display text. Resolution does not alter severity,
suppression, baseline identity, `hasLocation`, or gate eligibility for valid
inputs; unsupported location data now fails input validation explicitly.

### Related locations

`result.relatedLocations` uses the same local URI/base/index resolver. Nonempty
arrays add a separate `resolvedRelatedLocations` collection in each result trace;
each entry points into `/runs/.../results/.../relatedLocations/...` and indexed
entries also retain `artifactSourcePointer`. Literal parent segments and encoded
URI data follow the dot-only and once-decoded display contracts above. Markdown
adds a separate **Related locations** table with escaped plain path text.

```sh
vulnwrench sarif check examples/sarif/locations/related.sarif
vulnwrench sarif check examples/sarif/locations/related.sarif --format markdown
```

Both commands exit **1** for the warning. The example has no primary locations,
so `hasLocation` stays `false` and `unlocated` stays `1`. Its inline and indexed
related references resolve to `file:///workspace/link/../a%20b.py` and display as
`/workspace/link/../a b.py`. Related paths do not affect gate eligibility, severity,
suppression, execution, baseline identity or run pairing.

Missing/empty related arrays omit the new trace field. Nonempty collections
containing only logical/address-only locations produce an empty collection and
no Markdown table. Malformed arrays, location objects or consumed artifact
references fail with `InputError` (**CLI exit 2**, existing outputs preserved),
including remote URIs, invalid indexes and disagreeing dual references. Location
IDs and relationships remain raw evidence without schema validation or
relationship traversal. Regions use the explicit source-line/column/byte/character subsets below.
No artifact, CWD or network lookup is performed.

### Literal location messages

On a resolved primary or related path, an optional `message` adds a literal
`message` string and `messageSourcePointer` to that `resolvedLocations` or
`resolvedRelatedLocations` entry. The pointer selects the actual input field,
for example `/runs/0/results/0/locations/0/message/text` or
`/runs/0/results/0/relatedLocations/0/message/markdown`. `text` takes precedence over
`markdown`, just as for result messages. Every supplied `text`, `markdown` and
`id` must be a nonempty string, including a nonselected field; whitespace-only
strings are accepted. A supplied message must be an object with `text` or
`markdown`: null, arrays, empty objects and ID-only messages fail with
`InputError` (**CLI exit 2**, existing outputs preserved). No string tables,
arguments or placeholders are expanded. Other message properties remain raw
evidence. Pathless primary and related messages remain uninterpreted, even if
malformed. A nonempty primary array still establishes `hasLocation` even when
all entries are pathless; related entries never establish it.

Each **Locations** / **Related locations** Markdown table independently adds a
Message column only if a resolved message exists in that collection; absent
messages in mixed tables have empty cells. HTML,
Markdown punctuation, pipes, brackets and entities are escaped as plain text.
Each newline, carriage return or tab becomes one space (CRLF becomes two).
Nothing is rendered as HTML or Markdown. With all location messages absent, JSON
location entries and Markdown output are unchanged. Primary message absence also
preserves existing related-message output. Messages preserve the path,
source-line range, artifact and region pointers, raw evidence, primary location
counts, policy, baseline identity and digest-bound run pairing. They cause no
source, CWD or network access.

```sh
vulnwrench sarif check examples/sarif/locations/related-messages.sarif
vulnwrench sarif check examples/sarif/locations/related-messages.sarif --format markdown
```

Both commands exit **1** for the synthetic warning. The fixture includes inline
text, indexed Markdown, source lines, an absent message and a pathless ID-only
message retained as raw evidence.

For primary messages, use the corresponding synthetic example:

```sh
vulnwrench sarif check examples/sarif/locations/primary-messages.sarif
vulnwrench sarif check examples/sarif/locations/primary-messages.sarif --format markdown
```

Both commands exit **1**. Inline text and agreeing dual URI/index Markdown
messages retain source lines and all provenance; another resolved entry has no
message, and a pathless ID-only message stays raw. A related literal is displayed
separately. `hasLocation` is `true` and `unlocated` is `0`.

### Source line ranges

A resolved primary or related physical location can also report explicit source
lines from its own `physicalLocation.region`. This works with inline, indexed and
agreeing dual artifact references. For `{"startLine": 7, "endLine": 9}`, the
resolved JSON entry adds:

```json
{
  "sourceLineRange": {"startLine": 7, "endLine": 9},
  "regionSourcePointer": "/runs/0/results/0/locations/0/physicalLocation/region"
}
```

The existing `sourcePointer` still points to the artifact reference; indexed
entries keep `artifactSourcePointer`. The range always comes from the referring
physical location, not from the artifact catalog. Markdown appends `:7-9` to the
escaped path text. A start-only region adds `{"startLine": 7}` and `:7`; an
explicit equal end is retained and displays as `:7-7`. `resolvedUri` and
`displayPath` themselves do not acquire a line suffix.

For resolved paths, a supplied region must be an object. Supplied `startLine`
and `endLine` must be positive JSON integers; booleans, zero, negative values,
floats, strings and null are rejected. `endLine` requires an explicit `startLine`
and must be at least that start. Failures raise fixed-path `InputError`
(**CLI exit 2**, no report, existing JSON and Markdown outputs preserved). This
explicit validation replaces formerly uninterpreted handling of those fields.

Omitted regions, empty objects and regions with neither line field add no
source-line range or line suffix. Columns, byte offsets and character offsets use the explicit
subsets below. Snippets and unknown region fields remain raw
evidence without validation or coordinate inference. Pathless physical regions, `contextRegion`, artifact
catalog regions and code-flow regions remain uninterpreted. Raw regions and all
original metadata remain in `evidence.document`. No source files or network
resources are opened, no snippets are rendered, and lines do not change primary
location counts, policy, baseline identity or run pairing.

```sh
vulnwrench sarif check examples/sarif/locations/line-ranges.sarif
vulnwrench sarif check examples/sarif/locations/line-ranges.sarif --format markdown
```

Both synthetic example commands exit **1** for warning findings.

### Explicit source columns

On a resolved primary or related path with a valid explicit `region.startLine`,
optional `startColumn` and `endColumn` are also consumed. The referring region
supplies the coordinates for inline, indexed and agreeing dual artifact paths.
For `{"startLine": 7, "endLine": 9, "startColumn": 3, "endColumn": 5}`, the entry
keeps its line/artifact provenance and adds:

```json
{
  "sourceLineRange": {"startLine": 7, "endLine": 9},
  "sourceColumnRange": {"startColumn": 3, "endColumn": 5},
  "regionSourcePointer": "/runs/0/results/0/locations/0/physicalLocation/region"
}
```

Markdown shows `path:7-9 (startColumn=3, endColumn=5)` as escaped plain text.
Labels keep endpoint roles clear when only one column is supplied: for example,
`path:7 (endColumn=5)` does not add a missing start column or end line. JSON
likewise contains only supplied fields, and `resolvedUri`/`displayPath` remain
unchanged. Line-only and coordinate-absent output retain their previous form;
literal location messages and selected-field pointers are unchanged.

Consumed columns must be positive JSON integers; booleans, zero, negative values,
floats, strings, null, arrays and objects fail with fixed-path `InputError`
(**CLI exit 2**, both existing outputs preserved). If both columns are supplied
and `endLine` is absent or equals `startLine`, `endColumn` must be at least
`startColumn`. Equality is allowed for an insertion point. With a later explicit
`endLine`, a smaller end column is allowed. Either column may be omitted.
These rules follow [SARIF 2.1.0 sections 3.30.2 and 3.30.5–3.30.8](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html):
columns are one-based and the end column is **exclusive**. Omitted `endLine`
means the same line for ordering validation only; its default is never emitted.
No source-length bounds or offset/line consistency are checked.

This remains an explicit-coordinate subset, not full region validation. Columns
without an explicit `startLine` stay unvalidated raw evidence and add no range,
column suffix or column-derived region pointer; explicit byte or character ranges can supply
the same region pointer independently. An `endLine` without `startLine` still fails the existing
line contract. Missing columns are never defaulted. Numbers retain the producer's
source units: an explicitly declared `run.columnKind` can label displayed columns
as described below, without inference or UTF conversion. Pathless/context/catalog/code-flow regions remain uninterpreted.
No source/snippet lookup, filesystem/network/CWD access or relationship traversal
is performed. Columns do not change primary counts, policy, component/fingerprint
identity or digest-bound run pairing for valid inputs.

```sh
vulnwrench sarif check examples/sarif/locations/column-ranges.sarif
vulnwrench sarif check examples/sarif/locations/column-ranges.sarif --format markdown
```

Both synthetic commands exit **1** for a warning finding.

### Declared source-column units

Only when a run has a resolved primary or related entry with `sourceColumnRange`,
an explicitly supplied `run.columnKind` is consumed. The supported declarations
are exactly `utf16CodeUnits` and `unicodeCodePoints`. Each column-bearing entry
adds the literal declaration and its **run-level** provenance separately from
coordinates:

```json
{
  "sourceLineRange": {"startLine": 7},
  "sourceColumnRange": {"startColumn": 3, "endColumn": 5},
  "sourceColumnUnit": "utf16CodeUnits",
  "columnKindSourcePointer": "/runs/0/columnKind",
  "regionSourcePointer": "/runs/0/results/0/locations/0/physicalLocation/region"
}
```

Markdown independently adds **Column unit** and **Unit source pointer** columns
only to a Locations/Related locations table with a declared unit. Both cells use
the existing plain-text escaping; rows without units have empty cells. Path,
line/column suffixes and literal message cells keep their existing roles.
Inline, indexed and agreeing dual paths use the referring run's declaration,
including entries with only one supplied column endpoint. No units cross runs.

Omission adds neither JSON field and never infers SARIF's default unit; when all
units are absent, Markdown keeps its previous table shape. A declaration adds no
label to line-only/path-only entries. If a run exposes no resolved columns, even
malformed `columnKind` remains unvalidated raw evidence: this includes empty runs,
pathless regions, columns without explicit `startLine`, and context/catalog/code-flow
metadata. `/runs/i/columnKind` leaves `uninterpretedFields` only when consumed;
the original declaration always remains in `evidence.document`.

A consumed declaration that is null, boolean, numeric, an array/object, empty,
case-mismatched or unsupported raises the fixed diagnostic
`/runs/i/columnKind: expected one of unicodeCodePoints, utf16CodeUnits`.
The CLI exits **2**, emits no report and preserves both existing outputs; input
values are never included in the diagnostic. This explicit validation replaces
formerly evidence-only handling only at the consumed boundary.

Coordinates remain exactly producer-supplied, with exclusive `endColumn` and no
unit conversion, source/snippet lookup, coordinate defaults, filesystem/network/CWD
access or relationship traversal. Unit labels do not change line, column, region,
artifact or message provenance, primary location counts, policy, component/fingerprint
identity or exact-byte digest-bound run pairing for valid input.

```sh
vulnwrench sarif check examples/sarif/locations/column-units.sarif
vulnwrench sarif check examples/sarif/locations/column-units.sarif --format markdown
vulnwrench sarif check examples/sarif/locations/column-units-invalid.sarif
```

The positive synthetic examples exit **1** for warnings; the negative example
exits **2** with a sanitized diagnostic.

### Explicit source-byte ranges

Resolved primary and related paths consume an explicitly supplied
`physicalLocation.region.byteOffset` as a strict JSON integer at least **-1**.
Zero is a valid first-byte offset; **-1** means unknown/unset and produces no
byte range. With a known explicit offset (zero or greater), optional `byteLength`
must be a strict nonnegative integer. Zero length is a valid insertion point.
Booleans, floats, strings, null, arrays and objects are rejected in consumed fields.
These boundaries follow [SARIF 2.1.0 sections 3.30.11–3.30.12 and its region schema](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html).

```json
{
  "sourceByteRange": {"byteOffset": 0, "byteLength": 4},
  "regionSourcePointer": "/runs/0/results/0/locations/0/physicalLocation/region"
}
```

`sourceByteRange` preserves only supplied values. Omitted length never becomes
zero; no end offset is calculated. There is no artificial upper bound or source
length/coordinate consistency check. Byte-only regions expose the path and exact
region provenance without inventing lines, columns or column units. Existing
line/column ranges, declared units and literal messages can coexist unchanged.
Inline, indexed and agreeing dual references retain referring-region provenance,
artifact pointers and selected message pointers independently.

Markdown adds **Byte range** and **Byte region source pointer** columns only to
a Locations/Related locations table containing known byte ranges. The labels
`byteOffset=0, byteLength=4` and pointer use plain-text escaping independently of
Path suffixes, Column unit and Message cells. Rows without byte ranges get empty
cells; tables with no byte ranges keep their previous shape.

Absent offsets and the explicit `-1` sentinel add no range, byte-only region
pointer or byte cells. In both cases, even malformed `byteLength` stays raw and
unvalidated: this subset never guesses its position. Pathless regions,
`contextRegion`, artifact catalog regions and code flows remain raw, including
malformed byte fields. Character offsets use the separate explicit subset below;
snippets remain uninterpreted; region-level messages use the separate subset below.
The original document and existing subtree evidence inventory are retained unchanged.

A malformed consumed offset raises the fixed diagnostic
`/runs/i/results/j/locations/k/physicalLocation/region/byteOffset: expected integer at least -1`;
a malformed consumed length uses `/byteLength: expected nonnegative integer`.
Related entries use their exact `relatedLocations` pointer. Existing region,
line and column validation still applies first. The CLI exits **2**, emits no
report and preserves both existing output files; diagnostics never include input
values. Valid byte ranges do not change primary counts, gate policy,
component/fingerprint identity or exact-byte digest-bound run pairing.
No byte-to-text/UTF conversion, source/snippet access, filesystem/network/CWD
lookup, context/code-flow or relationship traversal occurs.

```sh
vulnwrench sarif check examples/sarif/locations/byte-ranges.sarif
vulnwrench sarif check examples/sarif/locations/byte-ranges.sarif --format markdown
vulnwrench sarif check examples/sarif/locations/byte-ranges-invalid.sarif
```

The positive synthetic example exits **1** for warnings; the negative example
exits **2** with a sanitized diagnostic.

### Explicit source-character ranges

Resolved primary and related paths consume an explicitly supplied
`physicalLocation.region.charOffset` as a strict JSON integer at least **-1**.
Zero is a valid first-character offset; **-1** means unknown/unset and produces
no character range. Only a known explicit offset (zero or greater) consumes
optional `charLength`, which must be a strict nonnegative integer. Zero length
is a valid insertion point. Booleans, floats, strings, null, arrays and objects
are rejected in consumed fields. These boundaries follow the
[SARIF 2.1.0 region schema](https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json).

```json
{
  "sourceCharacterRange": {"charOffset": 0, "charLength": 4},
  "regionSourcePointer": "/runs/0/results/0/locations/0/physicalLocation/region"
}
```

`sourceCharacterRange` retains only the supplied offset and optional length.
No missing value, end offset, line, column, byte position or unit is inferred.
Character-only regions need no lines and do not consume `run.columnKind`;
that declaration labels only displayed source columns. Character ranges remain
separate from `sourceByteRange` and `sourceColumnRange`, with no character/UTF/byte
conversion, artificial upper bound, source-length or coordinate-consistency check.
Mixed coordinates can coexist with declared column units and literal location
messages. Inline/indexed/agreeing dual references keep exact referring-region,
artifact and selected location-message pointers.

Markdown independently adds **Character range** and **Character region source
pointer** cells to each Locations/Related locations table containing a known
character range. Labels such as `charOffset=0, charLength=4` and pointers use the
existing plain-text escaping, separate from byte cells, path suffixes, units and
messages. Rows without character ranges get empty cells; tables with none keep
their prior shape.

Omitted offsets and explicit `-1` emit no character range, character-only region
pointer or character cells. Without a known offset, even malformed `charLength`
stays raw and unvalidated. Pathless/context/catalog/code-flow regions, snippets
and unknown fields remain raw; region-level messages are displayed only as described
in the next section. Full original evidence and
the existing location subtree inventory remain retained. No source/snippet access,
filesystem/network/CWD lookup or context/code-flow traversal occurs.

Malformed consumed offsets raise
`/runs/i/results/j/locations/k/physicalLocation/region/charOffset: expected integer at least -1`;
malformed consumed lengths use `/charLength: expected nonnegative integer`.
Related entries use their exact `relatedLocations` pointer. Existing region,
line, column and byte validation applies first. Input errors exit **2**, emit no
report and preserve both output files, with no producer values in diagnostics.
Valid character ranges preserve primary counts, policy, component/fingerprint
identity and exact-byte digest-bound run pairing.

```sh
vulnwrench sarif check examples/sarif/locations/character-ranges.sarif
vulnwrench sarif check examples/sarif/locations/character-ranges.sarif --format markdown
vulnwrench sarif check examples/sarif/locations/character-ranges-invalid.sarif
```

The positive synthetic example exits **1** for warnings; the negative example
exits **2** with a sanitized diagnostic.

### Literal region messages

On a resolved primary or related path, an optional `physicalLocation.region.message`
adds a `regionMessage` string and `regionMessageSourcePointer` to that
`resolvedLocations` or `resolvedRelatedLocations` entry. It is independent of the
location-level `message`: a supplied location message and region message are both
kept, and neither overwrites the other. The pointer selects the actual input field,
for example `/runs/0/results/0/locations/0/physicalLocation/region/message/markdown`.
`text` takes precedence over `markdown`. Every supplied `text`, `markdown` and `id`
must be a nonempty string, including a nonselected field; whitespace-only literals
are accepted. A supplied region message must be an object with `text` or
`markdown`: null, arrays, empty objects and ID-only messages fail with `InputError`
(**CLI exit 2**, existing outputs preserved). This tightens earlier behavior, where
an ID-only region message on a resolved region was raw evidence. No string tables,
arguments or placeholders are expanded, and nothing is rendered as Markdown or HTML.

A region message alone adds no coordinate, no `sourceLineRange`/`sourceByteRange`/
`sourceCharacterRange`/`sourceColumnRange`, and no `regionSourcePointer`. Pathless,
context, artifact-catalog and code-flow regions remain raw and unvalidated, even
when malformed. Each Locations and Related locations Markdown table independently
adds **Region message** and **Region message source pointer** cells only if a
resolved region message exists in that collection; other rows get empty cells.
Text uses the existing plain-text escaping. Messages preserve the path, artifact and
location-message pointers, raw evidence, primary counts, policy, baseline identity
and digest-bound run pairing. They cause no source, CWD or network access.

```sh
vulnwrench sarif check examples/sarif/locations/region-messages.sarif
vulnwrench sarif check examples/sarif/locations/region-messages.sarif --format markdown
vulnwrench sarif check examples/sarif/locations/region-messages-invalid.sarif
```

The first two commands exit **1** for synthetic blocking warnings; the fixture also
contains one unlocated result. The invalid fixture exits **2** with
`vulnwrench sarif: /runs/0/results/0/locations/0/physicalLocation/region/message: text or markdown required; id-only messages are unsupported`
and emits no stdout.

## Supported input and field mapping

This is a gate-oriented **subset reader**, not a full SARIF schema validator or
SARIF rewrite tool. It accepts one self-contained UTF-8 JSON document (optional
UTF-8 BOM), `version: "2.1.0"`, and an array of runs. Multiple runs and invocations
are aggregated without deduplication. Missing `results` is treated as an empty
collection and marked `resultsPresent: false`; explicit null is rejected.

| Input | Interpretation / trace |
| --- | --- |
| `runs[].tool.driver.name` | Required nonempty string; recorded in run trace. |
| `tool.driver.rules[].id` / `tool.extensions[].rules[].id` | Component-local catalogs; duplicate IDs within one component are errors. |
| `result.ruleIndex` / `result.rule.index` | Zero-based index within the selected component; `-1` or omission means no index. Redundant indexes must agree. |
| `result.rule.toolComponent.index` | Index into `tool.extensions`; omitted/not-set selects driver. Names only check agreement. GUID references are unsupported. |
| `result.ruleId` / `result.rule.id` | Redundant IDs must agree. Indexed IDs equal the catalog ID or append one hierarchical component. Legacy `ruleId`-only lookup uses exact driver ID; unlisted IDs require an empty driver catalog. |
| `result.level` | Highest precedence; `none`, `note`, `warning`, `error` only. |
| Matched `rule.defaultConfiguration.level` | Used if result level is omitted; otherwise SARIF default `warning`. `levelSource` records the actual source. |
| `result.message.text` / `.markdown` | A nonempty literal message is required; text is preferred. Markdown input is displayed as escaped plain text, not rendered markup. |
| `result.suppressions[]` | Requires `kind: inSource` or `external`. `accepted` excludes that result while preserving every suppression. `rejected`, `underReview`, and omitted status remain actionable. A literal status `unspecified` is invalid; the trace uses that word only for omission. One accepted entry is enough even when other entries are rejected. |
| `result.baselineState` | Missing, `new`, `updated`, and `unchanged` are active by default. Only explicit `--ignore-unchanged` excludes unchanged. `absent` denotes a finding no longer present and is always excluded. Other values are errors. |
| `result.locations` | No entries means `hasLocation: false` and increments `unlocated`; findings still gate. Nonempty primary location arrays (including logical locations) count as located. Inline artifact URIs and explicit run-local artifact indexes resolve as described above; optional explicit source lines/columns/bytes/characters and literal location or region messages on resolved paths use the subsets above; raw locations/regions and catalogs are retained. |
| `result.relatedLocations` | Separate `resolvedRelatedLocations` and escaped Markdown display using the same local resolver; optional literal messages on resolved paths use the subset above. Does not establish `hasLocation` or change `unlocated`; raw metadata remains evidence. |
| `runs[].columnKind` | Explicit `utf16CodeUnits`/`unicodeCodePoints` labels and run-level provenance only on resolved source columns; omitted units are never inferred. Malformed consumed declarations fail; runs without resolved columns keep raw metadata. |
| `invocations[].executionSuccessful` | Strict JSON boolean when present. `false` always blocks, including with no results. Omission is recorded as unknown, never inferred successful. |
| `invocations[].toolExecutionNotifications[]` | Literal message required; level defaults to warning. Each `error` blocks even when executionSuccessful is true. Other levels are retained without blocking. |
| Missing invocations / success | Default policy permits an unknown execution state but exposes it in JSON and Markdown. `--require-execution-success` additionally fails absent invocations, missing success booleans, and zero runs. |

`failedInvocations` counts explicit false booleans, `errorNotifications` counts
error notifications, and `scanFailures` counts affected invocation/run entries
(each has its reasons). `acceptedSuppressions` counts **results with at least one
accepted entry**, not the number of suppression objects. Exclusion counters can
overlap when a result has both accepted suppression and an excluded baseline.

## Evidence, output, and limits

Every input result has a trace with a JSON Pointer back to the source. JSON
includes the **entire parsed original document** under `evidence.document`, a
SHA-256 of the exact input bytes, and `uninterpretedFields` pointers to unconsumed
fields/subtrees. Unknown properties, vendor data, code flows, locations, and
notification details are retained. They do not affect policy. The pointer list
is an interpretation inventory, not a full schema-extension detector: even known
SARIF fields outside this policy are listed. Serialization preserves JSON values,
not the original whitespace, key order, or number spelling; input-byte digest
preserves provenance. No timestamp, hostname, or absolute input path is emitted.

Reports contain unredacted input evidence and messages. Error diagnostics contain
fixed schema paths and array indexes, never input values or JSON excerpts.
Markdown neutralizes HTML, links, Markdown syntax and controls in finding text.
JSON escapes HTML metacharacters and non-ASCII text without changing decoded
values. No URI, `$schema`, artifact, or external reference is fetched or opened.

Explicitly rejected with exit 2:

- Versions other than 2.1.0, null runs, invalid consumed types/enums, duplicate JSON
  keys, non-finite numbers, invalid UTF-8, or excessive JSON nesting.
- Externalized SARIF (`externalPropertyFileReferences` or
  `inlineExternalProperties`), GUID rule/component references, and invocation
  rule/notification configuration overrides.
- Result kinds other than omitted/default `fail`; id-only messages needing string
  table resolution. These require additional interpretation beyond this MVP.

The CLI reads at most **32 MiB** by default; `--max-bytes N` explicitly changes
that limit. Evaluation holds parsed evidence and traces in memory. This is not a
streaming reader. The library has no byte limit; callers should bound inputs.
Locations and arbitrary retained metadata are not fully schema-validated. Custom
severity properties, enabled flags, process exitCode, and configuration
notifications are retained but do not override the documented gate semantics.
A pass does not establish scan coverage, report authenticity, or absence of
vulnerabilities. The optional baseline view is limited to the explicit identities
described above. URI resolution is limited to the local display subset above.
There is no scanner execution, SARIF modification, network access, or general UI.

Library usage:

```python
from pathlib import Path
from vulnwrench.sarifgate import Policy, check_bytes, markdown_summary

report = check_bytes(Path("examples/sarif/semgrep.sarif").read_bytes(), Policy(level="warning"))
assert report["decision"] == "pass"
summary = markdown_summary(report)
```

`evaluate(document, Policy(...))` accepts a JSON tree without mutating it and uses
a canonical-document digest instead of an input-byte digest. `InputError` is the
library's invalid-input exception. `dumps(report)` produces deterministic JSON.

## Reproducible examples and comparison

All fixtures are small synthetic reports, not outputs from running real scanners.
`examples/sarif/semgrep.sarif` is Semgrep-shaped: driver name, ruleId, warning level,
accepted in-source suppression, and explicit successful invocation. Actual CLI
output is committed in `examples/sarif/expected/semgrep.json` and `.md`; the JSON has:

```json
{
  "actionable": 0,
  "acceptedSuppressions": 1,
  "decision": "pass"
}
```

This excerpt selects three fields from the full generated report. The naive count
for the same fixture is 1 and incorrectly fails the expected gate decision.

```sh
python -m pytest tests/sarifgate
vulnwrench sarif --help
python scripts/sarif/verify_examples.py
python scripts/sarif/compare_naive.py
```

The `compare_naive.py` command independently counts only explicit warning/error results and asserts
both baseline counts and gate decisions against `examples/sarif/corpus.json`. On the
**14-case synthetic corpus**, it measured **8 correct baseline decisions** and
**14 correct gate decisions**. The 6 differences cover accepted suppression,
rule defaults, implicit warning, failed invocation, error notification, and
baseline absence. Rejected, under-review and unspecified suppressions remain
blocking. Full per-case counts are the actual generated
`examples/sarif/expected/comparison.json`, which `verify_examples.py` reproduces and
compares byte-for-byte. This measures decision correctness on this corpus;
there is no timing/speedup or general population accuracy claim.

## Upstream relationship and license

[microsoft/sarif-tools](https://github.com/microsoft/sarif-tools) already supports
`--check`, filters, summaries, and diff. It is MIT-licensed and is neither a
runtime dependency nor the naive baseline in this experiment. vulnwrench sarif focuses
on an auditable policy trace across suppression status, rule default levels and
execution status; it does not replace those broader capabilities.

[Semgrep #11605](https://github.com/semgrep/semgrep/issues/11605) is evidence of
consumer ambiguity around SARIF and ignored findings, not proof of a defect in
all current scanner versions. No Semgrep engine or rule code was copied. See [LICENSE](../LICENSE)
for this independent implementation's MIT terms and [THIRD_PARTY.md](../THIRD_PARTY.md)
for notices and upstream relationships.
