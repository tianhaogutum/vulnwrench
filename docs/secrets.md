# vulnwrench secrets

Gitleaks fingerprints change whenever a commit or line moves, so re-triaging every scan
either floods reviewers with the same secrets or hides a secret that was swapped in at a
known position. `vulnwrench secrets` turns complete Gitleaks JSON reports into a
**redacted, keyed review ledger** and compares the next report against it: unchanged,
moved, new content at an old location, new, absent or uncomparable. Use it to keep a
secrets-review history in CI without ever storing the secrets themselves.

_Formerly the standalone `secret-ledger` tool._

Content groups use `HMAC-SHA256(local_key, Secret UTF-8 bytes) + RuleID + normalized
relative File`. The ledger keeps all occurrence locations and native fingerprints, so
commit churn can share one review group while changed content at an old position is
visible. Explicit bijective file mappings support rename-aware comparisons without
weakening keyed content identity.

## Quick start

Standard library only. The committed `TEST-ONLY.key` is public and for the synthetic
examples only. From a clone of the repository:

```sh
pip install vulnwrench
vulnwrench secrets --help

chmod 600 examples/secrets/TEST-ONLY.key   # Git does not keep the 0600 mode
vulnwrench secrets snapshot --key-file examples/secrets/TEST-ONLY.key \
  --report examples/secrets/before-gitleaks.json --output before.json
vulnwrench secrets compare --key-file examples/secrets/TEST-ONLY.key \
  --before before.json --report examples/secrets/after-gitleaks.json \
  --output comparison.json --ledger-output after.json --markdown comparison.md
vulnwrench secrets import-renames --name-status examples/secrets/renames.name-status.z
```

| Subcommand | What it does |
| --- | --- |
| `init` | Generate a private 0600 key and a sibling Git ignore entry |
| `snapshot` | Build a standalone redacted ledger from a complete Gitleaks report |
| `compare` | Compare a prior ledger with a new complete report; optionally write the next ledger and a Markdown summary |
| `import-renames` | Convert supplied `git diff --name-status -z` bytes into a `--path-map` file; never runs Git |

Exit codes: **0** successful processing (even when changes or unknowns exist), **2**
invalid/unsupported input, key or I/O error. It is a review tool with no exit-1 policy
gate; gate on the comparison JSON (for example `summary.new_content`) in your pipeline.
POSIX key ownership, mode 0600, symlink refusal and hard-link artifact publication assume
a local POSIX filesystem. Ledgers keep the `secret-ledger/v1` and comparison
`secret-ledger-comparison/v1` schema identifiers of the standalone tool, so existing
ledgers remain valid `--before` inputs.

## Create and use a private local key

Only `init` generates a key; other commands fail if it is missing. Pick an
existing private directory. Example with local filenames you control:

```sh
mkdir -m 700 -p .local-ledger
vulnwrench secrets init --key-file .local-ledger/review.key
vulnwrench secrets snapshot --key-file .local-ledger/review.key \
  --report /authorized/local/before-gitleaks.json --output .local-ledger/before.json
vulnwrench secrets compare --key-file .local-ledger/review.key \
  --before .local-ledger/before.json --report /authorized/local/after-gitleaks.json \
  --output .local-ledger/comparison.json --ledger-output .local-ledger/after.json \
  --markdown .local-ledger/comparison.md
```

`init` creates 32 random raw bytes with mode 0600 and first appends a literal
`/review.key` ignore entry to the key's sibling `.gitignore` (preserving existing
rules). It refuses an existing key or symlink, or a symlinked `.gitignore`.
Keys must be regular, owned by the current user and exactly mode 0600 on POSIX.
Key filenames use letters/digits followed by letters/digits/dot/underscore/hyphen.
Keep the same key for a ledger lineage: mixed key IDs cause exit 2. Rotation
requires a fresh snapshot and retriage. Git ignore does not remove an already
tracked file or prevent a deliberate forced add; never commit real keys.

Outputs default to stdout if `--output` is omitted. File outputs are mode 0600,
created atomically one at a time, and **never overwrite** existing paths.
Their parent directories must exist. Output/input aliasing is rejected. A
multi-file command is not a transaction: an I/O failure after publishing one
artifact may leave that complete artifact; no partial contents are published.
Report paths are only evidence; no target source files are opened or executed.
The command has no network, subprocess, scanner or package-manager calls.

Error messages omit report values and filenames.

## Reproduce the committed synthetic example

The committed public key is **TEST ONLY**, never suitable for real data.
Git does not preserve 0600 mode. These commands create a fresh `out.json` (choose another name if it exists):

```sh
chmod 600 examples/secrets/TEST-ONLY.key
vulnwrench secrets compare --key-file examples/secrets/TEST-ONLY.key \
  --before examples/secrets/before-ledger.json --report examples/secrets/after-gitleaks.json \
  --output out.json
```

`src/config.py:4` changes from synthetic secret A to B while its native
fingerprint stays identical. The actual generated result in
`examples/secrets/expected-comparison.json` contains `new_content_same_location` for B,
an `absent` event for A, and no raw secret. Its actual summary is:

```json
{"absent": 2, "new_content": 0, "new_content_same_location": 1,
 "same_secret_moved": 1, "unchanged": 1, "uncomparable": 2}
```

The example also has one content group appearing at two new lines/commits,
one unchanged group, one removed group and two unavailable-content groups.
`python scripts/secrets/verify_examples.py` reproduces the four committed artifacts
byte for byte in a temporary directory; repeated runs do not overwrite fixtures.

## Exact supported input and field mapping

Input must be a UTF-8 JSON **array** of native-shaped finding objects (empty
`[]` is supported), from a **full report for the same repository and scan scope**.
The CLI accepts regular local files up to 64 MiB, parses in memory, and rejects
duplicate JSON members, non-finite numbers, missing required fields and unknown
field names. NDJSON, SARIF, wrapper objects, `null`, custom schemas, partial/diff
reports, absolute paths, archive paths, and Gitleaks baseline files are unsupported.
Full coverage is caller-declared in provenance; the tool cannot verify it.

| Input | Validation and output mapping |
| --- | --- |
| `RuleID` (required) | ASCII letter/digit followed by up to 199 letters/digits/`_.-`; retained as `rule_id` |
| `File` (required) | Relative path, max 4096 characters; `\\` becomes `/`, `.` and repeated separators collapse; retained as `path` |
| `StartLine` (required) | Integer 1 through 2147483647, never a boolean; retained as `start_line` |
| `Commit` (required) | Empty for directory scans or full 40/64 hex Git ID; retained verbatim |
| `Fingerprint` (required) | `file:rule:line`, `commit:file:rule:line`, or `:file:rule:line` for empty commit; max 8192 characters; must agree with finding fields after path normalization; retained verbatim |
| `Secret` (optional) | String/null; exact UTF-8 bytes are HMAC input, never stored; missing/empty/redacted content becomes unknown |
| `Match` (optional) | String/null; discarded, **never** used as a content fallback |
| `Description`, `EndLine`, `StartColumn`, `EndColumn`, `Line`, `SymlinkFile`, `Entropy`, `Author`, `Email`, `Date`, `Message`, `Tags` | Recognized native/JSON-extra metadata; explicitly discarded without interpretation, never copied to outputs |

Every occurrence, including an exactly repeated record, is preserved. Unknown
fields cause exit 2 instead of silent schema drift. Only rule, relative path,
HMAC (or null), comparability, start line, commit and fingerprint enter a ledger.
No raw Secret, Match, source line, description or author metadata is persisted.
If retained metadata contains a Secret or Match value from the report, processing
fails rather than exposing it (including cross-row and prior-ledger overlap).
This conservative check can reject very short secrets that overlap ordinary
paths. Metadata strings reject control/surrogate characters; paths reject every
`..` segment, drive/UNC/absolute forms, `:` and archive `!` notation. Paths are
lexically normalized, case-sensitive, and never resolved against the filesystem.

Recognized redaction includes any `redact` substring (case-insensitive), `*`,
blank strings, and common bracketed masked/removed/hidden/secret placeholders.
Use `--redacted` on snapshot/compare for **all** redacted reports, especially
arbitrary placeholders which cannot be inferred reliably. This forces every
content value to unknown. Real secrets containing those marker strings are
conservatively unknown too. Match-only findings stay unknown, even if Match
contains plausible unredacted content.

`--before` accepts only standalone `secret-ledger/v1` snapshots with the exact
schema/provenance/key ID and internally consistent groups/summary. Comparison
JSON is a different schema; use `--ledger-output` for the next `--before` input.
JSON output ordering is deterministic; there are no wall-clock timestamps,
absolute input paths, report-body digests or author identities in the ledger.
The key ID is SHA-256 of the ASCII prefix `secret-ledger-key-id-v1`, followed
by one NUL byte and then the 32 key bytes.

## Classification semantics

| Classification | Meaning at content-group level |
| --- | --- |
| `unchanged` | Same HMAC, rule, normalized path and complete occurrence multiset |
| `same_secret_moved` | Same HMAC/rule and same or explicitly mapped path, but path or occurrence evidence changed |
| `new_content_same_location` | New HMAC in this rule/path overlaps a prior comparable group's start line |
| `new_content` | New comparable content without a prior same-line group |
| `absent` | Prior comparable group is absent from the current full report; not proof of remediation |
| `uncomparable` | Content is unavailable, or a path has no correspondence in explicit mapping mode; equality/absence cannot be established |

An exact comparable match takes precedence. Otherwise, any prior unknown in the
same rule/path makes a new current group uncomparable; any current unknown in a
rule/path prevents claiming a missing prior group is absent. Prior unknown groups
also get an uncomparable event, even against an empty report. Null HMACs never
match each other. Unknown occurrences are aggregated by rule/path only for
presentation; this does **not** assert a shared underlying secret. Counts are
review events/groups, not unique-secret counts; a replacement can generate both
new-content and prior-absence events. Without an explicit path mapping, moving
between files creates new/absent groups. Rule IDs always remain identity
boundaries. Mixed same-rule
findings at one line are detected as new content without inferring one-to-one
replacement. End lines/columns are outside identity scope.

## Explicit file renames

Supply a local UTF-8 JSON **array** of exact file pairs, directed from the prior
ledger's paths to the current report's paths. For example, `paths.json`:

```json
[{"old_path": "src/config.py", "new_path": "lib/config.py"}]
```

```sh
vulnwrench secrets compare --key-file .local-ledger/review.key \
  --before .local-ledger/before.json --report /authorized/local/after-gitleaks.json \
  --path-map paths.json --output .local-ledger/renamed-comparison.json \
  --ledger-output .local-ledger/renamed-current.json
```

If the prior report contains synthetic content A at `src/config.py:4` and the
current report contains the same A at `lib/config.py:4`, this mapping produces
exactly one `same_secret_moved` event and no new/absent event. Without the option,
it produces `new_content` plus `absent`. Replacing A with B at the mapped line
produces `new_content_same_location` plus `absent`; moving B to a different line
produces `new_content` plus `absent`. A map alone never establishes equality:
the key ID, HMAC and rule must still agree. Missing/Match-only/redacted content
stays `uncomparable`, even across a mapped path.

Supplying the option (including an empty `[]`) enables conservative mapping
mode. Unmapped paths present in both reports retain same-path correspondence,
unless explicitly renamed away. Other unmapped current/prior paths produce
`uncomparable` with reason `current_path_unmapped` / `prior_path_unmapped`,
rather than inferring a rename, new content or absence. Explicitly mapped
endpoints remain comparable even if one side has no findings; known content
can then be new or absent. Entries for files without findings are allowed.

Each entry must contain exactly `old_path` and `new_path`. Both use the same
relative path normalization/validation as findings; no globs, directory-prefix
substitution, filesystem resolution or Git invocation occurs. Duplicate sources
or destinations after normalization (even identical repeated pairs), one-to-many
or many-to-one mappings, traversal and invalid schemas fail with **exit 2**,
sanitized diagnostics, and no output artifacts. A destination colliding with an
unmapped prior path also fails, regardless of rule or content. Pairs apply
simultaneously, so explicit file swaps are supported; entries are never chained.
The caller must establish the real rename relationship and matching scan scope.

Comparison JSON records the normalized, sorted `path_map` only when supplied;
Markdown also lists it. Map paths overlapping current report Secret/Match values
are rejected, including unused entries. Prior evidence keeps its original
path/fingerprint. The current standalone ledger keeps only current paths and
needs no mapping when used as the next `--before`. Mapping is per comparison,
never carried forward implicitly.

## Import supplied Git rename records offline

Convert an already supplied `git diff --name-status -z` file into
the mapping format above. The importer reads bytes; it never runs Git, accesses
a repository, or needs a key. By default it requires rename-only input, as
produced with rename detection (`-M`) and `--diff-filter=R`. The caller supplies the file and must
verify its direction, repository and scan scope. Continue using **full** Gitleaks
reports for snapshot/compare; a path diff does not establish full scan coverage.

```sh
vulnwrench secrets import-renames \
  --name-status examples/secrets/renames.name-status.z --output paths.json
# Use the resulting paths.json with compare --path-map paths.json.
# For supplied mixed changes, explicitly opt in to validated A/M/D/T filtering:
vulnwrench secrets import-renames --allow-non-renames \
  --name-status supplied-mixed.z --output mixed-paths.json
```

The committed synthetic binary fixture contains these two records (shown with
`\0` for each literal NUL byte; these are not backslash escapes in the file):

```text
R087\0src/凭据.py\0lib/凭据.py\0R100\0src/space name.py\0lib/space name.py\0
```

The output is exactly [`examples/secrets/renames-path-map.json`](../examples/secrets/renames-path-map.json),
a deterministic JSON array sorted by normalized old path:

```json
[
  {"new_path": "lib/space name.py", "old_path": "src/space name.py"},
  {"new_path": "lib/\u51ed\u636e.py", "old_path": "src/\u51ed\u636e.py"}
]
```

Each record's status determines its exact arity:

| Status | NUL-delimited record | Behavior |
| --- | --- | --- |
| `R000` through `R100` | `status NUL old_path NUL new_path NUL` | Validate and retain one mapping |
| Exactly `A`, `M`, `D` or `T` | `status NUL path NUL` | Reject by default; with `--allow-non-renames`, validate the path then discard the record |
| Any other status | Unsupported | Reject with or without the option |

Rename scores must be exactly three ASCII digits from `000` through `100`;
they are validated then discarded, never treated as proof of secret equality.
For example, `M\0README.md\0R100\0old name.py\0new name.py\0` yields only
`[{"old_path": "old name.py", "new_path": "new name.py"}]` with the option;
without it, exit 2 and no output. A zero-byte file, or an opted-in stream of
ordinary changes with zero renames, produces `[]`.

Every nonempty input requires the final NUL. Paths, **including ignored paths**, decode
as strict UTF-8 and use the existing relative-path validation and normalization,
with spaces and Unicode preserved, without case folding or Unicode normalization.
Literal Git backslashes are rejected because ledger paths interpret them as
separators. Tabs/newlines/ASCII controls, surrogates, non-UTF-8 Git filenames, absolute,
traversal, drive and archive paths remain unsupported.

Copy (`C`/`C100`), unmerged (`U`/combined statuses), unknown statuses, scored
ordinary statuses such as `M100`, bare `R`, malformed/out-of-range scores, text/tab/quoted output, empty
paths, incomplete/extra fields and duplicate normalized sources or destinations
(even repeated identical pairs) fail with exit **2**, sanitized diagnostics,
empty stdout and no output file. Swaps are simultaneous; input record order
does not affect JSON output. Files must be regular and at most 64 MiB, parsed
in memory. File output is private (0600), atomic and create-only, or JSON goes
to stdout when `--output` is omitted. No partial map is emitted on validation
failure, including a bad record after valid records.

Parsing consumes exactly the paths required by each status. A filename such as
`R100` or `M` remains a path in that position; the parser never searches ahead
for an apparent status to recover from malformed input. NUL framing cannot
distinguish an omitted field from a valid status-looking filename when the whole
stream still has a valid parse. Ignored ordinary paths do not create mappings
or participate in rename endpoint uniqueness checks.

The importer validates map structure and paths only. It has no report/ledger
context: `compare --path-map` still checks collisions with unmapped prior files
and overlap with current Secret/Match values. It does not infer renames,
authenticate supplied records or open the named source files. Opt-in filtering
does not prove scan completeness or file correspondence.
An empty imported map **still enables conservative mapping mode** when passed to
compare: shared same-path files retain correspondence; other unmapped paths are
`uncomparable`, not inferred additions, removals or renames. Omitting `--path-map`
has different semantics. Reproduce the focused checks with:

```sh
python -m pytest tests/secretledger/test_import_renames.py
```

## Reproducible position-only baseline comparison

```sh
python scripts/secrets/compare_naive.py
```

The script actually runs both algorithms on a small synthetic corpus, asserting
result counts and retention of all 340 current occurrences. The baseline uses
exact native Fingerprint set membership: position-only fingerprints for the
same-line replacement cohort, commit-bearing fingerprints for the churn cohort.
This is **not** a benchmark of all Gitleaks baseline behavior.

One recorded run (Linux x86_64, CPython 3.14) is in
[`examples/secrets/comparison-measurement.json`](../examples/secrets/comparison-measurement.json):

| Measure | Position fingerprint baseline | Content ledger |
| --- | ---: | ---: |
| Changed content detected (40 cases) | 0 | 40 |
| Churn review units (25 contents × 12 occurrences) | 300 | 25 |
| Repeated churn units beyond one per content | 275 | 0 |

All 340 current occurrences remain in 65 ledger groups. Five-run median wall
times in the recorded run were 0.021572 ms for the baseline and 10.287707 ms for
the ledger **including construction of the prior snapshot**. Timing excludes
CLI I/O and will vary; HMAC grouping does more work. The improvement measured is
changed-content visibility and review deduplication, with **no speedup or
security-proof claim**.

## Metadata privacy scaling and resource limit

Privacy validation checks every nonempty Secret **and Match**, including unknown
and explicitly redacted values, against all retained rule/path/commit/fingerprint
fields, prior evidence, and supplied mapping paths. Matching remains exact,
case-sensitive Unicode substring matching; fields are checked separately. Up to
16 distinct values use direct searches. Larger sets use one multi-pattern
Aho-Corasick index, reused across a comparison. Values longer than 8192 characters
cannot fit any retained field and are excluded from the index only.

The index is limited to **250,000 states**, including its root. Exceeding this
budget raises `LedgerError`; the CLI returns **exit 2**, empty stdout and no
output artifacts. The value-free diagnostic says to reduce the **complete scan
scope consistently for both snapshots and rebuild the prior ledger**. Do not
split a full report and compare its pieces against the original full ledger:
that would invalidate absence conclusions. This guard also applies with
`--redacted`; redaction never disables metadata privacy checks. It bounds index
states, not total process memory. The existing 64 MiB file limit still applies;
library callers remain responsible for their input size.

For example, a safe 1000-group synthetic report from
`scripts/secrets/benchmark_privacy.py` retains all 1035 occurrences (including exact
duplicates); missing and `[masked]` content stays unknown. Embedding any of its
Secret/Match strings in another row's valid path/fingerprint, in prior metadata,
or in an unused map entry fails before output. A report with 40 long synthetic values
(each with an 8000-character suffix) can exceed the state budget despite fitting
the file limit; the test suite covers this diagnostic and no-output behavior,
including `--redacted`.

Reproduce measurements with public synthetic inputs only:

```sh
python scripts/secrets/benchmark_privacy.py
# Measure another core.py (for example an older revision) with the same runner and data:
python scripts/secrets/benchmark_privacy.py --core path/to/other/core.py
```

Recorded on Linux x86_64 / CPython 3.14 in
[`examples/secrets/privacy-measurement.json`](../examples/secrets/privacy-measurement.json).
Each time is the median of three untraced runs after a warmup. Peak memory is
from a **separate tracemalloc run**, in MiB of Python allocations during the
operation, **not process RSS**. Input/prior construction and JSON/CLI I/O are
excluded. Before/after fixture and output SHA-256 hashes match at both sizes.

| Groups | Operation | Before time | After time | Before peak | After peak |
| ---: | --- | ---: | ---: | ---: | ---: |
| 1000 | Snapshot | 187.64 ms | 21.63 ms | 0.90 MiB | 3.06 MiB |
| 1000 | Mapped comparison | 519.41 ms | 41.72 ms | 1.97 MiB | 3.87 MiB |
| 4000 | Snapshot | 3076.72 ms | 85.19 ms | 3.60 MiB | 11.98 MiB |
| 4000 | Mapped comparison | 8172.88 ms | 156.24 ms | 7.74 MiB | 15.24 MiB |

Before the indexed privacy check, snapshot time grew 16.4× for 4× the groups. Profiling that earlier
4000-group comparison put 36.88 of 49.22 instrumented seconds in metadata checks
and another 11.80 in mapping validation. On this corpus, the current implementation
measured 8.7×/36.1× faster snapshots and 12.5×/52.3× faster mapped comparisons
at 1000/4000 groups, with increased allocation peaks. These are local synthetic
measurements, not a general-history/scanner benchmark or a security proof.
Input parsing, validation and output size can still dominate other workloads;
the separate same-path replacement measurement below covers another bottleneck.

## Replacement candidate scaling

Comparison indexes prior known groups by **rule, mapped path and start line**
only for buckets with an unmatched known current group that reaches replacement
lookup. Exact-only, current-unknown-only, empty, unmapped and prior-unknown-blocked
buckets build no line memberships. A separate rule/path lookup retains prior
unknowns. A single prior-group pass collects group indexes for needed buckets.
Buckets with no prior known candidates are then removed from replacement
scheduling. They classify without visiting current occurrences to collect query
lines or construct lookup line sets. This also covers same-path rule changes,
explicitly mapped files with no prior findings, and new paths without mapping.
Unknown evidence and conservative unmapped-path handling still take precedence.
Each nonempty needed bucket is indexed on its first replacement query and released
immediately after its last query. Current groups are sorted by rule/path/HMAC,
so at most one line-membership index is live. Each bucket is indexed once;
several replacements never trigger repeated full-bucket scans. Before indexing, a
forward walk through the contiguous current bucket collects distinct start lines
from unmatched known groups only. Exact and unknown groups request no lines.
The prior occurrence pass retains memberships only for those requested lines;
all-miss queries retain none. If the built index is empty, every query in that
bucket classifies without constructing a lookup line set or revisiting its
occurrences. The empty index remains built until the last query, so it is never
rebuilt. Nonempty prior buckets still require one current query-line collection
pass and one prior occurrence indexing pass. The query-line set is released after
index construction, before lookups. With a nonempty index, one lookup occurrence
pass retains only distinct current start lines present in that index; queried
misses never enter the per-query line set. This set is bounded by the active
index keys and released, together with the candidate-union set, after evidence
construction. A fully missing query within a partially hitting bucket retains
no lookup lines. Evidence includes every overlapping prior
group, sorted as before and listed once even when several lines overlap. The
original paths, fingerprints and complete occurrence lists (including duplicate
records) remain intact. Matching uses start lines only; it never infers an
exclusive one-to-one replacement or matches across rules or unmapped files.

Exact HMAC/rule/path matches still take precedence over unknowns and line
candidates. Otherwise any prior unknown in the rule/mapped path makes new
content uncomparable, even at another line. Current unknowns still prevent
prior absence claims. No output schema, CLI option or classification changed.

Reproduce the focused regressions and the synthetic measurement:

```sh
python -m pytest tests/secretledger/test_replacements.py
python scripts/secrets/benchmark_replacements.py
python scripts/secrets/benchmark_replacements.py --workloads exact redacted unknown
python scripts/secrets/benchmark_replacements.py --sizes 64 256 --buckets 16 \
  --workloads replacement exact redacted unknown --repeats 3
python scripts/secrets/benchmark_replacements.py --sizes 16 64 --buckets 8 \
  --lines-per-group 16 --workloads empty-candidates mixed-empty --repeats 3
python scripts/secrets/benchmark_replacements.py --sizes 16 64 --buckets 4 \
  --lines-per-group 16 --workloads many-miss mixed-miss --repeats 3
python scripts/secrets/benchmark_replacements.py --sizes 16 64 --buckets 4 \
  --lines-per-group 16 --workloads partial-hit mixed-partial --repeats 3
```

The deterministic work regression failed on the prior implementation with
66,048 prior-occurrence visits for 256 replacements, against a budget of 2,048.
The indexed implementation passes that budget. Explicit evidence contracts and
60 seeded cases also agree with an independent exhaustive comparison oracle.
On a synthetic corpus of 1000 and 4000 changed-content groups sharing one rule/path
(same-path and explicit-rename variants, identical input/output hashes before and after),
the indexed comparison was roughly 5x faster at 1000 groups and 17-20x faster at 4000
groups than a full candidate scan, with slightly higher Python allocation peaks.
These are local synthetic measurements, not a general
scanner or history performance guarantee.

Indexing removes exhaustive candidate scans; it cannot bound output size. If every new
group overlaps every prior group, the required evidence itself is quadratic. Parsing,
validation, occurrence sorting and serialization remain in memory, and there is no total
runtime or process-memory bound.

## Library

```python
from vulnwrench.secretledger import compare, load_json, load_renames, read_key, snapshot

key = read_key(".local-ledger/review.key")
before = snapshot(load_json("authorized-before.json"), key)
comparison, current = compare(before, load_json("authorized-after.json"), key)
# Optional rename-aware mode (an empty list enables conservative mapping too):
comparison, current = compare(before, load_json("authorized-after.json"), key,
                             path_map=[{"old_path": "src/config.py",
                                        "new_path": "lib/config.py"}])
# Or import a supplied rename-only NUL stream (no Git invocation or key needed):
mapping = load_renames("supplied-name-status.z")
# Explicitly validate and discard A/M/D/T records in a supplied mixed stream:
mapping = load_renames("supplied-mixed.z", allow_non_renames=True)
# import_renames(raw_bytes, allow_non_renames=True) exposes the same byte parser.
# Persist only comparison/current; LedgerError messages contain no input values.
```

Functions do not mutate caller reports or execute code; they return JSON-safe
dictionaries. The file CLI applies size/regular-file limits; in-memory library
callers are responsible for input resource limits and safely persisting results.

## Verification

```sh
python -m pytest tests/secretledger
python scripts/secrets/verify_examples.py
python scripts/secrets/compare_naive.py
```

`verify_examples.py` regenerates the four committed ledger/comparison artifacts in a
temporary directory, compares them byte for byte and checks that no synthetic secret
reaches any output.

## Upstream relationship and limits

[Gitleaks](https://github.com/gitleaks/gitleaks) already provides fingerprints
and native baselines. `vulnwrench secrets` is a separate redacted, content-aware review
history for full reports. It never writes `.gitleaksignore`, exports a native
baseline, validates credentials, rotates secrets, scans history, executes target
code, uploads data, or claims scanner-equivalent coverage. Findings already
suppressed/omitted upstream cannot be recovered by this tool.

Motivating upstream discussions include Gitleaks issues
[2239](https://github.com/gitleaks/gitleaks/issues/2239),
[1054](https://github.com/gitleaks/gitleaks/issues/1054), and
[1284](https://github.com/gitleaks/gitleaks/issues/1284). The field mapping follows the
official Gitleaks README. Source and rule code were independently implemented;
no Semgrep source/rules or source-available implementation is reused. See
[LICENSE](../LICENSE) and [THIRD_PARTY.md](../THIRD_PARTY.md).

The HMAC hides raw content from the persisted ledger while its key remains
private; it does **not** make low-entropy secrets safe when the key is exposed.
Key IDs/HMACs link equality, and paths/commits/fingerprints can remain sensitive.
This is not an authenticated/signed ledger: protect prior ledgers from tampering.
The raw report necessarily enters process memory; Python does not guarantee
memory zeroization. Protect input reports, directories, terminal destinations
and backups. Arbitrary redaction formats, cross-repository comparisons,
automatic rename discovery, symlink/source resolution and scan-completeness verification are
out of scope. The tests and examples use synthetic inputs only.

