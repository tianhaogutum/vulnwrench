# vulnwrench path

A scanner tells you that a vulnerable package is somewhere in your dependency tree,
but not which of your applications pulls it in, or through which chain of
dependencies. `vulnwrench path` answers "which declared dependency roots can reach
the packages in this Grype report?" offline: it reads the explicit dependency edges of
a CycloneDX JSON or SPDX 2.3 JSON SBOM, joins findings by exact PURL or a user-supplied
mapping, and gives one shortest witness path for every affected root. Use it when you
triage a Grype finding and need to know who depends on the vulnerable package and why.

_Formerly the standalone `sbom-pathfinder` tool._

It does not generate SBOMs, run scanners, infer missing edges or judge runtime
exploitability. Standard library only; Python 3.11+.

## Quick start

```sh
pip install vulnwrench
vulnwrench path --help
vulnwrench path explain bom.json --grype grype.json --output out.json
vulnwrench path explain bom.json --grype grype.json --format markdown
vulnwrench path explain bom.json --grype grype.json --format dot --output witnesses.dot
```

`explain` is the only subcommand. The SBOM is a positional argument (CycloneDX JSON
1.4-1.6 or SPDX 2.3 JSON); `--grype` is required. To run the bundled synthetic
examples, use a clone of the repository and run from its root:

```sh
vulnwrench path explain examples/path/bom.json --grype examples/path/grype.json --output out.json
vulnwrench path explain examples/path/bom.json --grype examples/path/grype.json --format markdown
python3 scripts/path/verify_examples.py
```

| Option | Meaning |
| --- | --- |
| `bom` | CycloneDX JSON 1.4-1.6 or SPDX 2.3 JSON |
| `--grype FILE` | Local Grype JSON report (required) |
| `--mapping FILE` | Explicit artifact-id mapping JSON, `schemaVersion` 1 |
| `--root REF` | Component `bom-ref` or package `SPDXID`; repeat to replace the declared roots |
| `--no-roots` | Select no roots; reachability stays unknown |
| `--max-roots N` | Affected roots shown per result (default 100) |
| `--max-paths N` | Total witness paths in the report (default 1000) |
| `--format json\|markdown\|dot` | Output format (default `json`) |
| `--finding-index N` | Original zero-based Grype `matches[]` index; repeat; default all |
| `--no-findings` | Select no findings; keep roots and full input validation and evidence |
| `--max-nodes N`, `--max-edges N` | DOT only: emitted nodes (default 200) and witness edges (default 400) |
| `--include-input-digests` | DOT only: include canonical digests of the full original inputs |
| `--include-dangling-dependencies` | DOT only: include all full-input dangling-dependency diagnostics |
| `--include-missing-dependency-declarations` | DOT only: include full-input refs without dependency declarations |
| `--output FILE` | Output file; otherwise stdout |

## Examples and output

`examples/path/bom.json` declares `app → a → b`; `examples/path/grype.json` is a
synthetic fixture in Grype's native JSON structure, where vulnerability
`CVE-2099-0001` has `artifact.purl` `pkg:npm/b@2.0`. The complete generated output is
[examples/path/out.json](../examples/path/out.json). Its result is:

```json
{
  "vulnerabilityId": "CVE-2099-0001",
  "vulnerableRef": "b",
  "status": "reachable",
  "affectedRootCount": 1,
  "affectedRoots": [{"root": "app", "path": ["app", "a", "b"]}]
}
```

This is an excerpt of `results[0]` of the full report; `provenance.inferredEdges` is always 0.

The complex example contains a diamond, a cycle, two roots, the same name at different
versions, a missing PURL, an unreachable package and a dangling reference. The actual
output of the following command is stored in [examples/path/graph.md](../examples/path/graph.md):

```sh
vulnwrench path explain examples/path/graph.json \
  --grype examples/path/graph-grype.json --mapping examples/path/mapping.json \
  --root app --root worker --format markdown --output graph.md
```

The witnesses for `lib-v1` are `app → left → lib-v1` and `worker → lib-v1`; `lib-v2` is
reachable only from `worker`. `orphan` is unreachable; a package that does not exist is
`unmapped`; a finding with neither a PURL nor a mapping is `unknown_identity`. All are
kept rather than dropped.

```sh
# Truncated display; affected roots are still counted completely
vulnwrench path explain examples/path/graph.json \
  --grype examples/path/graph-grype.json --mapping examples/path/mapping.json \
  --root app --root worker --max-roots 1 --max-paths 1
```

`--max-roots` (default 100) limits **how many affected roots are shown per result**, not
the roots that take part in the search; `--max-paths` (default 1000) limits the number of
complete paths in the whole report. `affectedRootCount` always counts all selected
roots. `truncation.rootsOmitted` counts roots not shown; `pathsOmitted` counts only paths
of shown roots that were omitted because of the global path budget; such a path is
`null` and carries `pathOmittedReason`. The two counts never overlap. Finding a
vulnerability, missing edges or truncation are not policy failures: successful
processing exits **0**; input, format, argument or I/O errors exit **2**. There is no
gate or exit-code-1 policy.

## Explicit empty root selection (all output formats)

Without a root option, the roots declared in the SBOM are used; repeated `--root`
options are deduplicated by ref and **replace** the declared roots. `--no-roots`
explicitly selects zero roots, equivalent to `explain(roots=[])` in the API; it may be
repeated and is idempotent. It is mutually exclusive with any `--root`; mixing them in
either order exits **2** and keeps an existing output.

```sh
vulnwrench path explain examples/path/graph.json \
  --grype examples/path/graph-grype.json --no-roots --finding-index 1 --format json
# json can be replaced by markdown or dot; CycloneDX and SPDX both support --no-roots
```

The command exits **0**: the JSON has `roots=[]`, `provenance.rootSelection="explicit"`
and keeps the `no_roots` warning. Original `findingIndex=1` corresponds to `lib-v2`,
with status `roots_unknown`, `affectedRootCount=null` and `affectedRoots=[]`; there is
no witness and no report-budget omission. Unknown reachability is not turned into
unreachable. Markdown keeps `Roots: (unknown)` and the same result, and shows
`Roots selected explicitly: (none).`; DOT keeps the affected ref but has no root nodes
or witness edges. The DOT node budget can still drop the affected ref and records the
omission.

`--no-roots` combines independently with finding selection: by default all findings are
still analyzed; `--no-findings` additionally selects zero results, in which case DOT has
no nodes or edges. `unmapped` and `unknown_identity` statuses are unchanged and explicit
mappings still apply. All inputs are still fully validated; original evidence, digests,
graph diagnostics and the full input finding count are kept. It does not skip
unselected findings, malformed dependencies or mapping validation, and it is not an
input size or memory limit. Root and path budgets must still be positive and
DOT-only budgets are still DOT-only; failures do not replace an existing output, and
overwriting inputs or their hard links is refused.

Explicit root selection (CLI `--root` / `--no-roots`, or API `roots=[...]` / `roots=[]`)
adds one paragraph to Markdown after the existing root summary and before the finding
selection note and the result table:

```text
Roots selected explicitly: app, worker.
```

Refs are deduplicated and sorted in `explain`'s exact string order and use the
Markdown escaping; for example `--root worker --root app --root worker` shows only
`app, worker`. The paragraph lists all selected roots and is not cut by the affected
root or path display budgets. An explicit empty selection shows `(none)`, even together
with `--no-findings`; it means zero roots were selected and reachability stays unknown.
Without a root option (CycloneDX/SPDX declared roots, or no declared roots) the
paragraph is not added and the Markdown bytes are unchanged. The note does not change
JSON; the DOT root scope is described below. Explicit-root Markdown only adds this
paragraph; result rows, finding scope, warnings, budgets and input digests are
unchanged. [examples/path/graph.md](../examples/path/graph.md) is real output with
explicit non-empty roots.

## Selecting original findings (all output formats)

`--finding-index` applies to JSON, Markdown and DOT and uses the **zero-based index** of
the original Grype `matches[]`, not the row number of the sorted results. Without a
selection option everything is analyzed; repeated indexes are deduplicated, and all
selected findings/candidate results share one path budget. Selection happens before the
`--max-paths` allocation, so unselected findings consume no budget.

```sh
vulnwrench path explain examples/path/graph.json \
  --grype examples/path/graph-grype.json --root app --root worker \
  --format json --finding-index 1 --max-paths 1
vulnwrench path explain examples/path/graph.json \
  --grype examples/path/graph-grype.json --root app --root worker \
  --format markdown --finding-index 1 --max-paths 1
```

Both commands exit **0** and output only the result for original `findingIndex=1`:
`lib-v2`, `reachable`, complete `affectedRootCount=1`, witness `worker → lib-v2`. The
JSON has `provenance.selectedFindingIndexes=[1]`; `summary.activeFindings=6` is still the
number of all input matches, with `results=1`, `unmappedFindings=0`, `witnessPaths=1`
and both omission counts 0. Result, unmapped, witness and omission statistics cover
only selected results; graph information, input completeness warnings and the raw JSON
evidence/digests keep the full input scope, and unselected matches must still pass
validation. Markdown renders the same selected report; see the JSON for full evidence.

With an explicit selection, Markdown shows the selection scope before the result table;
the example above contains:

```text
Selected original finding indexes (Grype matches, zero-based): 1. Total active input findings: 6; selected results: 1.
```

Indexes are deduplicated and sorted by original `matches[]` index; `Total active input
findings` is the full input count and `selected results` the number of selected result
records. When one finding's PURL matches several candidate refs, the result count can
exceed the number of selected indexes. API `finding_indexes=[]` and CLI `--no-findings`
show indexes `(none)` and result count `0`, and still keep the full input count, roots,
diagnostics and digests. Without an explicit selection this paragraph is not added and
the Markdown bytes are unchanged. The scope note does not change result rows, escaping,
path/root budgets, raw evidence or input digests; the DOT finding scope is described
below.

`--no-findings` explicitly selects zero findings in all three formats, equivalent to
API `finding_indexes=[]`; it may be repeated and is idempotent. It is mutually exclusive
with any `--finding-index`; mixing them in either order exits **2** and keeps an
existing output.

```sh
vulnwrench path explain examples/path/graph.json \
  --grype examples/path/graph-grype.json --root app --root worker \
  --format json --no-findings
# json can be replaced by markdown or dot; --no-findings may also be repeated
```

The command exits **0**; the JSON has `provenance.selectedFindingIndexes=[]`,
`results=[]`, `summary.activeFindings=6`, and result, unmapped, witness and both
omission counts are **0**. Roots are still `app` / `worker`; all inputs are still fully
validated, and raw evidence, digests, graph diagnostics and input-scope warnings are
kept. An empty selection does not skip malformed matches, mapping or root validation.
Markdown shows `(none)`, 6 input findings and 0 results; DOT by default shows only the
two context roots, without affected nodes or witness edges. The DOT node budget can
still drop roots and records the omission; `--max-nodes` / `--max-edges` are still
rejected for JSON/Markdown. `--max-roots` / `--max-paths` must still be positive; an
empty selection produces no report-budget omissions. Without either selection option,
every format's default output bytes are unchanged.

Selection does not change reachability or complete root counts. For example, selecting
finding 0 with `--max-roots 1 --max-paths 1` still gives `affectedRootCount=2` and
`rootsOmitted=1`; selecting 0 and 1 with only `--max-paths 1` outputs 1 path in total
and records `pathsOmitted=2`. Negative, non-integer or nonexistent indexes exit **2**;
`--max-nodes` / `--max-edges` remain DOT-only and exit 2 for JSON/Markdown even with a
finding selection. Failures keep an existing output. Without selection arguments, the
output bytes of every format are unchanged.

## DOT dependency witness graph

```sh
vulnwrench path explain examples/path/graph.json \
  --grype examples/path/graph-grype.json --mapping examples/path/mapping.json \
  --root app --root worker --format dot --finding-index 0 --output graph.dot
# Node/edge truncation still exits 0; graph label and attributes record the omissions
vulnwrench path explain examples/path/graph.json \
  --grype examples/path/graph-grype.json --root app --root worker \
  --format dot --finding-index 0 --max-nodes 2 --max-edges 1
# Findings are selected first, then the path budget is allocated; earlier unselected findings consume none
vulnwrench path explain examples/path/graph.json \
  --grype examples/path/graph-grype.json --root app --root worker \
  --format dot --finding-index 1 --max-paths 1
```

The actual output of the first command is [examples/path/graph.dot](../examples/path/graph.dot).
The input contains a diamond and a cycle; finding 0 is still `reachable` with
`affectedRootCount=2`, and the graph has **4 nodes and 3 edges**: `app → left → lib-v1`
and `worker → lib-v1`. Roots are blue boxes, packages linked to the selected finding
are filled red (including `unreachable` candidates), and witness edges are bold; one
node can be both a root and an affected package. Packages of unselected findings are not
added to the graph, but all selected dependency roots are kept as context.

`--finding-index` is the **zero-based index** of the original Grype `matches[]` and may
be repeated; without it all findings are selected, and repeated indexes are
deduplicated. All candidate refs of a finding are kept; you cannot select by the row
number of the sorted results. The CLI selects findings before allocating `--max-paths`,
so unselected findings consume no budget; selection changes neither reachability nor the
complete affected-root count. The third command above keeps original `findingIndex=1`,
`affectedRootCount=1` and outputs `worker → lib-v2`; including context root `app`, there
are 3 nodes and 1 edge, no omissions and `truncated="false"`. The budget is still shared
by all selected findings/candidate results, not one per finding. The graph merges only
**one shortest witness per root and per result** from the report; it does not enumerate
all branches, cycles or alternative paths, and `witness_scope` and the graph label say
so. `input_cycles_detected` records whether the input graph has a cycle; the witness
subgraph itself is not guaranteed to contain it. Dangling edges never become witnesses.

`--max-nodes` (default **200**) and `--max-edges` (default **400**) must be positive
integers and apply only to DOT. Nodes keep roots first, then the selected affected refs,
then intermediate nodes, each group sorted by ref; edges are sorted by their endpoint
refs, and only edges whose endpoints were both kept are emitted, so DOT never implicitly
creates extra nodes. `nodes_total` / `edges_total` are the deduplicated union of the
witnesses kept in the report (plus roots and affected refs), **not the full SBOM graph
counts**. `nodes_omitted` / `edges_omitted` are the exact DOT omissions, the latter
including edges whose endpoints were dropped; the second command above yields 2 nodes and
0 edges, omitting 2 nodes and 3 edges, and still keeps the finding's affected-root count
of 2.

Explicit root selection (`--root` / `--no-roots`, API `roots=[...]` / `roots=[]`) adds
`root_selection="explicit"` and `selected_roots_json` to the DOT graph attributes. The
latter is a JSON array of **all** selected refs after `explain`'s deduplication and
sorting, for example `["app","worker"]`; an explicit empty selection is `[]`. After the
truncation summary and before the finding summary, the graph label shows
`Roots selected explicitly: app, worker.` or `Roots selected explicitly: (none).`. This
scope is independent of finding selection; even when `--no-findings` or `--max-nodes 1`
drops root nodes, the metadata and label keep the complete selection. The metadata uses
the same DOT-safe JSON encoding as `results_json`, so special refs decode exactly; the
human-readable label uses the usual escaping, with control characters and lone
surrogates shown as visible text.

For example, `--no-roots --finding-index 1 --format dot` still keeps original finding 1,
`roots_unknown`, `affectedRootCount=null` and no witness edges; an explicit empty root
selection is never read as unreachable. `--no-roots --no-findings --format dot` has no
nodes or edges and still declares the explicit empty root selection. Repeated
`--root worker --root app --root worker --no-findings --max-nodes 1 --format dot` keeps
only the `app` node with `nodes_omitted="1"`, but `selected_roots_json` still decodes to
`["app","worker"]`.

Only explicit-root DOT adds these two attributes and one label line; existing node/edge
statements, results/original indexes, unknown reachability, witnesses, budgets/omission
counts and evidence/digests are unchanged. Without a root option, CycloneDX/SPDX
declared roots and no declared roots add neither attribute nor the root scope line;
with the same finding selection, the root scope extension does not change the existing
DOT bytes. This DOT change does not change any JSON/Markdown bytes. Node/edge budgets
do not limit the length of the complete root metadata or label.

Explicit finding selection (CLI `--finding-index` / `--no-findings`, or the API) adds
`finding_selection="explicit"`, `selected_finding_indexes_json`, `active_findings` and
`selected_results` to the DOT graph attributes. Indexes are **zero-based** original
Grype `matches[]` indexes, deduplicated and sorted; an explicit empty selection is
`[]`. `active_findings` is the full input `summary.activeFindings`; `selected_results` is
the number of candidate result records actually included in this DOT, which can exceed
the number of indexes when one finding matches several refs. The label shows it after
the root scope and before the finding summary, for example:

```text
Findings selected explicitly (zero-based): 1. Total active input findings: 6; selected results: 1.
```

An empty selection shows `(none)` and result count `0`; an explicit selection of all
findings still shows the scope, distinguishing it from the default. The complete scope
and counts are not cut by node/edge/root/path budgets, and the root scope is kept
independently. Only these explicit selections add the four attributes and the scope
line; default `explain()` with default `to_dot()` DOT bytes and all JSON/Markdown bytes
are unchanged, as are existing nodes/edges, `results_json`, omission counts and input
evidence/digests.

In the API, `selected_finding_indexes_json` prefers the original selection from
`explain(finding_indexes=...)`; if filtering happens only in `to_dot(finding_indexes=...)`,
it records that formatter selection. When an already-selected report is filtered
further, the original scope is kept, the existing `selected_findings` still lists the
original indexes actually included in the DOT, and `selected_results` counts the
filtered candidates; the label adds `DOT findings emitted (zero-based): 1.` (or `(none)`
when empty). For example, selecting `[0,1,3]` and then filtering `[1]` keeps the JSON
scope `[0,1,3]`, with `selected_findings=[1]` and 1 result. Passing the same selection
through both CLI stages does not add a duplicate label; the formatter cannot restore
excluded findings or witnesses. Scope/count metadata and label length are not limited by
DOT node/edge budgets.

The optional `--include-input-digests` (API: `to_dot(report, include_input_digests=True)`)
adds the digest provenance of the complete original inputs to the DOT:

```sh
vulnwrench path explain examples/path/graph.json \
  --grype examples/path/graph-grype.json --format dot --finding-index 1 \
  --include-input-digests --output provenance.dot
```

Graph attribute `digest_algorithm="sha256-canonical-json"` comes verbatim from
`provenance.digestAlgorithm`; `input_digests_json` uses the same safe DOT/JSON encoding as
`results_json` and decodes exactly to `provenance.inputDigests`, containing `bom`,
`grype` and `mapping`. Without a mapping, JSON `null` is kept; with a mapping (including
an empty `artifacts`), the digest of that complete mapping is kept. A digest is the
SHA-256 of the UTF-8 serialization of the parsed original JSON with sorted keys, ASCII
escaping and no extra whitespace; the report's existing values are reused, not
recomputed. Object key order and file formatting do not affect the digest; array order
still matters. This is not a raw file-byte digest, a signature or an authenticity check.

The graph label gains one line after the truncation summary and before the root/finding
scope:

```text
Input digests: SHA-256 of canonical JSON for full original inputs (not the selected witness projection); mapping null means no explicit mapping input.
```

The provenance always covers the complete original inputs, including evidence of
unselected findings; it never becomes a digest of the selected witness subgraph. Even
with `--no-findings` / `--no-roots`, further formatter filtering or node/edge/root/path
budget omissions, the digests stay complete. For example, when only finding 1 is
selected and the description of unselected finding 0 changes, the default DOT bytes are
identical, while with the option the `grype` digest differs. DOT embeds no raw
evidence, mapping content or file paths; the full evidence is in the JSON.

Without this option, or with `False` in the API, all DOT bytes are unchanged; enabling it
only adds the two graph attributes and one label line, and existing scope,
results/original indexes, unknown/null status, nodes/edges, witnesses and omission counts
are unchanged. All valid JSON/Markdown output bytes are unchanged. The CLI flag may be
repeated and is idempotent; using it with default JSON, explicit JSON or Markdown exits
**2** and keeps an existing output; all input validation and the checks against
overwriting inputs/hard links still apply. The API option accepts only `bool`; other
types raise `InputError`.

The optional `--include-dangling-dependencies` (API:
`to_dot(report, include_dangling_dependencies=True)`) exports the full input's dangling
dependency diagnostics:

```sh
vulnwrench path explain examples/path/graph.json \
  --grype examples/path/graph-grype.json --root app --root worker \
  --format dot --finding-index 1 --include-dangling-dependencies --output diagnostics.dot
```

Graph attribute `dangling_dependencies_json` uses the existing safe DOT/JSON encoding and
decodes exactly to `report.graph.danglingDependencies`; it keeps the original order and
`from` / `to` / `missing` / `kind`, and the `to` of an unknown source declaration stays
JSON `null` rather than an empty string. `dangling_dependency_count` is the **number of
diagnostic records**, not the number of unique missing refs or edges; one unknown source
can produce one declaration record and several edge records. The example above has 3
records; adding `another-missing-ref` to `no-purl.dependsOn` makes it 4, while the
`worker → lib-v2` witness stays the same. The graph label gains one line after the
optional input digests and before the root/finding scope:

```text
Dangling dependency diagnostics (full input): 3 records; unknown endpoint refs excluded from traversal; no nodes or edges added.
```

The diagnostics always come from the **full input** and are not reduced by finding/root
selection, further formatter filtering or node/edge/root/path budgets; even
`--no-roots --no-findings` with no nodes or edges keeps them complete. Missing endpoints
are not added as nodes or witness edges, and no dependency is inferred. Valid SPDX input
exports `[]` with count `0`; unknown SPDX endpoints are still strictly rejected rather
than downgraded to dangling diagnostics. This option exports only dangling dependencies,
not missing dependency declarations, concrete cycle back edges or all warnings; the
other complete diagnostics remain in JSON/Markdown.

It can be combined with `--include-input-digests`. Without the flag, or with `False` in
the API, DOT bytes are unchanged; enabling it only adds these two graph attributes and
one label line, keeping existing results/original indexes, unknown/null status, selection
scope, digests, nodes/edges, witnesses and omission counts, and all valid JSON/Markdown
bytes unchanged. The flag may be repeated and is idempotent; using it with default JSON,
explicit JSON or Markdown exits **2** and keeps an existing output, and full input
validation and input/hard-link protection still apply. The API accepts only `bool` and
raises `InputError` otherwise. The metadata keeps exact refs (possibly sensitive); it is
neither redaction nor a full evidence export, and the number and length of diagnostics
are not limited by node/edge budgets.

The optional `--include-missing-dependency-declarations` (API:
`to_dot(report, include_missing_dependency_declarations=True)`) exports the refs in the
full input that have no dependency declaration:

```sh
vulnwrench path explain examples/path/graph.json \
  --grype examples/path/graph-grype.json --root app --root worker \
  --format dot --finding-index 1 --include-missing-dependency-declarations
```

Graph attribute `missing_dependency_declarations_json` uses the safe DOT/JSON encoding
and decodes exactly to `graph.missingDependencyDeclarations`;
`missing_dependency_declaration_count` is the length of that complete list. In this
example it is `["orphan"]` with count `1`, but `orphan` is not in the selected witness
and the diagnostic adds no nodes or edges. After adding a `{"ref":"orphan","dependsOn":[]}`
declaration, the list is `[]` with count `0`, and the default DOT and the non-empty
`worker → lib-v2` witness are unchanged. The label gains one line:

```text
Missing dependency declarations (full input): 1 refs; absence is not proof of no dependencies; no nodes or edges added.
```

The list always covers the full input and is not reduced by default/explicit/empty root
or finding selection, further formatter filtering or node/edge/root/path budgets.
CycloneDX distinguishes an explicit `dependsOn: []` from no source declaration; an
existing ref declaration without `dependsOn` is still described by the separate
`depends_on_absent` warning and is not listed as missing a declaration. SPDX package
`DEPENDS_ON NONE` / `NOASSERTION` both count as declarations and are not listed as
missing; `NOASSERTION` still means unknown, and `NONE` is still only an unverified author
assertion. `CONTAINS` markers are not dependency declarations. An empty list does not
prove that dependencies are complete, that a node is a leaf or that a package is safe.

Without this option, or with `False` in the API, all existing DOT bytes are unchanged;
enabling it only adds two graph attributes and one label line. It combines independently
with the digest and dangling-diagnostic options and does not modify the report,
results/indexes/status/null values, scope, witnesses, truncation or the inferred-edge
count. All valid JSON/Markdown bytes are unchanged. The CLI flag may be repeated and is
idempotent; using it with default/explicit JSON or Markdown exits **2** without replacing
an existing output. An empty selection still fully validates inputs, and the rules
against overwriting inputs and hard links are unchanged. The API accepts only `bool` and
raises `InputError` for other types. Exact refs may be sensitive, and the number/length of
the metadata is not limited by node/edge budgets; it is not a redactor and exports
neither all warnings nor raw evidence.

Graph attribute `results_json` is a JSON string that keeps, per result, `findingIndex`,
the vulnerability ID, the ref, the original status, the complete `affectedRootCount` and
the original report's truncation. `report_roots_omitted` / `report_paths_omitted` sum
only the report-budget omissions of the selected results. If a library caller first runs
`explain()` over all findings and then selects with `to_dot()`, the formatter cannot
restore paths the original report already omitted; select at the
`explain(finding_indexes=[...])` stage instead (see the API below). When any layer has
omissions, `truncated="true"` and the graph label shows all four omission counts; `false`
only means this shortest-witness projection omitted nothing because of budgets, not that
all paths were enumerated. Unknown identity, unmapped, unreachable and rootless results
are still kept in the graph label and `results_json`, and no edges are invented. Use the
JSON for raw evidence and complete diagnostics.

Exporting needs no Graphviz installation and starts no renderer. Following Graphviz's
[DOT grammar](https://graphviz.org/doc/info/lang.html) and
[escString rules](https://graphviz.org/docs/attr-types/escString/), it uses generated
node IDs and quoted plain-text labels; quotes, backslashes and substitution sequences
such as `\N` are escaped, newlines are used as label line breaks, and other control
characters and lone surrogates are shown as visible escape text. The DOT contains no HTML
labels, links or image directives. Budgets limit only node/edge statements, not labels,
result metadata, input evidence or the working memory used to build the projection; do
not treat them as a byte-size limit.

Nonexistent or negative finding indexes, invalid budgets, or DOT-only node/edge budgets
in JSON/Markdown mode exit **2**, and the API raises `InputError`; as with the other
formats, failures do not replace an existing output, and overwriting inputs or their hard
links is refused.

## SPDX 2.3 JSON projection

The format is detected from `spdxVersion="SPDX-2.3"`; fields follow the pinned
[SPDX 2.3 JSON Schema](https://github.com/spdx/spdx-spec/blob/v2.3/schemas/spdx-schema.json)
and [relationship definitions](https://github.com/spdx/spdx-spec/blob/v2.3/chapters/relationships-between-SPDX-elements.md).
This is a bounded package/dependency projection, not a complete SPDX validator or format
converter.

```sh
vulnwrench path explain examples/path/bom.spdx.json --grype examples/path/grype.json
vulnwrench path explain examples/path/bom.spdx.json --grype examples/path/grype.json --format markdown
# Explicit roots replace all documentDescribes / DESCRIBES roots
vulnwrench path explain examples/path/bom.spdx.json --grype examples/path/grype.json --root SPDXRef-a
```

The input [examples/path/bom.spdx.json](../examples/path/bom.spdx.json) is a local
synthetic fixture equivalent to the CycloneDX example. It declares
`SPDXRef-app DEPENDS_ON SPDXRef-a` and `SPDXRef-a DEPENDS_ON SPDXRef-b`, plus an extra
`SPDXRef-app CONTAINS SPDXRef-b`. The path in the expected output is still
`SPDXRef-app → SPDXRef-a → SPDXRef-b` with **2** edges; `CONTAINS` is kept as a diagnostic
with its original relationship index and cannot shorten the path. The complete actual
output is [examples/path/out.spdx.json](../examples/path/out.spdx.json). The tests map
`app/a/b` explicitly to these SPDX IDs and check that both PURL joins and artifact-id
mappings without PURLs give the same per-root witnesses.

| SPDX field | Supported scope and failure behavior |
| --- | --- |
| `SPDXID` / `packages[].SPDXID` | The document ID must be `SPDXRef-DOCUMENT`; nodes use explicit local `SPDXRef-` IDs (suffix only letters, digits, `.`, `-`). IDs must be unique across the document, packages, `files[]` and `snippets[]`; duplicate or missing IDs exit 2 |
| Package identity | Only `referenceLocator` of `packages[].externalRefs[]` entries with `referenceCategory="PACKAGE-MANAGER"` and `referenceType="purl"`, joined by exact `pkg:` string; other references are kept as is. A package may repeat the same PURL; several different PURLs are explicitly rejected rather than picked arbitrarily |
| Default roots | The deduplicated union of `documentDescribes[]` and the targets of `DESCRIBES` relationships from the document ID, which must point to packages; `--root` or API `roots` replace them. Without root declarations the status is `roots_unknown` with count `null`; roots are never inferred from package order, name or in-degree |
| Dependency edges | Only `relationships[].relationshipType="DEPENDS_ON"`, directed `spdxElementId → relatedSpdxElement`; both ends of a package-to-package edge must exist, and duplicate edges are deduplicated. Targets that are exactly uppercase `NONE` / `NOASSERTION` use the declaration diagnostics below and create no edge; other missing/unknown endpoints exit 2, and unknown nodes are never bridged |
| Other relationships | `CONTAINS`, `DEPENDENCY_OF`, `DESCRIBED_BY`, the build/test/runtime relationships and so on are never projected as dependencies or roots; they produce a `spdx_relationship_not_projected` warning (`relationshipIndex` points into the original array, with the type and both IDs), and the JSON evidence keeps the original relationship and its comments |
| Non-packages and scope limits | Files/snippets are registered by ID only, to check uniqueness and endpoints, and are not added to the dependency graph. Apart from the exact uppercase target markers `NONE` / `NOASSERTION` of package `DEPENDS_ON` and non-projected `CONTAINS`, relationship endpoints must be registered local elements. The source of a `CONTAINS` may be a registered document, package, file or snippet and must still pass full inventory validation. External `DocumentRef-...`, unknown IDs, markers as sources/roots, or markers as targets of other relationship types are unsupported and exit 2. Non-package `DEPENDS_ON` (including marker targets) or roots are also rejected. `hasFiles`, download locations and other fields create no edges |

Package `DEPENDS_ON NONE` means the author declares no dependencies and produces
`spdx_dependency_none`; package `DEPENDS_ON NOASSERTION` means the dependencies are unknown
and produces `spdx_dependency_noassertion`. Both warnings carry the original
`relationshipIndex`, `relationshipType`, `from` and `to`, and also appear in the Markdown
completeness section. Markers are not packages, dangling references or roots and add no
nodes or edges; both count as explicit dependency declarations and are not listed in
`missingDependencyDeclarations`, but the unknown nature of `NOASSERTION` is still kept by
its dedicated warning. `NONE` only preserves the author's assertion: it does not
independently verify completeness, prove safety, or remove other explicit edges from the
same source; contradictory declarations are not adjudicated.

```sh
vulnwrench path explain examples/path/markers.spdx.json --grype examples/path/grype.json
vulnwrench path explain examples/path/markers-no-roots.spdx.json --grype examples/path/grype.json --format markdown
```

This pair of synthetic fixtures differs only in the `documentDescribes` root declaration:
both contain the two real edges of `app → a → b`, `b DEPENDS_ON NONE` and
`app DEPENDS_ON NOASSERTION`. The first still gives the complete three-node witness with
**1** affected root; the second is `roots_unknown` with affected root count `null` and no
path. Markers never infer roots, `inferredEdges=0`, and the original relationships and
comments of both inputs are kept completely in the JSON evidence. A test with
marker-only dependency relationships also checks that the edge count is **0**, that other
packages are `unreachable` with roots and still unknown without.

`CONTAINS NONE` / `CONTAINS NOASSERTION` are also kept as `spdx_relationship_not_projected`
completeness diagnostics: the former is the author's (unverified) assertion that nothing
is contained, the latter means the contained elements are unknown. The warning keeps the
original `relationshipIndex`, type, source and exact target, and Markdown shows the
meaning too; the JSON evidence keeps the whole relationship, its comments and all input
fields. They **do not count as dependency declarations**, remove no package from
`missingDependencyDeclarations`, create no nodes, edges or roots, and do not remove
existing `DEPENDS_ON` edges. The source must still exist in the local inventory; a marker
as source cannot bypass validation.

```sh
vulnwrench path explain examples/path/contains-markers.spdx.json --grype examples/path/grype.json
vulnwrench path explain examples/path/contains-markers-no-roots.spdx.json --grype examples/path/grype.json --format markdown
```

This pair of fixtures differs only in `documentDescribes`: both declare
`app CONTAINS NONE` / `app CONTAINS NOASSERTION` at original relationship indexes **0** /
**3**, with the two dependency edges of `app → a → b` in between. With roots the shortest
witness is unchanged and there is **1** affected root; without roots the status is
`roots_unknown`, the count `null`, and there is no path. Both have `inferredEdges=0`, and
`b` still lacks a dependency declaration. With only `CONTAINS` markers the edge count is
**0** and all packages still lack dependency declarations; neither reachability nor
completeness is inferred from containment.

A missing `relationships` produces a warning and no edges; packages without an outgoing
`DEPENDS_ON` (including marker declarations) are listed in `missingDependencyDeclarations`,
which does not mean they have no dependencies. Mapping files use the same structure, with
the SPDXIDs of existing packages as values. The original SPDX input is always kept in
`evidence.bom`, digests cover the original parsed input; `provenance.bomFormat="SPDX"`,
`specVersion="SPDX-2.3"`, `rootSelection="spdx-declarations"` (with declared roots), and
`inferredEdges` is always 0. CLI failures exit 2 and keep an existing output; the API
raises `InputError`.

## Supported scope and field mapping

| Input | Fields used and handling |
| --- | --- |
| CycloneDX JSON | `bomFormat="CycloneDX"`; `specVersion` must be the string `1.4`, `1.5` or `1.6` |
| Components | `components[]` and nested `components[]`, `metadata.component` and its nested components; every component must have a non-empty `bom-ref`. Containment only declares nodes and never becomes a dependency edge |
| Roots | `metadata.component.bom-ref` by default; one or more `--root` options **replace** the default roots, selected by exact ref; `--no-roots` explicitly clears them. Without roots the status is `roots_unknown`; roots are never inferred from in-degree |
| Dependencies | `dependencies[].ref` is the source and `dependsOn[]` the array of target refs; only edges whose two ends are both in the component table are traversed. Duplicate edges are deduplicated and paths are not enumerated twice |
| Identity | Component `purl` and Grype `matches[].artifact.purl` are joined by full string equality; only a non-empty string starting with `pkg:` is checked. There is no full PURL syntax validation, normalization, version inference, qualifier reordering or case conversion |
| Grype findings | Top-level `matches` must be an array; each item must have `vulnerability.id` (non-empty string) and `artifact` (object); `artifact.id` is used for mappings. If present, `descriptor.name` must be `grype`. No scanner version is pinned, and no support for all past/future formats is claimed |
| Preserved evidence | `results[].findingIndex` points back to the original `matches` index; `evidence.bom/grype/mapping` keep the complete parsed inputs, including unknown extension fields, severity, fix information, aliases and matcher details; aliases and findings are never merged |
| Exclusions | Grype `ignoredMatches` are only kept verbatim, counted and noted; they take no part in reachability analysis, and `appliedIgnoreRules` is not read for policy decisions |

Missing, empty or null PURLs are all kept as unknown identities. A valid finding whose
exact PURL is not found is `unmapped`. When one PURL corresponds to several component
refs, all candidate refs are output separately, with `join.candidateCount` and a warning;
none is picked arbitrarily. A user mapping can override the PURL join; its structure is
(keys are Grype **artifact.id**, values one or more existing component refs):

```json
{"schemaVersion": 1, "artifacts": {"local-artifact": ["no-purl"]}}
```

A mapping is a user-supplied identity assertion and produces
`join.method="explicit-artifact-id"`; unused mapping entries produce an explicit warning.
After the join, the search still follows only the existing dependency edges.

## Completeness, determinism and limits

- Duplicate `bom-ref`s (including metadata/nested components), duplicate dependency source
  declarations, mappings to nonexistent targets, nonexistent explicit roots and
  non-array dependency structures are all rejected. Components without a `bom-ref` are
  also outside the supported subset.
- Missing `dependencies`, components without a dependency declaration, a missing
  `dependsOn`, missing PURLs and dangling edges all produce warnings. Dangling source
  declarations and dangling edges are kept in `graph.danglingDependencies`, and paths are
  never bridged through unknown nodes. An explicit `dependsOn: []` is distinguished from a
  missing declaration, but even complete declarations do not prove the real dependencies
  are complete.
- `unreachable` only means not reachable from the **selected roots** along the currently
  known edges; it does not mean the package is safe or unaffected. Without roots, mapped
  refs have status `roots_unknown` and an affected root count of `null`. When identity
  cannot be joined, the count is also `null`.
- An iterative DFS detects cycles in all connected components and reports the back edges
  that prove a cycle; it does not enumerate all cycles. BFS gives each root one shortest
  path; ties between equal-length paths are broken by sorted neighbors. When a root
  itself is affected, its path contains only that root.
- What is supported is the structural projection above, **not a complete CycloneDX JSON
  Schema validator**. Non-empty `services` and non-empty dependency `provides` are
  explicitly rejected; `compositions` completeness declarations are kept with a warning and
  not interpreted. Other unused fields are kept in the JSON evidence, and no edges or
  security conclusions are inferred from them.
- SPDX support is limited to the **2.3 JSON package/DEPENDS_ON projection** above; other
  SPDX versions, native Syft JSON, XML, SARIF, compressed files and other findings formats
  are unsupported and return 2. Only local regular file paths are read, never URLs, stdin
  or external BOM references; no source code is parsed, no target code or external script
  is executed, there is no network access and no key is needed.
- Each input is limited to **32 MiB**. JSON must be UTF-8 (a BOM is allowed); duplicate
  object keys, NaN/Infinity and JSON too deep to process safely are rejected. Error
  messages contain only fixed descriptions/structural positions and never echo input
  values, file names or exception details. The complete JSON evidence **may contain
  sensitive information from the inputs**; review a report before sharing it. The report
  is not a redactor.
- Path/root budgets do not limit the total number of findings, raw evidence or the size of
  the input root list. One BFS uses O(V) memory; the graph and affected-root lists are about
  O(V+E+T·min(R,root-cap)), and complete witness memory depends on the total number and
  length of paths; it is not suited to extremely large SBOMs. Each root runs one BFS over
  the full graph, and only roots whose paths are output run a second BFS; no unmeasured
  performance improvement is claimed.
- Output is byte-deterministic for identical inputs/options; results are sorted by
  vulnerability ID, PURL, artifact ID, original finding index and ref. Reordering input
  arrays can change original indexes and evidence/digests but does not affect the choice
  of shortest paths. Input digests are the SHA-256 of canonical JSON with sorted object
  keys and preserved array order, not hashes of the original file bytes.
- JSON is the format that keeps all evidence; Markdown is a safely escaped readable
  projection with vulnerabilities, refs, package identities, statuses, roots, witnesses
  and warnings. Files are written atomically through a temporary file in the same
  directory, and overwriting inputs or their hard links is refused. Without `--output`,
  output goes to stdout; the file extension does not select the format.

## Library API

```python
import json
from vulnwrench.sbompath import explain, to_markdown, to_dot, InputError

with open("examples/path/bom.json", encoding="utf-8") as handle:
    bom = json.load(handle)
with open("examples/path/grype.json", encoding="utf-8") as handle:
    grype = json.load(handle)
report = explain(bom, grype, roots=["app"], max_roots=20, max_paths=100)
print(to_markdown(report))
selected_report = explain(bom, grype, roots=["app"], finding_indexes=[0], max_paths=1)
print(to_dot(selected_report, max_nodes=200, max_edges=400))
# Optional: keep the digests of the complete original inputs in the DOT
print(to_dot(selected_report, include_input_digests=True))
# Optional: keep the full input's dangling-dependency diagnostics, adding no nodes/edges
print(to_dot(selected_report, include_dangling_dependencies=True))
# Optional: keep the full input's refs without dependency declarations; no leaf or safety inference
print(to_dot(selected_report, include_missing_dependency_declarations=True))
```

`explain` accepts JSON-compatible dicts and returns an independent copy; structural errors
raise `InputError`. `finding_indexes=None` analyzes everything; a list selects by original
`matches[]` index after deduplication, and an empty list returns zero results but keeps
the roots; invalid or nonexistent indexes raise `InputError`. Selection happens before the
root/path display budgets are allocated, still validates all inputs (including
unselected findings), and neither reduces raw evidence nor changes digests. An explicit
selection is recorded in `provenance.selectedFindingIndexes`; `summary.activeFindings`
is still the number of all input matches, while `results`, `unmappedFindings`, path and
omission statistics cover only selected results. Without a selection argument, the
original report structure and output are unchanged.

`to_markdown` / `to_dot` accept a report produced by `explain` and do not modify it;
`to_dot`'s `finding_indexes=None` selects all findings in the report, and an empty list
selects none (still showing the selected dependency roots). It can only filter existing
results further; it cannot restore findings excluded by `explain` or paths already
omitted. The CLI's `--finding-index` / `--no-findings` select at the `explain` stage in
JSON, Markdown and DOT alike; only the node/edge budgets are DOT-only. File size limits,
strict JSON parsing and safe I/O checks belong to the CLI layer; API callers are
responsible for using a trustworthy JSON parser, limiting input size and handling
exceptions appropriately.

## Tests

The suite under `tests/sbompath/` is standard-library `unittest` code (collected by
pytest) that uses only synthetic fixtures. It covers real-format CLI subprocess runs,
success and failure paths, two roots, diamonds, cycles and dangling nodes, multiple
versions, no roots, mappings, unknown identities, budgets, determinism, evidence
preservation, sensitive error messages and a 1500-node chain; SPDX cross-format witness
equivalence, markers and containment; and DOT selection, budgets, escaping/injection,
stable ordering and all opt-in DOT metadata, with an independent strict DOT-subset syntax
checker. Fixed-seed small random graphs are checked against an exhaustive simple-path
oracle. `scripts/path/verify_examples.py` runs 15 example scenarios and compares the
committed JSON/Markdown/DOT byte for byte, writing only to a temporary directory it
removes afterwards. The fixtures do not represent a real vulnerability database or real
scan results.

```sh
python -m pytest tests/sbompath
python3 scripts/path/verify_examples.py
```

## Upstream relationship and differences

[Syft](https://github.com/anchore/syft) generates SBOMs;
[CycloneDX CLI](https://github.com/CycloneDX/cyclonedx-cli) can already analyze, merge,
convert and diff them; [Grype](https://github.com/anchore/grype) scans for
vulnerabilities; [sbomqs](https://github.com/interlynk-io/sbomqs) scores quality. This
command only connects **existing local** Grype findings to the explicit dependency edges
of CycloneDX or SPDX 2.3, showing per-root shortest witnesses and where the data is
incomplete; it does not replace those tools or claim to be the first to do so. Syft issues
[#3071](https://github.com/anchore/syft/issues/3071) /
[#572](https://github.com/anchore/syft/issues/572) are background on relationship
completeness, not a statement about current upstream defects.

The implementation is MIT licensed; third-party relationships are described in
[THIRD_PARTY.md](../THIRD_PARTY.md).
