# Named synthetic schema fixtures

These files are hand-authored **synthetic data in real report structures**, not
reports produced by actually invoking the upstream scanners. No compatibility
claim for every release follows from them. All fixtures are tiny, local and safe
to process offline. Unknown extension data is included intentionally.

| Fixture | Structural profile | Purpose |
| --- | --- | --- |
| trivy.json | Trivy SchemaVersion 2-style `Results[].Vulnerabilities[]` | CVE primary ID, npm PURL, Target/PkgPath, severity/fix data; different installed version |
| grype.json | Grype `matches[]`, `artifact`, `vulnerability`, `relatedVulnerabilities` | Explicit GHSA/CVE link, conflicting severity/fix, distinct PyPI ecosystem, path/accessPath |
| osv.json | OSV-Scanner `results[].packages[]` containing OSV-schema vulnerability objects | Transitive OSV/GHSA alias, raw CVSS vector, textual label, affected-package-specific fixes, different PURL qualifier |
| trivy-empty.json | `Results: []` | Recognized empty Trivy report |
| grype-empty.json | `matches: []` | Recognized empty Grype report |
| osv-empty.json | `results: []` | Recognized empty OSV report |
| unsupported.json | SARIF-like `runs: []` | Explicit unsupported-root failure; exit 2 |
| coverage.json | Local `vulnfuse-coverage-1` manifest | Byte-bound coverage for trivy.json plus empty Grype/OSV reports; mismatched targets, incomplete OSV scan and missing OSV database date |
| explain/{trivy,grype,osv}.json | Local synthetic instances of the same three scanner profiles | Two explicit alias links, same-name packages with distinct PURL subpaths and scanner paths, conflicting severity/fix evidence, an external alias bridge and an unlinked ID |
| explain/merged.json | Current `vulnfuse-1` merge of the three explain scanner fixtures | Saved evidence; no original files needed to explain |
| explain/dangling-alias.json | Same saved merge with one dangling alias `observationId` | Invalid reference; exit 2 before selection, no stdout or output replacement |
| database/{found,absent,coverage}.json | Two synthetic Trivy reports and a byte-bound coverage manifest | Same target, policy and database timestamp, different snapshot identities; one retained finding, no remediation inference |
| policy/{found,suppressed,coverage}.json | Two synthetic Trivy reports and a byte-bound coverage manifest | Same target, completion and database timestamp, different suppression policy declarations; one retained finding, no remediation inference |

Reproduce the committed outputs from the repository root (recorded input names are
repository-relative, so run from there):

```sh
vulnwrench fuse merge --trivy examples/fuse/trivy.json --grype examples/fuse/grype.json --osv examples/fuse/osv.json --output examples/fuse/expected/merged.json --markdown examples/fuse/expected/merged.md
python3 scripts/fuse/verify_examples.py
```

The verifier does not rewrite expected outputs. It runs the command in a temporary
output directory, checks exact bytes against the committed golden outputs,
verifies input digests and observation counts, repeats for determinism, and
checks empty/unsupported/unreadable/invalid inputs. Tests additionally generate
malformed identities/versions, wrong JSON types, duplicate JSON keys, non-finite
numbers, unknown ecosystem/PURL evidence, namespace/qualifier/version differences,
permission errors and link-alias output paths in temporary files.

The focused explanation fixture has 5 observations across 3 findings. Execute:

```sh
vulnwrench fuse explain --trivy examples/fuse/explain/trivy.json --grype examples/fuse/explain/grype.json --osv examples/fuse/explain/osv.json --advisory OSV-EXPLAIN-1 --package 'pkg:npm/demo@1.0#apps/api'
```

Expected output is [expected/explanation.json](expected/explanation.json): two
contributing observations, two direct alias links, HIGH/CRITICAL and 1.1/1.2
conflicts. The third evidence observation supplies a global alias link from
the worker package; it does not contribute to the API finding. Worker 9.9 and
unlinked-advisory 8.8 fix observations stay separate. Removing `--package` is
ambiguous and returns exit 2 before replacing output. `verify_examples.py` checks
the exact committed JSON, a byte-identical repeat, and that failure behavior.

The coverage fixture uses exact report names relative to this directory:

```sh
cd examples/fuse
vulnwrench fuse merge --trivy trivy.json --grype grype-empty.json --osv osv-empty.json --coverage-manifest coverage.json
```

Expected: two findings/two observations retained, with Grype `target-mismatch`
and OSV `database-timestamp-missing`/`scan-incomplete` for each absence. All
assessments have `canEstablishFixed: false`. No real scan completion or database
freshness is claimed: these are synthetic caller declarations. Editing input
bytes without updating their bound SHA-256 rejects the manifest with exit 2.

The policy fixture uses exact report names relative to `examples/fuse/policy/`:

```sh
cd examples/fuse/policy
vulnwrench fuse merge --trivy found.json --trivy suppressed.json --coverage-manifest coverage.json
```

Expected: two inputs, one observation and one finding (`CVE-POLICY-1`). Both
declarations assert the same target, complete scans and database timestamp.
`synthetic:suppress:none` and `synthetic:suppress:CVE-POLICY-1` model different
effective suppression policies; no policy was evaluated or scanner executed.
Top-level and absence assessments are `incomparable` with exactly
`scan-policy-mismatch`, and `canEstablishFixed` remains false. The verifier checks
the counts, reason codes and byte/entry provenance; the out-of-repository CLI test
also checks determinism and rejection of stale report bytes before output replacement.

Explain the saved report with the same expected explanation bytes:

```sh
vulnwrench fuse explain --merged examples/fuse/explain/merged.json --advisory OSV-EXPLAIN-1 --package 'pkg:npm/demo@1.0#apps/api'
```

`explain/merged.json` was generated by merging the three explain fixtures with
those repository-relative input names. `explain/dangling-alias.json` changes only
`aliasEdges[0].observationId` to a nonexistent observation. It must fail without
replacing output. Both fixtures are checked by the example verifier and saved-report
tests. The saved mode validates the whole current report profile against embedded
evidence before selecting; it does not authenticate original file-byte digests.

The database fixture uses exact names relative to `examples/fuse/database/`:

```sh
cd examples/fuse/database
vulnwrench fuse merge --trivy found.json --trivy absent.json --coverage-manifest coverage.json
```

Expected: two inputs, one observation and one finding (`CVE-SNAPSHOT-1`). Target,
policy, completion and timestamp declarations match, but snapshot labels A and B
differ. Global, per-absence and `comparedTo` assessments report `incomparable`
and exactly `database-identity-mismatch`; `canEstablishFixed` stays false.
The verifier checks counts and report/manifest byte and entry provenance.
Older manifests may omit `databaseIdentity` or set it to null; those declarations
are unknown (`database-identity-missing`). Existing coverage/policy fixtures use
a common synthetic snapshot label to isolate their original differences; this is
an unverified caller assertion, not a claim about real scanner databases.
