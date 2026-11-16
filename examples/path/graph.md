# SBOM dependency witnesses

Only explicit edges are traversed. Unreachable does not mean safe.

Roots: app, worker. Inferred edges: 0.

Roots selected explicitly: app, worker.

| Vulnerability | Ref | Artifact / PURL | Identity / state | Root | Shortest witness |
| --- | --- | --- | --- | --- | --- |
| CVE-2099-0001 | lib-v1 | pkg:npm/lib@1.0 | finding 0: reachable; exact-purl | app | app → left → lib-v1 |
| CVE-2099-0001 | lib-v1 | pkg:npm/lib@1.0 | finding 0: reachable; exact-purl | worker | worker → lib-v1 |
| CVE-2099-0001 | lib-v2 | pkg:npm/lib@2.0 | finding 1: reachable; exact-purl | worker | worker → lib-v2 |
| CVE-2099-0002 | orphan | pkg:npm/orphan@1.0 | finding 2: unreachable; exact-purl | — | — |
| CVE-2099-0003 | — | pkg:npm/not-in-bom@1.0 | finding 3: unmapped; unjoined | — | — |
| CVE-2099-0004 | no-purl | local-artifact | finding 4: reachable; explicit-artifact-id | app | app → no-purl |
| CVE-2099-0005 | — | unknown-artifact | finding 5: unknown\_identity; unjoined | — | — |

## Completeness and provenance

- \{"code": "explicit\_edges\_only"\}: Only dependencies\[\].dependsOn is traversed; no runtime exploitability or complete dependency coverage is implied. Other fields remain in evidence.
- \{"code": "dependency\_declarations\_missing", "refs": \["orphan"\]\}: These nodes have no dependency declaration; absence is not proof of no dependencies.
- \{"code": "dangling\_dependencies"\}: Unknown endpoint refs are reported and excluded from traversal.
- \{"code": "cycles\_detected"\}: DFS back edges prove cycles; traversal remains finite.
- \{"code": "component\_purls\_missing", "refs": \["app", "left", "no-purl", "right", "worker"\]\}: Components without PURLs require explicit artifact-id mapping to join.

## Dangling dependencies

- lib-v1 → missing-node; missing: missing-node
- unknown-source → \(declaration\); missing: unknown-source
- unknown-source → lib-v1; missing: unknown-source

Witness paths: 4; roots omitted: 0; paths omitted: 0.

Input digests (SHA-256, canonical JSON):

- bom: 1264f8ddf30dc4606fc43ece20fd18bc4fe72001d8a7504d70754e4d32172453
- grype: 0a5d51870046ba08e3cdcb566f094ef04d67aac2b384ed006759cc14438e03a5
- mapping: 9c0ec21624418ead80635e6ebc649656c86de2e7bb46fc4dacfb9c02cf857c40

Markdown is a projection. Use JSON for complete input evidence, mapping provenance, and per-finding details.
