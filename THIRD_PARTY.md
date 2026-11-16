# Third-party sources and attribution

vulnwrench is licensed under MIT (see [LICENSE](LICENSE)). The commands below were
previously separate MIT-licensed projects by the same authors; their notices are
preserved below, one section per command, with paths updated to this repository's
layout. vulnwrench has **no runtime dependencies**: every command uses only the Python
standard library, and the wheel contains only the `vulnwrench` package and these
project notices. License texts that must accompany redistribution are in
[licenses/](licenses/) (currently the CC0-1.0 dedication of the OpenVEX JSON Schema
used by the `vulnwrench triage` tests).

Product names identify interoperable formats only; vulnwrench is not affiliated with
or endorsed by Aqua Security (Trivy), Anchore (Grype, Syft), Google (OSV-Scanner),
the OpenSSF (Scorecard), OASIS (SARIF), CycloneDX/OWASP, SPDX/the Linux Foundation,
OpenVEX, FIRST (EPSS), CISA (KEV), Gitleaks, GitHub, Semgrep, or any other project
named here.

## At a glance

### Dependencies

| Package | License | Installed by | Used by |
| --- | --- | --- | --- |
| Python standard library | PSF-2.0 | Python itself | every command |
| [pytest](https://github.com/pytest-dev/pytest) (with iniconfig, pluggy: MIT; packaging: Apache-2.0 OR BSD-2-Clause; Pygments: BSD-2-Clause) | MIT | `test` extra | test runner only; the suites are `unittest` modules |

Build-only tools are [hatchling](https://github.com/pypa/hatch) (MIT; with pathspec: MPL-2.0,
trove-classifiers: Apache-2.0, packaging, pluggy) and
[hatch-fancy-pypi-readme](https://github.com/hynek/hatch-fancy-pypi-readme) (MIT).
CI additionally uses [ruff](https://github.com/astral-sh/ruff) (MIT), build (MIT) and twine (Apache-2.0).

### Bundled code and data

- **No third-party source code is vendored.** Every module under `src/vulnwrench/` is original MIT work.
- **No scanner, advisory database, EPSS/KEV feed, Scorecard result or rule pack is bundled.**
  Every command reads only the local files you pass it.
- **One third-party file is redistributed:** the unmodified OpenVEX v0.2.0 JSON Schema at
  `docs/triage/schemas/openvex-v0.2.0.schema.json` (CC0-1.0,
  [text](licenses/openvex-schema-CC0-1.0.txt)), used only by the `triage` test suite. It is in
  the source distribution, not the wheel.
- Test, example and benchmark fixtures (scanner reports, SBOMs, SARIF logs, Gitleaks reports,
  EPSS/KEV and Scorecard snapshots, ignore files) are original synthetic data under the root MIT
  license. They imitate the documented shapes of the upstream formats; identifiers such as CVE
  numbers, package names and digests are illustrative, not production evidence.
- The original standalone projects carried background research archives (upstream documentation
  excerpts and license texts studied while designing the formats). They are not part of this
  repository.

## Contents

- [`vulnwrench fuse` (formerly vulnfuse)](#vulnwrench-fuse-formerly-vulnfuse)
- [`vulnwrench delta` (formerly scan-delta)](#vulnwrench-delta-formerly-scan-delta)
- [`vulnwrench path` (formerly sbom-pathfinder)](#vulnwrench-path-formerly-sbom-pathfinder)
- [`vulnwrench layers` (formerly layer-attribution)](#vulnwrench-layers-formerly-layer-attribution)
- [`vulnwrench scorecard` (formerly scorecard-join)](#vulnwrench-scorecard-formerly-scorecard-join)
- [`vulnwrench ignores` (formerly ignore-audit)](#vulnwrench-ignores-formerly-ignore-audit)
- [`vulnwrench triage` (formerly triage-bridge)](#vulnwrench-triage-formerly-triage-bridge)
- [`vulnwrench secrets` (formerly secret-ledger)](#vulnwrench-secrets-formerly-secret-ledger)
- [`vulnwrench exploit` (formerly exploit-gate)](#vulnwrench-exploit-formerly-exploit-gate)
- [`vulnwrench sarif` (formerly sarif-gate)](#vulnwrench-sarif-formerly-sarif-gate)

## `vulnwrench fuse` (formerly vulnfuse)

vulnfuse's Python implementation, synthetic fixtures, tests and documentation are
independently written and MIT-licensed. It has no third-party runtime dependencies.
No scanner, scanner rules, advisory database, Semgrep source, or source-available
implementation is included. The research archive the original project carried
(upstream READMEs, license texts, issue excerpts and an evidence-only Grype Go source
snapshot) is not part of vulnwrench.

`vulnwrench fuse` reads report formats associated with the following projects. It is
not a fork of, endorsed by, or a replacement for those scanners. No upstream source
fragments were copied into `src/vulnwrench/fuse/`, `scripts/fuse/`, `tests/fuse/` or
`examples/fuse/`.

| Project | Relationship | Upstream license |
| --- | --- | --- |
| [Trivy](https://github.com/aquasecurity/trivy) — Aqua Security and contributors | JSON `Results[].Vulnerabilities[]` adapter | [Apache-2.0](https://github.com/aquasecurity/trivy/blob/main/LICENSE) |
| [Grype](https://github.com/anchore/grype) — Anchore and contributors | JSON `matches[]` adapter | [Apache-2.0](https://github.com/anchore/grype/blob/main/LICENSE) |
| [OSV-Scanner](https://github.com/google/osv-scanner) — Google and contributors | JSON `results[].packages[].vulnerabilities[]` adapter | [Apache-2.0](https://github.com/google/osv-scanner/blob/main/LICENSE) |

All example vulnerability IDs, packages, paths and advisory details under
`examples/fuse/` and `tests/fuse/` were created for synthetic test cases; they are not
claims about real advisories.

## `vulnwrench delta` (formerly scan-delta)

scan-delta's Python implementation, tests, scripts, fixtures and documentation are
independently written and MIT licensed. No scanner engine, upstream source fragments,
Semgrep rules, or source-available implementation was copied. There are no third-party
runtime, build, or test Python dependencies. CPython and optional pip/uv installers
retain their respective licenses and are not redistributed inside the wheel.

This command consumes documented, deliberately restricted Trivy and Grype report shapes
and the CycloneDX inventory shape; it is not affiliated with their maintainers.

| Referenced upstream | Project license | Relationship |
| --- | --- | --- |
| [Trivy](https://github.com/aquasecurity/trivy) | Apache-2.0 | Report format (schema 2) consumed; no code copied |
| [Grype](https://github.com/anchore/grype) | Apache-2.0 | Grype 0.86.1 JSON format supported by an independent adapter; no code copied |
| [OSV-Scanner](https://github.com/google/osv-scanner) | Apache-2.0 | Context only; not parsed by this command |
| [CycloneDX CLI](https://github.com/CycloneDX/cyclonedx-cli) | Apache-2.0 | Related component-diff tool; not a dependency |

The original project's research archive (upstream documents, license texts, issue
evidence and a pre-existing Go source reference, `grype_ignore.go`) is not part of this
repository; no code from that reference was used or shipped. Upstream rights remain
applicable to those materials, and the MIT license does not replace upstream licenses.

All advisory IDs, package scans, database IDs and inventories under `examples/delta/`
and `scripts/delta/corpus.py` are synthetic test data, not security advice or claims
about real package versions. The `scan-delta:target` / `scan-delta:package-path`
CycloneDX property names and the `"tool": "scan-delta"` output field are kept from the
original tool for compatibility.

## `vulnwrench path` (formerly sbom-pathfinder)

sbom-pathfinder's code (`src/vulnwrench/sbompath/`), scripts, tests and synthetic
fixtures are independently authored under MIT. They do not copy upstream
implementation code, rules, scanners or source-available material. Runtime and tests
use only Python's standard library. No Grype/Syft/CycloneDX/sbomqs binary is required or
invoked, and no Semgrep engine or rule material is incorporated. The research corpus
the original project carried (archived documents, license texts, issue excerpts and
source evidence under their own upstream copyrights) is not part of vulnwrench.

The command consumes documented report structures and is unaffiliated with these
projects. Their names identify input formats or neighboring tools, not sponsorship.

| Project | Relationship | Upstream license |
| --- | --- | --- |
| [Syft](https://github.com/anchore/syft) | Can produce CycloneDX JSON; no native Syft relationship inference | Apache-2.0 |
| [CycloneDX CLI](https://github.com/CycloneDX/cyclonedx-cli) | Existing analysis/conversion/merge/diff tool; not bundled | Apache-2.0 |
| [Grype](https://github.com/anchore/grype) | Reads local `matches[].artifact.purl` and vulnerability IDs | Apache-2.0 |
| [sbomqs](https://github.com/interlynk-io/sbomqs) | Existing SBOM quality scoring; not bundled | Apache-2.0 |

### Format and specification references

Referenced for field and grammar compatibility only; no schema, specification text or
Graphviz code is bundled, and Graphviz is not required.

- [CycloneDX](https://cyclonedx.org/) JSON 1.4-1.6: `components`, `dependencies`, `metadata.component`
- [SPDX 2.3 JSON Schema](https://github.com/spdx/spdx-spec/blob/v2.3/schemas/spdx-schema.json) and
  [relationship definitions](https://github.com/spdx/spdx-spec/blob/v2.3/chapters/relationships-between-SPDX-elements.md):
  package/`DEPENDS_ON` projection
- [Graphviz DOT language](https://graphviz.org/doc/info/lang.html) and
  [escString](https://graphviz.org/docs/attr-types/escString/): DOT output grammar and escaping

All `examples/path/` inputs are small, authored synthetic format fixtures. CVE-2099 IDs,
package names, paths and example.invalid links illustrate behavior and are not real
vulnerability intelligence. Outputs were generated by the local CLI.

## `vulnwrench layers` (formerly layer-attribution)

The implementation in `src/vulnwrench/layers/`, its scripts (`scripts/layers/`), tests
(`tests/layers/`) and synthetic fixtures (`examples/layers/`) are independently written and
MIT licensed. No scanner implementation, upstream rules or source-available code was
copied. There are no third-party runtime dependencies.

The input adapter uses Trivy's report field names and OCI image config/manifest data
(subset of the [OCI Image Specification v1.1.1](https://github.com/opencontainers/image-spec/tree/v1.1.1),
Apache-2.0; no schema or specification text is bundled). These projects are related
upstreams, not bundled runtime components:

| Project | License | Relationship |
| --- | --- | --- |
| [Trivy](https://github.com/aquasecurity/trivy) | Apache-2.0 | Schema-2 container image vulnerability JSON adapter |
| [Syft](https://github.com/anchore/syft) | Apache-2.0 | Related layer/location evidence tooling; no adapter |
| [Grype](https://github.com/anchore/grype) | Apache-2.0 | Related vulnerability/layer tooling; no adapter |

The original standalone project's background research material (including a Grype
source file studied as research, covered by Grype's Apache-2.0 license) is not part of
this repository or of the vulnwrench wheel. There is no claim of affiliation with or
endorsement by upstreams.

## `vulnwrench scorecard` (formerly scorecard-join)

The `src/vulnwrench/scorecard/` implementation, tests (`tests/scorecard/`), verifier
(`scripts/scorecard/`), documentation and synthetic example fixtures
(`examples/scorecard/`) were written independently and are MIT licensed. No upstream
scanner implementation, check scoring logic, rules, or source fragments were copied.
It imports only the Python standard library at runtime. It does not distribute or
execute Scorecard, Syft or CycloneDX CLI.

| Documented format / integration | Upstream code license | Relationship |
| --- | --- | --- |
| [OpenSSF Scorecard](https://github.com/ossf/scorecard) JSON snapshots ([check documentation](https://github.com/ossf/scorecard/blob/main/docs/checks.md)) | Apache-2.0 | Result JSON layout read as input; no code copied |
| [Syft](https://github.com/anchore/syft) CycloneDX JSON exports | Apache-2.0 | Inventory input format; no code copied |
| [CycloneDX CLI](https://github.com/CycloneDX/cyclonedx-cli) JSON exports | Apache-2.0 | Inventory input format; no code copied |

Apache-2.0 here describes those projects' code, not a blanket license for user
reports. Scorecard's README describes its published API data as
CDLA-Permissive-2.0. This repository ships **only synthetic snapshots**, not a copy of
that dataset. Users must retain the provenance and applicable terms of their own input
data. The output includes entire supplied documents, including their notices and
extension fields; do not assume output is free of sensitive information.

The upstream names identify compatible input formats. This command is not an upstream
release, endorsement, certification, or affiliated product.

## `vulnwrench ignores` (formerly ignore-audit)

`src/vulnwrench/ignoreaudit/`, `scripts/ignores/`, `tests/ignoreaudit/` and the synthetic
`examples/ignores/` fixtures are independent implementations under the root MIT license.
No upstream engine, rule, or implementation fragment was copied into these files. There
are no third-party runtime or test dependencies.

The adapters consume documented local report/config formats from:

| Project | License | Relationship |
| --- | --- | --- |
| [Trivy](https://github.com/aquasecurity/trivy) | Apache-2.0 | `.trivyignore` text and vulnerability-only SchemaVersion 2 JSON |
| [OSV-Scanner](https://github.com/google/osv-scanner) | Apache-2.0 | `IgnoredVulns` TOML and `results`/`source`/`packages` JSON |
| [Grype](https://github.com/anchore/grype) | Apache-2.0 | Motivation only; no Grype parser or runtime integration |

This project is not affiliated with or endorsed by those projects. Their names
identify file formats and prior work, not code ownership. The original standalone
project's research corpus (upstream documentation, issue excerpts, license texts) is
not part of this repository or the vulnwrench wheel; those materials retain their
original rights and are not relicensed. No Semgrep source or rules, source-available
engine, or research scripts are used.

## `vulnwrench triage` (formerly triage-bridge)

triage-bridge is independently implemented under MIT. It does not vendor or
execute any upstream scanner or vexctl implementation. No Semgrep source, rules,
source-available implementation, or third-party package is used; runtime and tests
use only Python's standard library.

### Format references

| Upstream | License | Relationship |
| --- | --- | --- |
| [Aqua Security Trivy](https://github.com/aquasecurity/trivy) | Apache-2.0 | `.trivyignore.yaml` filtering format (documented field shapes); not bundled or executed |
| [Google OSV-Scanner](https://github.com/google/osv-scanner) | Apache-2.0 | `osv-scanner.toml` `IgnoredVulns` / `PackageOverrides` configuration format; not bundled or executed |
| [OpenVEX vexctl](https://github.com/openvex/vexctl) | Apache-2.0 | OpenVEX document conventions; not bundled or executed |
| [OpenVEX specification](https://github.com/openvex/spec) | CC0-1.0 | OpenVEX v0.2.0 statement semantics |

### Bundled third-party file

The unmodified official OpenVEX v0.2 JSON Schema is redistributed as
`docs/triage/schemas/openvex-v0.2.0.schema.json` (upstream:
https://github.com/openvex/spec/blob/main/openvex_json_schema_0.2.0.json). Its
CC0-1.0 dedication is preserved next to it in `docs/triage/schemas/LICENSE.openvex`
and in [licenses/openvex-schema-CC0-1.0.txt](licenses/openvex-schema-CC0-1.0.txt).
The schema is used only by the test suite (`tests/triage/schema_subset.py`), which
checks emitted documents with a deliberately limited, fail-closed test-only evaluator,
not a general JSON Schema implementation. It is in the source distribution, not the
wheel. `docs/triage/schemas/decisions-v1.schema.json` is original MIT work describing
the decision input format.

## `vulnwrench secrets` (formerly secret-ledger)

secret-ledger is an independent MIT implementation. Runtime and test code use the
Python standard library exclusively. No Gitleaks or Semgrep source, rules, templates
or other source-available implementation code is copied or bundled. Gitleaks is not
invoked, downloaded or required to run; the synthetic fixtures under
`examples/secrets/` follow its documented JSON finding field names.

| Reference | License | Relationship |
| --- | --- | --- |
| [Gitleaks](https://github.com/gitleaks/gitleaks), copyright (c) 2019 Zachary Rice | MIT | JSON report format (`--report-format json` finding fields) consumed as input; not bundled, linked or executed |

`examples/secrets/TEST-ONLY.key` is a deliberately public synthetic test key (the ASCII
bytes `0123456789abcdef0123456789abcdef`); every finding, name, email and commit in the
examples is fabricated. No third-party runtime packages or code fragments need
additional notices.

## `vulnwrench exploit` (formerly exploit-gate)

The `src/vulnwrench/exploitgate/` implementation, tests (`tests/exploitgate/`),
verification scripts (`scripts/exploit/`) and synthetic examples (`examples/exploit/`)
were independently written and are MIT licensed. No scanner source, Semgrep source or
rules, or source-available implementation was copied. There are no third-party
runtime or test dependencies.

The supported native JSON structures belong to these independent projects; this
command is not affiliated with or endorsed by them:

| Project | Upstream | Code license | Relationship |
| --- | --- | --- | --- |
| Trivy | https://github.com/aquasecurity/trivy | Apache-2.0 | Native JSON report layout (`SchemaVersion: 2`) read as input; no code copied |
| Grype | https://github.com/anchore/grype | Apache-2.0 | Native JSON report layout read as input; no code copied |
| OSV-Scanner | https://github.com/google/osv-scanner | Apache-2.0 | Native JSON report layout read as input; no code copied |

The EPSS CSV input corresponds to the FIRST EPSS publication format
(https://www.first.org/epss/data_stats). The KEV input corresponds to CISA's
Known Exploited Vulnerabilities catalog JSON
(https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
The checked-in examples are entirely synthetic; they are not redistributed
FIRST, CISA, OSV, or scanner findings and are not real vulnerability advice.
User-supplied snapshots retain their own source terms. The MIT license does not
relicense external data. Grype's own ignore-rule source was consulted as background
only; it is neither imported, executed, copied into this command, nor included in
the wheel.

## `vulnwrench sarif` (formerly sarif-gate)

sarif-gate is independently implemented under MIT. It has no third-party runtime,
build-backend, or test dependencies, and contains no copied scanner code or rules.
Python itself is separately licensed by the Python Software Foundation.

[microsoft/sarif-tools](https://github.com/microsoft/sarif-tools) (MIT, copyright
Microsoft Corporation) is a related tool, not a dependency or bundled implementation.
Its license text was retained in the original project's research archive, which is not
part of this repository; no sarif-tools code is used or included in the wheel.

[SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html)
is an OASIS interchange specification. This implementation uses documented JSON
field names and synthetic examples; it does not bundle a schema or specification.

[Semgrep issue #11605](https://github.com/semgrep/semgrep/issues/11605) motivates
careful report consumption. It is not proof of a defect in all current scanner
versions. No Semgrep source, rules, or source-available components are incorporated.
The Semgrep-shaped fixture under `examples/sarif/` is entirely synthetic, with no
copied rule contents. The report's `schemaVersion: "sarif-gate/1"` and
`generator.name: "sarif-gate"` fields are kept from the original tool for compatibility.
