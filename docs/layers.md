# vulnwrench layers

A container scan lists every vulnerability in the image, but the fix depends on where it
came from: bump the base image, or change your own Dockerfile layers. `vulnwrench layers`
attributes each Trivy image finding to the base layers, the application layers, or
"unknown" when the evidence is insufficient, using only exact OCI DiffID prefixes from
local image configs (package names are never treated as proof). Use it to route findings
to the right owner, to fail CI only on app-layer findings, or to compare a base upgrade.

_Formerly the standalone `layer-attribution` tool._

It does not scan, pull images, execute history commands, contact registries, or
automatically suppress findings.

## Quick start

```sh
pip install vulnwrench
vulnwrench layers --help
vulnwrench layers explain \
  --report examples/layers/trivy.json \
  --base-config examples/layers/base.json \
  --image-config examples/layers/image.json \
  --output out.json
# CI gate: exit 1 when any app-layer or unknown-origin finding exists
vulnwrench layers explain --report examples/layers/trivy.json \
  --base-config examples/layers/base.json --image-config examples/layers/image.json --gate app
# Compare a base-image upgrade
vulnwrench layers compare \
  --before-report examples/layers/upgrade-before.json \
  --before-base-config examples/layers/base.json --before-image-config examples/layers/image.json \
  --after-report examples/layers/upgrade-after.json \
  --after-base-config examples/layers/upgraded-base.json \
  --after-image-config examples/layers/upgraded-image.json
```

Get the inputs from your own image with `trivy image --format json` (schema 2,
`container_image` artifact) and the image configs from `docker image inspect` /
`crane config` / `skopeo inspect --config` for the final image and its base. Python 3.11+;
no runtime dependencies. Run the quick start from a clone of the repository so the
`examples/layers/` paths resolve.

## CLI and real synthetic output

```sh
vulnwrench layers explain --report examples/layers/trivy.json \
  --base-config examples/layers/base.json --image-config examples/layers/image.json --output out.json
```

This command was run to produce [examples/layers/expected.json](../examples/layers/expected.json).
The eight synthetic findings produce these actual counts:

```json
{"base": 1, "app": 2, "unknown": 5, "total": 8}
```

`DEMO-APP-UPGRADE` and `DEMO-BASE` deliberately share the package name `openssl`.
The app finding has `origin: "app"`, `proof: "exact_diff_id"`, the full `sha256:bbbb…`
DiffID (64 hexadecimal digits), and image history index 3, command
`COPY synthetic app upgrade /app`. The first and third history entries are empty
layers and do not consume DiffIDs. `DEMO-DIGEST-IS-NOT-DIFFID` has only a compressed
Digest equal in text to a base DiffID; it remains **unknown**.

An optional map is a plain JSON object from compressed Digest to uncompressed DiffID:

```sh
vulnwrench layers explain --report examples/layers/trivy.json \
  --base-config examples/layers/base.json --image-config examples/layers/image.json \
  --digest-map examples/layers/digest-map.json --output out.json
```

This yields `base=1, app=3, unknown=4, total=8`. Map entries are explicit **caller
assertions**, not independently verified content hashes. Both sides must be full
lowercase SHA-256 identifiers, and every mapped DiffID must be in the final image.
An unmapped Digest is never substituted for a DiffID, even if the strings match.
Conflicting supplied DiffID and mapped Digest produce unknown.

### Optional exact final-image digest-map pin

Supply a previously recorded local pin to detect edits to the original map bytes:

```sh
vulnwrench layers explain --report examples/layers/trivy.json \
  --base-config examples/layers/base.json --image-config examples/layers/image.json \
  --digest-map examples/layers/digest-map.json \
  --digest-map-sha256 sha256:f455f334f13da1f41040a1dd5544aea81a5121e535e099253929772af86922e9 \
  --output pinned-digest-map.json
```

Only pinned success adds `provenance.digestMapDigest` and
`provenance.digestMapPinAgreement="matched_local"`. The parsed `digestMap`, findings,
counts, gate, manifest bindings and other evidence stay unchanged. The pin must be
`sha256:` plus exactly 64 lowercase hex digits and requires `--digest-map`.
The tool bounds the original map to 32 MiB before hashing, then verifies the hash
before strict UTF-8 JSON object parsing. Duplicate keys and non-finite values reject.
A matching pin still requires valid SHA-256 map identifiers, final-image rootfs
membership, ordered manifest mappings, shared base/final consistency and all other
snapshot checks. `--base-digest-map` remains a separate descriptor assertion map.

Changing the mapped DiffID in this fixture from `sha256:cccc…` to `sha256:bbbb…`
(both valid image DiffIDs) or changing whitespace rejects the original pin with
exit 2 and preserves existing output. Malformed or orphan pins also fail. Omitting
the pin preserves existing API/CLI behavior and output.

Agreement proves only caller-local bytes. It does not verify compressed-to-uncompressed
layer content, scanner authenticity, completeness, publisher identity, signatures or
remediation. Replacing both bytes and pin is undetectable. Report, manifest, target-map
and per-snapshot digest-map pins remain independent. No network access is performed.

### Optional exact report pin

Supply `--report-sha256` to check the original Trivy report bytes before parsing:

```sh
vulnwrench layers explain --report examples/layers/trivy.json \
  --report-sha256 sha256:3392594be5b32c864bf44e2929ee41b79ec2a704d71fd28c18be03df1e4b171a \
  --base-config examples/layers/base.json --image-config examples/layers/image.json --output out.json
```

Only pinned success adds `provenance.reportDigest` and
`provenance.reportPinAgreement: "matched_local"`; `provenance.report` remains the
unchanged parsed report. Counts remain `base=1, app=2, unknown=5, total=8` without
a digest map. Findings, warnings, gate behavior and optional manifest bindings are
unchanged. The pin must be `sha256:` plus exactly 64 lowercase hex digits. The
report is bounded to 32 MiB before hashing, and its hash is checked before strict
UTF-8 JSON parsing. A matching hash still requires the supported report schema and
all existing evidence/config/map/prefix checks. At the CLI boundary, other files
are still read and bounded normally; unrelated read errors may be reported first.

Changing `synthetic:local` to `synthetic:other` in the report's `ArtifactName`, or
adding whitespace, fails with **exit 2**, no stdout and no replacement of an
existing output, even though findings and DiffIDs still agree. A malformed pin
also fails. `--report` remains required. Omitting the pin preserves existing output.

This establishes only agreement with caller-supplied local bytes. It does not
verify scanner identity, authenticity, completeness, signatures, layer content or
remediation. Replacing both report and pin is undetectable. Report pins and all
base/final manifest pins are independent; no input or pin is borrowed implicitly.

### Optional offline manifest/config verification

```sh
vulnwrench layers explain --report examples/layers/trivy.json \
  --base-config examples/layers/base.json --image-config examples/layers/image.json \
  --image-manifest examples/layers/image-manifest.json \
  --digest-map examples/layers/manifest-digest-map.json --output out.json
```

Expected output includes `counts: {"base": 1, "app": 3, "unknown": 4, "total": 8}`
and `ancestry.imageManifestBinding` with `status: "verified_local"`,
`orderedLayerCount: 3`, `layerContentVerified: false`, and the config's verified
SHA-256 digest. `ancestry.reportConfigBinding` remains independently
`diff_ids_consistent` for this report; a report without embedded sequences still
warns `report_config_binding_unverified`. The map-based proof remains
`explicit_digest_mapping`.

The supported subset follows the pinned **OCI Image Specification v1.1.1**
[manifest](https://github.com/opencontainers/image-spec/blob/v1.1.1/manifest.md),
[config](https://github.com/opencontainers/image-spec/blob/v1.1.1/config.md), and
[descriptor](https://github.com/opencontainers/image-spec/blob/v1.1.1/descriptor.md)
formats. It checks schema version 2, OCI manifest/config media types, full SHA-256
digests and nonnegative int64 descriptor sizes. Manifest `mediaType` may be omitted
as allowed by OCI. Layer media types are OCI tar, gzip or zstd (including their
nondistributable forms). This is a field-subset verifier, not a full OCI schema
validator; extension fields are retained, not interpreted.

Verification requires the **original final-config file bytes**: `config.size`
must equal their length and `config.digest` must equal their SHA-256 hash, before
JSON parsing. Reformatting the file changes its digest. Each manifest layer must
have an explicit digest-map entry, whose DiffID must equal the config DiffID at
the **same index**. Layer counts must match, and map entries outside the manifest
are rejected. No mapping is inferred by zipping arrays or matching digest text,
even for an uncompressed tar descriptor. Repeated layers retain the existing
ambiguity rules.

Failure examples: changing `amd64` to `arm64` in a copy of `image.json` produces
`config digest mismatch`; reversing `layers` produces `ordered layer mapping
mismatch`; omitting the map or any layer entry produces `missing layer mapping`.
All return **exit 2**, produce no explanation, and preserve an existing output.
The smaller `examples/layers/digest-map.json` is intentionally insufficient for this
mode; use `examples/layers/manifest-digest-map.json` for the complete ordered fixture.

`verified_local` establishes only agreement among supplied local inputs. The
manifest and explicit map are still caller assertions. No layer blobs are read,
hashed, decompressed, extracted or executed; descriptor `urls` and `data` are not
followed or consumed. Layer sizes are validated as integers but cannot be checked
against absent blobs. The fixture uses synthetic descriptors with no layer blobs.
Manifest signatures and report authenticity are not verified. Base-config bytes
can also be checked against the separate caller pin below, without a base manifest.
Coordinated edits to the manifest/config/map are not detectable without an unchanged
caller pin for the edited input. A config without its manifest or pin remains a
caller assertion.

### Optional exact final-image manifest pin

Supply `--image-manifest-sha256` with the original final-image manifest bytes:

```sh
vulnwrench layers explain --report examples/layers/trivy.json \
  --base-config examples/layers/base.json --image-config examples/layers/image.json \
  --image-manifest examples/layers/image-manifest.json \
  --image-manifest-sha256 sha256:75461d56b78427df1977e08d4ef2433edd6f2fdc6a7afd0c8270535346cfdd09 \
  --digest-map examples/layers/manifest-digest-map.json --output pinned-image.json
```

The pin requires `--image-manifest` and must be `sha256:` plus exactly 64 lowercase
hexadecimal digits. The tool bounds the original manifest to 32 MiB and verifies
its exact bytes **before parsing that manifest or its config**. A matching pin
still requires strict UTF-8 JSON, supported OCI fields, exact config-byte size/hash,
complete ordered mappings and the exact base prefix. Same-length annotation edits
and whitespace edits reject the original pin, even when config and map checks
still agree. Malformed/orphan pins, missing raw library bytes and mismatches raise
`InputError` / return **exit 2**, emit no explanation and preserve existing output.

Pinned success adds `manifestDigest` with the verified SHA-256 and
`manifestPinAgreement: "matched_local"` to `ancestry.imageManifestBinding`.
`provenance.imageManifest` retains the full parsed manifest; raw bytes are not
emitted. Counts, finding evidence and report/config agreement checks are retained.
Unpinned API/CLI behavior and output are unchanged.

Base and final-image pins are independent; either can be supplied alone or both
together. A matching pin cannot satisfy the other manifest's checks. Pins establish
local agreement with caller-supplied values, not signatures, publisher identity,
report authenticity or layer-content verification. Replacing both a manifest and
its pin cannot be detected. No network access is performed.

### Optional exact final-image config pin

Supply a previously recorded local pin with the original final-image config bytes,
with or without a final-image manifest:

```sh
vulnwrench layers explain --report examples/layers/upgrade-after.json \
  --base-config examples/layers/upgraded-base.json \
  --image-config examples/layers/upgraded-image.json \
  --image-config-sha256 sha256:1724dabbd6ea32f93860d851ce38fb53e27e1187ffea2db7719a77908ca23ec6 \
  --output pinned-image-config.json
```

Only pinned success adds `provenance.imageConfigDigest` and
`provenance.imageConfigPinAgreement="matched_local"`. The full parsed `imageConfig`,
findings, counts (`base=1, app=0, unknown=1, total=2`), gates and independent manifest
bindings stay unchanged. A pin alone creates no `imageManifestBinding` or
`verified_local` manifest status and does not verify layer content.

The pin must be `sha256:` plus exactly 64 lowercase hex digits. Original immutable
bytes are bounded to 32 MiB before hashing; the hash is checked before config parsing.
A matching pin retains strict UTF-8 object JSON, config/digest/history validation,
exact base prefix, report/config agreement and all map/comparison checks. An optional
final-image manifest still checks the size/hash of those original bytes before
config parsing. Its descriptor and ordered map validation remain mandatory.

Same-length architecture, history or whitespace edits reject the original pin even
when rootfs and embedded report sequences still agree. Malformed pins, wrong raw
library types and mismatches raise `InputError` / return **exit 2**, emit no
explanation and preserve existing output. Other input reads/checks may fail first.
Omitting the pin preserves existing API/CLI behavior and serialized output.

This proves only caller-local byte agreement, not content or publisher authenticity,
scanner authenticity or completeness, signatures or remediation. Replacing bytes and
pin together is undetectable. Base/final config, manifest, report, map and before/after
pins remain independent. No network access is performed.

### Optional exact base-config pin

Supply a previously recorded local pin with the original base-config bytes, with
or without a base manifest:

```sh
vulnwrench layers explain --report examples/layers/upgrade-after.json \
  --base-config examples/layers/upgraded-base.json \
  --base-config-sha256 sha256:01607a6dbaceefa9ecdd26eb382fedef4ee90d3a1e1f8c304cf43e07982fb52f \
  --image-config examples/layers/upgraded-image.json --output pinned-base-config.json
```

Only pinned success adds `provenance.baseConfigDigest` and
`provenance.baseConfigPinAgreement="matched_local"`. The full parsed `baseConfig`,
findings, counts (`base=1, app=0, unknown=1, total=2`), gates and independent
bindings stay unchanged. A pin alone creates no `baseManifestBinding` or
`verified_local` manifest status and does not verify layer content.

The pin must be `sha256:` plus exactly 64 lowercase hex digits. Original immutable
bytes are bounded to 32 MiB before hashing; the hash is checked before parsing the
base config. A matching hash still requires strict UTF-8 object JSON, valid config
fields/digests, exact base prefix and all report/map/comparison checks. When a base
manifest is supplied, its config size/hash checks still use these original bytes
before config parsing; a matching caller pin cannot waive those checks.

Same-length `amd64` to `arm64`, history metadata or whitespace edits reject the
original pin, even if the rootfs prefix still agrees. Malformed pins, wrong raw
library types and mismatches raise `InputError` / return **exit 2**, emit no
explanation and preserve existing output. Other input reads/checks may fail first.
Omitting the pin preserves existing API/CLI behavior and output.

This proves only agreement with caller-local bytes, not content or publisher
authenticity, scanner authenticity or completeness, signatures or remediation.
Replacing bytes and pin together is undetectable. Config, report, manifest, map
and before/after pins are independent. No network access is performed.

### Optional offline base-manifest verification

```sh
vulnwrench layers explain --report examples/layers/upgrade-after.json \
  --base-config examples/layers/upgraded-base.json \
  --image-config examples/layers/upgraded-image.json \
  --base-manifest examples/layers/upgraded-base-manifest.json \
  --base-digest-map examples/layers/upgraded-base-digest-map.json --output base-bound.json
```

Expected counts are `base=1, app=0, unknown=1, total=2`. Output adds
`ancestry.baseManifestBinding` with `status: "verified_local"`,
`orderedLayerCount: 2`, the base config's SHA-256 digest, and
`layerContentVerified: false`. `provenance.baseManifest` and `.baseDigestMap`
retain the supplied inputs. The same strict OCI field subset, exact config-byte
hash/size checks, descriptor validation and complete ordered mapping rules apply
**before accepting the base-prefix boundary**. A verified base still must be an
exact DiffID prefix of the final config. Base and final manifests can be supplied
independently or together; base verification does not verify the final config.

`--base-digest-map` is a separate descriptor-to-base-DiffID assertion map, used
only to verify the base manifest. It never supplies compressed-Digest evidence
for report findings. `--digest-map` remains the final-image finding map; neither
map is copied to the other, and compressed descriptors may differ between images.
If the same compressed digest appears in both maps, its asserted DiffID must agree;
contradictory assertions reject the operation with exit 2 even without a final manifest.
A base map without `--base-manifest` is rejected. An empty base with an empty
manifest layer array needs no map; every nonempty base descriptor needs an entry.

Changing `amd64` to `arm64` in the original base-config bytes leaves the prefix
unchanged but fails with `base_manifest: config digest mismatch`. Reversing the
two fixture layer descriptors fails with `base_manifest: ordered layer mapping
mismatch`. Missing/extra mappings, wrong config size and non-prefix ancestry also
fail. Each returns **exit 2**, emits no explanation and preserves existing output.
As with final-image verification, this establishes only local input agreement:
base manifests/maps are caller assertions, layer blobs and signatures are not
verified, and coordinated input edits cannot be detected. Finding/report uncertainty
and enabled gates retain their existing behavior.

### Optional exact base digest-map pin

Supply a previously recorded local pin with the original base-map bytes:

```sh
vulnwrench layers explain --report examples/layers/upgrade-after.json \
  --base-config examples/layers/upgraded-base.json \
  --image-config examples/layers/upgraded-image.json \
  --base-manifest examples/layers/upgraded-base-manifest.json \
  --base-digest-map examples/layers/upgraded-base-digest-map.json \
  --base-digest-map-sha256 sha256:2491147cc0100c3ca82fb0d33fd3796e53588914ec51a2a76749f96300f42816 \
  --output pinned-base-map.json
```

Only pinned success adds `provenance.baseDigestMapDigest` and
`provenance.baseDigestMapPinAgreement="matched_local"`. The parsed `baseDigestMap`,
manifest bindings, findings, counts (`base=1, app=0, unknown=1, total=2`) and gates
stay unchanged. The pin must be `sha256:` plus exactly 64 lowercase hex digits
and requires `--base-digest-map`; the map still requires `--base-manifest`.
Original bytes are bounded to 32 MiB before hashing; the hash is checked before
strict UTF-8 JSON object parsing. A matching pin retains strict digest syntax,
base-rootfs membership, complete ordered mappings, shared base/final consistency,
exact config/prefix checks and every report/comparison check.

Same-length digest-key edits and whitespace edits reject the original pin with
exit 2, no stdout and no replacement of existing output, even if a correspondingly
edited unpinned base manifest satisfies descriptor validation. Malformed and orphan
pins fail too. Other input reads/checks may report an unrelated error first.
Omitting the pin preserves existing API/CLI output. Base maps remain separate
from final-image finding maps and never supply finding evidence.

Agreement proves only caller-local bytes, not layer content, scanner authenticity
or completeness, publisher identity, signatures or remediation. Replacing bytes
and pin together is undetectable. Every report, manifest, map and per-snapshot pin
is independent. No network access is performed.

### Optional exact base-manifest pin

To detect changes to the manifest itself, supply a previously recorded local pin
with the original manifest bytes:

```sh
vulnwrench layers explain --report examples/layers/upgrade-after.json \
  --base-config examples/layers/upgraded-base.json \
  --image-config examples/layers/upgraded-image.json \
  --base-manifest examples/layers/upgraded-base-manifest.json \
  --base-manifest-sha256 sha256:b7f68803d1d89fd2982d03cf9b9625171ad35c272a67824c28845cce9f678baa \
  --base-digest-map examples/layers/upgraded-base-digest-map.json --output pinned-base.json
```

The pin must be `sha256:` followed by exactly 64 lowercase hexadecimal digits.
It requires `--base-manifest`. The tool bounds the original manifest to 32 MiB,
hashes its exact bytes **before parsing that manifest**, and rejects a mismatch.
A matching hash still requires strict UTF-8 JSON and all existing OCI, exact
config-byte, complete ordered-map and base-prefix checks. Same-length annotation
changes and whitespace changes reject even when the config and mapping still agree.
Malformed or orphan pins, missing raw library bytes, and mismatches raise
`InputError` / return **exit 2**, emit no explanation and preserve existing output.

Pinned success adds these fields to `ancestry.baseManifestBinding`:

```json
{"manifestDigest": "sha256:b7f68803d1d89fd2982d03cf9b9625171ad35c272a67824c28845cce9f678baa",
 "manifestPinAgreement": "matched_local"}
```

The parsed manifest stays in `provenance.baseManifest`; raw bytes are not emitted.
Unpinned calls retain their existing output and verification behavior. The pin
establishes agreement with a caller-provided local value, not signatures, publisher
identity, report authenticity or layer-content verification. Replacing both the
manifest and the pin cannot be detected. No network access is performed.

Explanation is the default; enable a gate explicitly:

```sh
vulnwrench layers explain --report examples/layers/trivy.json \
  --base-config examples/layers/base.json --image-config examples/layers/image.json \
  --gate app --output out.json
# exit 1: two app and five unknown findings block; all eight remain in out.json
```

| Gate | Behavior |
| --- | --- |
| `none` (default) | Explain only; successful processing returns 0. |
| `app` | Every app or unknown finding blocks. Base findings stay in output. |
| `all` | Every finding blocks, including base. |

No severity, status, VEX, or suppression filtering is applied: **every input
vulnerability entry counts**, including duplicate IDs and separate targets. An
empty vulnerability report passes enabled gates. No gate can make unknown evidence
pass while app evidence fails.

Exit codes: **0** processed / passing gate; **1** enabled gate failed; **2** invalid
input, unsupported schema, invalid ancestry, or I/O failure. Gate failure still
writes the full explanation. `--output -` (default) writes deterministic JSON to
stdout; `--output FILE` uses an atomic replacement in the same directory. Parent
directories must already exist. Input paths and their symlink/hardlink aliases
cannot be replaced. Invalid input leaves an existing output untouched.

## Compare a base upgrade

Each side is attributed independently against its own report, base and final config.
The local synthetic example replaces the old base prefix `[A]` with `[D, B]` in a
new image `[D, B, C]` (letters stand for full SHA-256 DiffIDs):

```sh
vulnwrench layers compare \
  --before-report examples/layers/upgrade-before.json \
  --before-base-config examples/layers/base.json --before-image-config examples/layers/image.json \
  --after-report examples/layers/upgrade-after.json \
  --after-base-config examples/layers/upgraded-base.json \
  --after-image-config examples/layers/upgraded-image.json --output upgrade.json
```

Expected output is committed in [examples/layers/upgrade-expected.json](../examples/layers/upgrade-expected.json):

```json
{"attribution_changed": 1, "unknown": 1, "unchanged": 0,
 "before_only": 0, "after_only": 0, "total": 2}
```

`basePrefixChange` contains `changed: true` and both full prefix arrays.
`DEMO-MOVED` remains observed in both reports; its row says `attribution_changed`,
`beforeOrigin: "app"`, `afterOrigin: "base"`. `DEMO-LOST-EVIDENCE` gets a separate
`unknown` row with origins `app` and `unknown`; its after proof still explains
`missing_layer_evidence`. Any unknown origin takes precedence over an apparent
attribution change. `unchanged` means only the origin is unchanged; proof, history,
severity or other supplied fields may differ and remain visible in the snapshots.

Every row's `before` and `after` arrays contain local JSON Pointer references such
as `#/snapshots/before/groups/app/0`. They resolve to complete attribution records
in the embedded, independent `snapshots.before` and `snapshots.after` explanations.
Both snapshots retain all finding occurrences, warnings, provenance, and optional
manifest binding evidence. Nothing is filtered out. Counts measure comparison
**rows**, not finding occurrences: an ambiguous row can reference multiple findings.

Matching uses the exact tuple of result `Target`, `Class`, `Type` and finding
`VulnerabilityID`, `PkgName`, `InstalledVersion`, `PkgPath`, `PkgID`. Optional fields
must be strings or null; missing and null are treated alike. Layer identifiers are
excluded so a finding can move layers. Package names alone never establish a match.
A duplicate tuple in either snapshot produces an `unknown` row with reason
`ambiguous_finding_identity` and all references; entries are never paired by order.
Changed versions, targets (including image tags), paths or package IDs produce
`before_only`/`after_only` rows by default. Target renames require the explicit map
below; no rename is inferred and no cross-version matching is attempted.

### Explicit target correspondence

When an image tag or result target changes, optionally supply `--target-map FILE`:
a JSON object of **before Target → after Target** strings. For example,
[examples/layers/target-map.json](../examples/layers/target-map.json) contains:

```json
{"synthetic-upgrade": "synthetic-upgrade:v2"}
```

```sh
vulnwrench layers compare \
  --before-report examples/layers/upgrade-before.json \
  --before-base-config examples/layers/base.json --before-image-config examples/layers/image.json \
  --after-report examples/layers/upgrade-renamed-after.json \
  --after-base-config examples/layers/upgraded-base.json \
  --after-image-config examples/layers/upgraded-image.json \
  --target-map examples/layers/target-map.json --output renamed-upgrade.json
```

This produces the same two comparison rows as the upgrade example: one
`attribution_changed` and one `unknown`. Without the map, the changed target yields
two `before_only` and two `after_only` rows. The map substitutes **only Target** for
matching; Class, Type and all finding identity fields remain exact. Layer attribution
still runs independently, missing evidence stays unknown, and duplicate identities
remain ambiguous with every occurrence retained.

Mappings are caller assertions, not evidence that reports cover the same image.
Keys and values must be nonempty strings naming targets actually present in the
corresponding report's `Results`, even if a result has no vulnerabilities. Matching
uses exact strings, without trimming or tag parsing. The map may be partial: unlisted
before targets still match identical after targets. The **combined explicit and
implicit relation must be one-to-one**. Thus, with before targets `a,b` and after
targets `b,c`, `{"a":"b"}` fails because the implicit `b→b` collides; supply
`{"a":"b","b":"c"}` to establish both correspondences. Duplicate destinations,
unknown endpoints, malformed values and duplicate JSON keys fail with **exit 2**,
no stdout and no replacement of an existing output. Explicit swaps (`a→b,b→a`) and
self mappings (`a→a`) are valid. Unclaimed after targets stay `after_only`; mapped
names are not followed transitively. `{}` infers no renames.

Map-enabled output retains the supplied object as `targetMap`, adds warning
`target_map_is_caller_assertion`, and gives each row `beforeTarget` and `afterTarget`
(null when that side is absent). `identity.Target` remains the original before
target, or the original after target for an after-only row. Original report targets,
finding source targets, configs, proofs, warnings and provenance remain untouched
in the snapshots; every row's references still resolve there. Omitting the option
preserves the existing output format and exact matching behavior. The map input
uses the same strict parsing, 32 MiB limit and output-alias protections as other inputs.

To pin the exact original map bytes, add this option to the command above:

```sh
  --target-map-sha256 sha256:7d2ccc8d82f89b2b2d568abb5deb71295458623704a79beb0c998fb6394ca2e9
```

The pin must be `sha256:` plus exactly 64 lowercase hex digits and requires
`--target-map`. The map is bounded to 32 MiB before hashing; hash agreement is
checked before strict UTF-8 JSON parsing. Matching pins still require valid
endpoints, nonempty strings, the combined explicit/implicit partial bijection,
and every independent snapshot/identity check. Other CLI input files are read and
bounded normally first; unrelated read errors may take precedence.

Only pinned success adds top-level `targetMapDigest` and
`targetMapPinAgreement: "matched_local"`. The parsed `targetMap`, `targetCoverage`,
rows, counts, warnings and full snapshots are unchanged. Same-length correspondence
or whitespace edits and added whitespace fail with **exit 2**, no stdout and no
replacement of an existing output, even when the edited map is a valid bijection.
Malformed or orphan pins also fail. Omitting the pin preserves existing output.

This proves only caller-local byte agreement, not actual target correspondence,
scanner identity/authenticity/completeness, signatures, publisher identity or
remediation. Replacing both the map and its pin is undetectable. Map, report and
base/final manifest pins remain independent, including before/after snapshot pins.
No network access or scanner execution is involved.

Map-enabled output also includes `targetCoverage`, even for targets with **zero
vulnerability findings**. It contains one entry for each distinct before target,
in first-appearance report order, followed by unclaimed distinct after targets in
their report order. Map key order does not affect this list. Each entry has:

| Field | Contract |
| --- | --- |
| `status` | `paired` for an explicit or implicit exact-name correspondence; otherwise `before_only` or `after_only`. |
| `match` | `explicit_map` for caller-mapped pairs (including self mappings), `exact_name` for unlisted identical names, or null for unmatched targets. |
| `beforeTarget`, `afterTarget` | Original target strings; null on an absent side. |
| `before`, `after` | Arrays of local JSON Pointers into `#/snapshots/{side}/provenance/report/Results/{index}`; empty on an absent side. |

All results sharing a Target retain their references in original per-side order,
including results with omitted, null or empty `Vulnerabilities`. Different Class/Type
values and unequal numbers of repeated results do not create positional pairs:
coverage describes **target names**, while finding matching still uses all identity
fields above. The list establishes neither scanner completeness nor remediation,
and a zero-finding result does not establish that a target is vulnerability-free.
It adds no finding rows and changes no counts or snapshots. An empty map `{}`
enables coverage with exact-name matches only; missing/null/empty `Results` supplies
no targets. Omitting the map omits `targetCoverage` and preserves byte-identical output.

For an example with no vulnerability observations, run the installed CLI:

```sh
vulnwrench layers compare \
  --before-report examples/layers/target-coverage-before.json \
  --before-base-config examples/layers/base.json --before-image-config examples/layers/image.json \
  --after-report examples/layers/target-coverage-after.json \
  --after-base-config examples/layers/upgraded-base.json \
  --after-image-config examples/layers/upgraded-image.json \
  --target-map examples/layers/target-map.json --output target-coverage.json
```

`rows` is empty and all finding counts are zero. `targetCoverage` has four entries:
`synthetic-upgrade → synthetic-upgrade:v2` (`explicit_map`),
`stable/packages~1 → stable/packages~1` (`exact_name`), `old-only` (`before_only`),
and `new-only` (`after_only`). The first entry retains both before Results references
(`…/Results/0`, `…/Results/3`) and its one after reference (`…/Results/2`), all
resolving to the unchanged original report records in the snapshots.

The comparison **never establishes remediation**, even for a finding absent from
the after report: scanner coverage, filtering and package identity can change.
It does not infer a causal relationship from a changed base prefix. `compare` has
no gate: successful processing exits 0 even with unknown rows. Use `explain --gate`
separately for gating. Invalid ancestry, malformed input or invalid identity fields
on either side exit 2 without replacing an existing output. For example, passing
`examples/layers/non-prefix-base.json` as `--after-base-config` rejects the comparison.
All existing strict parsing, 32 MiB input limits and input-alias protections apply.

Each side optionally accepts `--before-digest-map` / `--after-digest-map` and
`--before-image-manifest` / `--after-image-manifest`, plus
`--before-base-manifest` / `--after-base-manifest` and
`--before-base-digest-map` / `--after-base-digest-map`, using the same verification
rules as `explain`. Maps and manifests are never shared implicitly between sides.
Each snapshot retains its own optional base binding and provenance.
`--before-base-manifest-sha256` / `--after-base-manifest-sha256` independently pin
the corresponding manifest's exact bytes. Either side may omit its pin; no pin or
manifest bytes are borrowed from the other side.
`--before-image-manifest-sha256` / `--after-image-manifest-sha256` independently pin
the final-image manifests by the same rules. All four base/final, before/after pins
and their corresponding manifests and maps remain independent.
`--before-report-sha256` / `--after-report-sha256` independently pin the original
report bytes for each snapshot by the report-pin rules above. Either side may be
unpinned; pin agreement does not bypass identity or target-map validation, and
report/config mismatches still leave findings unknown.

`--before-digest-map-sha256` / `--after-digest-map-sha256` independently pin the
original final-image map bytes for each snapshot by the digest-map rules above.
Either side may remain unpinned; no map or pin is borrowed from the other snapshot.

`--before-base-config-sha256` / `--after-base-config-sha256` independently pin
the original base-config bytes, including without a base manifest. Either side
may remain unpinned. Only the pinned snapshot gains config pin provenance; finding
rows, target correspondence and manifest bindings keep their existing rules.

`--before-image-config-sha256` / `--after-image-config-sha256` independently pin
original final-image config bytes, including without final-image manifests. Either
side may remain unpinned; only the pinned snapshot gains the two provenance fields.
Rows, counts, target correspondence and manifest bindings keep their existing rules.

## Supported inputs and field mapping

Only **local UTF-8 JSON documents**, including the optional OCI base and final-image
manifests above; not JSONL, SARIF, Docker archives, OCI indexes, Docker schema-2 manifests,
Docker inspect arrays, SBOMs, or scanner command output streams.
Maximum **32 MiB per CLI input**. Duplicate object keys, invalid JSON/UTF-8 and
non-finite numbers are rejected, including literal `NaN`/`Infinity` and numeric
exponent overflow such as `1e9999` or `-1e9999` anywhere in nested objects/arrays.
The shared raw parser raises sanitized `InputError`; the CLI exits 2 without
replacing existing output. This also applies after a matching byte pin and in
manifest-enabled raw configs. Size-before-hash, pin hash-before-parse, and optional
manifest config size/hash-before-parse checks retain their order. Finite exponents,
integers and floats keep their existing Python values (including signed zero and
float underflow); numbers are never clamped, stringified or dropped. Parsed library
dictionaries retain their existing caller-owned JSON-compatible input contract.
Raw JSON has a maximum of **128 object/array nesting levels**. The root object is
level 1; every nested object or array adds one level, including empty containers.
Scalars and braces/brackets inside strings add no depth. Valid object documents
at level 128 retain all metadata through provenance copying and serialization;
level 129 rejects with sanitized `InputError` (`JSON nesting exceeds 128 levels`),
or CLI exit 2 with no stdout and existing output preserved. An iterative scan
enforces the bound before JSON decoding or provenance copying, after byte-size,
applicable pin/manifest config hash checks and UTF-8 decoding. A matching pin
cannot bypass this limit. This applies to every raw report/config/manifest/map,
including both comparison snapshots and configs with optional manifests. Map
schemas still require their existing string values; nesting checks do not allow
extension fields in maps. Parsed library dictionaries keep their existing
caller-owned JSON-compatible contract and are not subject to this raw limit.
The tool neither changes Python's recursion limit nor discards deep metadata.
Parsed library report/config/manifest dictionaries are checked for object/array
cycles before any finding or provenance copying. A cycle raises sanitized
`InputError` with `cyclic object/array metadata`; the message identifies only the
document kind, never metadata keys, values or paths. This applies to `explain`
and independently to both `compare` snapshots, including nested extension fields
and optional base/final-image manifests. Inputs remain unchanged on rejection.
The iterative check distinguishes cycles from shared acyclic objects/arrays;
shared values remain accepted, and all acyclic JSON-compatible metadata is
preserved in separate copied provenance. It adds no parsed-input depth limit and
does not change raw byte-size, pin/hash, strict parsing or 128-level contracts.
Raw JSON cannot encode cycles. Other non-JSON Python values remain outside the
parsed-input contract; this check does not validate arbitrary Python objects.
The same iterative walk rejects parsed float `NaN`, positive infinity and negative
infinity at any object/array value position with sanitized `InputError`
(`non-finite numeric metadata`). This covers extension fields in every report,
config and optional manifest, independently in `explain` and both `compare`
snapshots, before any finding or provenance copying. Diagnostics contain only
the document kind, never caller metadata keys, values or paths. Finite floats,
including signed zero and subnormals, integers, booleans, nulls, strings and
shared acyclic containers retain their complete values and serialization.
Rejection leaves caller graphs unchanged; it adds no parsed depth limit and
does not change recursion limits or raw input size/hash/parse ordering.
Only full lowercase
`sha256:[0-9a-f]{64}` digests are supported; abbreviated documentation digests and
other algorithms are rejected with exit 2.

| Input field | Meaning / output |
| --- | --- |
| Trivy `SchemaVersion: 2`, `ArtifactType: "container_image"` | Required; other schemas and non-image reports fail. |
| `Results[]` and `Target` | Target required for each result. Results omitted/null/empty means no results. |
| `Results[].Vulnerabilities[]` | Every entry needs string `VulnerabilityID` and `PkgName`. Omitted/null/empty array means no vulnerabilities in that result. |
| Finding `Layer.DiffID` | Exact uncompressed layer evidence. Null/absent Layer or absent/empty-string identifiers mean missing evidence. Present malformed identifiers fail. |
| Finding `Layer.Digest` | Compressed identifier; usable only through `--digest-map`. |
| OCI config `rootfs.type: "layers"`, `rootfs.diff_ids[]` | Required for base and final configs; order defines the ancestry boundary. Empty base is allowed. |
| OCI config `history[]` | Skip entries where boolean `empty_layer` is true; align the remaining entries with DiffIDs and expose `created_by`. |
| Optional OCI manifest `config` / `layers[]` | Verify the corresponding base/final config bytes and complete explicit layer mappings in order; record only a verified local binding. |
| Optional report `Metadata.DiffIDs` / `Metadata.ImageConfig.rootfs` | Compare each provided layer sequence with the supplied final config. Any mismatch makes **all findings unknown**, with a warning. |

The adapter targets this documented field subset rather than claiming compatibility
with every Trivy release. `Class`, `Type`, versions, severity, package IDs, data
sources, and other fields are preserved as supplied; they do not change attribution.
Nonempty `Secrets`, `Misconfigurations`, `Licenses`, or `CustomResources` finding
families are rejected, so this vulnerability tool cannot silently discard those
findings. Other extension fields remain in provenance; an unfamiliar layer evidence
field contributes no proof and the finding remains unknown without usable DiffID.
Grype and Syft inputs are **not supported** by this MVP.

Each output group (`groups.base`, `.app`, `.unknown`) contains the unchanged
`finding`, `source.resultIndex`/`findingIndex`/`target`, origin, proof, reason,
DiffID, compressed Digest, all matching layer indices, history, and warning codes.
`provenance` retains the entire supplied report, both parsed configs, the maps and
optional manifests, including unknown extension fields. Exact config bytes are hashed
but not included in output. `counts.total` always equals the number of vulnerability
entries successfully parsed. Inputs to the library are not mutated.

## Evidence and uncertainty rules

1. Base DiffIDs must be an **exact ordered prefix** of final DiffIDs. Non-prefix,
   reordered, or longer base ancestry is an error, not a guessed classification.
2. With exact DiffID evidence, an occurrence exclusively before the prefix boundary
   is base; exclusively after it is app. A DiffID appearing on both sides is unknown.
   Repeated DiffIDs within one side retain every matching history location and warn.
3. Missing evidence, unmatched DiffID, unmapped compressed Digest, conflicting map
   evidence, or report/config mismatch stays unknown with an explicit reason.
4. Missing history warns. A nonempty-history count mismatch disables **all command
   alignment for that config**, retaining null command/index with a warning. It does
   not erase valid exact DiffID evidence. Base/final command disagreements also warn;
   history text is explanatory and never proof of ownership.
5. Without report-embedded layer sequences, output warns
   `report_config_binding_unverified`. Matching sequences mean only
   `diff_ids_consistent`, **not cryptographic authenticity**. The operator must supply
   authorized, corresponding report/configs and trust any digest map. This tool does
   not verify layer blob bytes, signatures, platform, scanner completeness, or report
   authenticity. Optional manifest modes check the corresponding base/final config
   digest and ordered map consistency only. Edited or previously filtered reports cannot be repaired.

This is **finding introduction-layer attribution**, not current filesystem ownership,
a judgment about exploitability, or proof that a base vulnerability is safe to ignore.
There is no inference from Dockerfile text or package names. It does not merge multiple
images/platforms. Mismatched inputs must be corrected by the operator.

Diagnostics intentionally omit input values, file paths and underlying exception
messages. Successful JSON intentionally preserves supplied report/config content,
which may include private paths, environment variables or history commands: store
and share it under the same controls as the original inputs.

## Library

```python
import json
from pathlib import Path
from vulnwrench.layers import InputError, explain

load = lambda path: json.loads(Path(path).read_text())
result = explain(load("examples/layers/trivy.json"), load("examples/layers/base.json"),
                 load("examples/layers/image.json"), gate="app")
assert result["gate"]["status"] == "failed"
assert result["counts"]["total"] == 8
```

`explain(report, base_config, image_config, *, digest_map=None, gate="none",
image_manifest=None, base_manifest=None, base_digest_map=None, base_manifest_sha256=None,
image_manifest_sha256=None, report_sha256=None, digest_map_sha256=None,
base_digest_map_sha256=None, base_config_sha256=None, image_config_sha256=None)`
accepts JSON-compatible dictionaries and returns a separate JSON-compatible dict.
With `image_manifest` supplied, `image_config` must instead be exact `bytes` (at most
32 MiB), for example `Path("examples/layers/image.json").read_bytes()`. The library checks
the hash/size, parses those bytes strictly, and verifies the complete ordered map;
it rejects a parsed config dict in this mode because reserialization changes hashes.
With `base_manifest`, `base_config` must likewise be exact `bytes`; the separate
`base_digest_map` verifies base descriptor order before the prefix check. Base maps
never classify report findings and require a base manifest. Either manifest may be
omitted independently. Raw config bytes require the corresponding manifest or
config pin (`base_config_sha256` / `image_config_sha256`).

With `image_config_sha256`, pass original immutable `bytes` as `image_config`,
including without a final-image manifest. The size-before-hash and hash-before-parse
contract is the same as for base config pins below. Dictionaries, strings, bytearray
and memoryview are rejected in pinned mode. Optional final-image manifest config
size/hash checks still precede config parsing. Only pinned success adds
`imageConfigDigest` and `imageConfigPinAgreement="matched_local"` in provenance;
a pin alone creates no manifest binding. `None` disables the pin and retains the
existing dictionary contract, or raw bytes with a final-image manifest.

With `base_config_sha256`, pass the original immutable `bytes` as `base_config`
(at most 32 MiB), even without a base manifest. Dictionaries, strings, bytearray
and memoryview cannot substitute for those bytes. Size is checked before hashing
and the hash before strict config parsing. Any optional base manifest still checks
the size/hash of the original bytes before parsing. Only pinned success adds
`baseConfigDigest` and `baseConfigPinAgreement` to provenance; the parsed config
and all other evidence remain unchanged. `None` disables this pin and retains the
existing dict contract, or raw bytes when a base manifest is supplied. For example:

```python
result = explain(report, Path("examples/layers/upgraded-base.json").read_bytes(),
                 json.loads(Path("examples/layers/upgraded-image.json").read_text()),
                 base_config_sha256="sha256:01607a6dbaceefa9ecdd26eb382fedef4ee90d3a1e1f8c304cf43e07982fb52f")
```

With `base_manifest_sha256` or `image_manifest_sha256` supplied, pass the original
corresponding manifest as `bytes` in `base_manifest` or `image_manifest` (also at
most 32 MiB), rather than a parsed dict. The pin is checked before strict parsing; a dict, string or bytearray cannot substitute for
the original bytes. `None` disables pinning and retains the existing parsed-dict
manifest contract; unpinned manifest bytes are rejected. For the final-image CLI
example above, the equivalent library call is:

```python
result = explain(load("examples/layers/trivy.json"), load("examples/layers/base.json"),
                 Path("examples/layers/image.json").read_bytes(),
                 image_manifest=Path("examples/layers/image-manifest.json").read_bytes(),
                 image_manifest_sha256="sha256:75461d56b78427df1977e08d4ef2433edd6f2fdc6a7afd0c8270535346cfdd09",
                 digest_map=load("examples/layers/manifest-digest-map.json"))
```

For a base-manifest pin:

```python
result = explain(load("examples/layers/upgrade-after.json"),
                 Path("examples/layers/upgraded-base.json").read_bytes(),
                 load("examples/layers/upgraded-image.json"),
                 base_manifest=Path("examples/layers/upgraded-base-manifest.json").read_bytes(),
                 base_manifest_sha256="sha256:b7f68803d1d89fd2982d03cf9b9625171ad35c272a67824c28845cce9f678baa",
                 base_digest_map=load("examples/layers/upgraded-base-digest-map.json"))
```

With `report_sha256`, `report` must be the original immutable `bytes` (at most
32 MiB), for example:

```python
result = explain(Path("examples/layers/trivy.json").read_bytes(), load("examples/layers/base.json"),
                 load("examples/layers/image.json"),
                 report_sha256="sha256:3392594be5b32c864bf44e2929ee41b79ec2a704d71fd28c18be03df1e4b171a")
```

The pin is checked before report parsing or config/manifest validation. A pin
without a report, a malformed pin, or a dict/string/bytearray in place of original
bytes raises `InputError`. `None` disables pinning and retains the existing report
dict contract; unpinned report bytes remain invalid. The parsed report is retained
in provenance, with `reportDigest` and `reportPinAgreement` only on pinned success.

With `digest_map_sha256`, pass original immutable `bytes` as `digest_map` (at most
32 MiB). Pin syntax, presence, byte type, size and hash are checked before parsing
that map. A dict, string, `bytearray` or `memoryview` cannot substitute for the bytes.
Only pinned success adds `digestMapDigest` and `digestMapPinAgreement` in provenance,
retaining the parsed map and every existing evidence check. `None` preserves the
parsed-dict/absent-map contract; unpinned raw map bytes remain unsupported. For example:

```python
result = explain(load("examples/layers/trivy.json"), load("examples/layers/base.json"),
                 load("examples/layers/image.json"),
                 digest_map=Path("examples/layers/digest-map.json").read_bytes(),
                 digest_map_sha256="sha256:f455f334f13da1f41040a1dd5544aea81a5121e535e099253929772af86922e9")
```

With `base_digest_map_sha256`, pass original immutable `bytes` as `base_digest_map`
(at most 32 MiB), using the same syntax/presence/type/size/hash-before-parse contract.
Parsed dictionaries, strings, `bytearray` and `memoryview` cannot substitute for
pinned bytes; unpinned base-map bytes remain unsupported. Only pinned success adds
`baseDigestMapDigest` and `baseDigestMapPinAgreement` to snapshot provenance.
The parsed map and all validation remain, including the base-manifest requirement.
For the CLI example above:

```python
result = explain(load("examples/layers/upgrade-after.json"),
                 Path("examples/layers/upgraded-base.json").read_bytes(),
                 load("examples/layers/upgraded-image.json"),
                 base_manifest=load("examples/layers/upgraded-base-manifest.json"),
                 base_digest_map=Path("examples/layers/upgraded-base-digest-map.json").read_bytes(),
                 base_digest_map_sha256="sha256:2491147cc0100c3ca82fb0d33fd3796e53588914ec51a2a76749f96300f42816")
```

It raises `InputError` for invalid/unsupported input. It has no filesystem, network,
process execution, or logging side effects. CLI JSON parsing and byte limits are a
separate boundary for other inputs; library callers are responsible for parsing
their unpinned report and other parsed config/manifest/map JSON strictly.

`compare(before_report, before_base_config, before_image_config, after_report,
after_base_config, after_image_config, *, before_digest_map=None,
after_digest_map=None, before_image_manifest=None, after_image_manifest=None,
before_base_manifest=None, after_base_manifest=None, before_base_digest_map=None,
after_base_digest_map=None, before_base_manifest_sha256=None,
after_base_manifest_sha256=None, before_image_manifest_sha256=None,
after_image_manifest_sha256=None, before_report_sha256=None,
after_report_sha256=None, before_digest_map_sha256=None, after_digest_map_sha256=None,
before_base_digest_map_sha256=None, after_base_digest_map_sha256=None,
before_base_config_sha256=None, after_base_config_sha256=None,
before_image_config_sha256=None, after_image_config_sha256=None,
target_map=None, target_map_sha256=None)`
is exported alongside `explain`. It invokes `explain` separately for both snapshots;
each manifest-enabled base/final config must be exact bytes on the corresponding side.
Each optional base/final-image manifest pin likewise requires that side's exact
corresponding manifest bytes; omitted pins or inputs are never borrowed.
`before_report_sha256` / `after_report_sha256` likewise require the corresponding
original report bytes and add local pin agreement only to that snapshot provenance.
`before_digest_map_sha256` / `after_digest_map_sha256` independently require that
side's original map bytes and add pin agreement only to its snapshot provenance.
`before_base_digest_map_sha256` / `after_base_digest_map_sha256` independently
require that side's original base-map bytes. CLI options are
`--before-base-digest-map-sha256` / `--after-base-digest-map-sha256`. Neither side
borrows maps, pins or manifests from the other.
`before_base_config_sha256` / `after_base_config_sha256` independently require
that side's original immutable base-config bytes, including without a manifest.
Matching pins add config pin provenance only to their own snapshot.
`before_image_config_sha256` / `after_image_config_sha256` independently require
that side's original immutable final-image config bytes, including without a
final-image manifest; only that snapshot gains final-config pin provenance.
It returns the same JSON document as the CLI, does not mutate caller inputs, and
raises `InputError` if either side, a comparison identity or target correspondence
is invalid. `target_map` is a parsed before-to-after JSON object with the same
validation and preservation contract as `--target-map`; `None` disables it.
With `target_map_sha256`, supply original immutable `bytes` as `target_map`
(at most 32 MiB). Parsed dictionaries, strings, `bytearray` and `memoryview`
are rejected in pinned mode; unpinned raw bytes remain unsupported. Pin syntax,
presence, byte type, size and hash are checked before map parsing and snapshot
processing. Strict parsing and all existing checks follow a matching hash.
Only pinned success adds `targetMapDigest` and `targetMapPinAgreement` to the
comparison output, preserving its parsed map and all evidence.


## Verification and measured comparison

```sh
python -m pytest tests/layers
python scripts/layers/verify_examples.py
python scripts/layers/compare_naive.py
```

The tests exercise real CLI subprocesses and failure exits, empty-layer history,
package-name collisions, repeated DiffIDs, bad ancestry, report/config mismatch,
unknown retention, inert command text, safe diagnostics and deterministic output.
Manifest and pin regressions cover exact bytes, same-length tampering, descriptor order,
missing mappings, hash-before-parse, strict parsing, bounded reads, independent
base/final/comparison pins, and output preservation on failure. Numeric-boundary,
nesting (exact 128/129 levels), parsed-cycle and parsed-number regressions cover every
input kind and both comparison sides without changing the interpreter's recursion limit.
`verify_examples.py` checks eight real CLI examples, including the committed default
output, both optional manifest bindings, and base-upgrade comparisons with exact targets
and an explicit renamed target.

`compare_naive.py` evaluates the eight independently labeled synthetic cases in
`examples/layers/comparison.json` using a name-only base package subtraction baseline and
the exact-evidence classifier:

| Method | Attribution errors / 8 | False base attributions | Unknown retained |
| --- | --- | --- | --- |
| Name-only base subtraction | 6 | 5 | 0 |
| Exact evidence | 0 | 0 | 5 |

Full measured rows are in [examples/layers/comparison-result.json](../examples/layers/comparison-result.json).
Unknown labels mean **insufficient evidence to assert origin**, not knowledge of the
package's true physical origin. This small adversarial fixture measures correctness,
not production accuracy or throughput; no performance speedup is claimed.

## Upstream relationship and scope

[Trivy](https://github.com/aquasecurity/trivy),
[Grype](https://github.com/anchore/grype), and [Syft](https://github.com/anchore/syft)
already provide layer/package evidence. This command consumes the supported Trivy JSON
subset and local OCI configs to explain an ancestry boundary without hiding evidence.
It does not replace their scanners or assert a novel scanning algorithm. The useful
difference from name-only base package subtraction is that an application upgrade of
a base-named package remains an application finding, while unproven origin stays
visible and blocks an enabled app gate.

Own implementation: MIT, see [LICENSE](../LICENSE). Upstream relationships and format
references are documented in [THIRD_PARTY.md](../THIRD_PARTY.md).
