# Mapping lint

Components: **4**; mapped: **1**; ambiguous: **1**; unmapped or missing PURL: **2**.

Mapping entries: **4**; ambiguous PURLs: **1**; unused PURLs: **1**; duplicate PURLs: **0**; shared repository identifiers: **1**.

Mapping status describes coverage, not a security decision.

## Components

| Name | PURL | Repository | Mapping status | File | JSON Pointer |
| --- | --- | --- | --- | --- | --- |
| demo | pkg:npm/demo@1.0 | — | ambiguous | bom.json | /components/0 |
| helper | pkg:npm/helper@1.0 | https://github.com/example/demo | mapped | bom.json | /components/1 |
| demo | pkg:npm/demo@3.0 | — | unmapped | bom.json | /components/2 |
| local-file | — | — | missing&#95;purl | bom.json | /components/3 |

## Issues

| Issue | Message | PURL | Repository | File | JSON Pointer | Occurrence |
| --- | --- | --- | --- | --- | --- | --- |
| ambiguous&#95;mapping | One exact PURL assigns different canonical repositories; remove the conflicting entries before joining. | pkg:npm/demo@1.0 | https://github.com/example/demo, https://github.com/example/other | repos.json | /pkg:npm&#126;1demo@1.0 | 1 |
| ambiguous&#95;mapping | One exact PURL assigns different canonical repositories; remove the conflicting entries before joining. | pkg:npm/demo@1.0 | https://github.com/example/demo, https://github.com/example/other | repos.json | /pkg:npm&#126;1demo@1.0 | 2 |
| ambiguous&#95;mapping | One exact PURL assigns different canonical repositories; remove the conflicting entries before joining. | pkg:npm/demo@1.0 | https://github.com/example/demo, https://github.com/example/other | bom.json | /components/0 | — |
| unused&#95;mapping | No component uses this exact PURL; check its version, qualifiers, case and escaping or remove the entry. | pkg:npm/demo@2.0 | — | repos.json | /pkg:npm&#126;1demo@2.0 | 1 |
| duplicate&#95;repository&#95;identifier | Multiple mapping entries normalize to this repository; shared repositories are valid, but verify the assignments are intentional. | — | https://github.com/example/demo | repos.json | /pkg:npm&#126;1demo@1.0 | 1 |
| duplicate&#95;repository&#95;identifier | Multiple mapping entries normalize to this repository; shared repositories are valid, but verify the assignments are intentional. | — | https://github.com/example/demo | repos.json | /pkg:npm&#126;1helper@1.0 | 1 |
| duplicate&#95;repository&#95;identifier | Multiple mapping entries normalize to this repository; shared repositories are valid, but verify the assignments are intentional. | — | https://github.com/example/demo | repos.json | /pkg:npm&#126;1demo@2.0 | 1 |
| unmapped&#95;component | No exact mapping exists; supply an explicit PURL-to-repository assignment. No repository was inferred. | pkg:npm/demo@3.0 | — | bom.json | /components/2 | — |
| missing&#95;purl | Component has no PURL; supply an explicit PURL to map it. | — | — | bom.json | /components/3 | — |

## Evidence

The JSON appendix retains the complete lint report, including every component, mapping entry, issue, location and input digest.

```json
{
  "components": [
    {
      "bomRef": null,
      "component": "pkg:npm/demo@1.0",
      "mappingStatus": "ambiguous",
      "name": "demo",
      "path": "/components/0",
      "purl": "pkg:npm/demo@1.0",
      "repository": null,
      "role": "inventory",
      "version": null
    },
    {
      "bomRef": null,
      "component": "pkg:npm/helper@1.0",
      "mappingStatus": "mapped",
      "name": "helper",
      "path": "/components/1",
      "purl": "pkg:npm/helper@1.0",
      "repository": "https://github.com/example/demo",
      "role": "inventory",
      "version": null
    },
    {
      "bomRef": null,
      "component": "pkg:npm/demo@3.0",
      "mappingStatus": "unmapped",
      "name": "demo",
      "path": "/components/2",
      "purl": "pkg:npm/demo@3.0",
      "repository": null,
      "role": "inventory",
      "version": null
    },
    {
      "bomRef": null,
      "component": "/components/3",
      "mappingStatus": "missing_purl",
      "name": "local-file",
      "path": "/components/3",
      "purl": null,
      "repository": null,
      "role": "inventory",
      "version": null
    }
  ],
  "inputs": {
    "bom": {
      "file": "bom.json",
      "sha256": "sha256:71fda35bb1f23ac2be6f18f5d8eb22eeeac4ed29673d6f41bea8da66e3271fdf"
    },
    "mapping": {
      "file": "repos.json",
      "sha256": "sha256:f73178fd9eba5dfd03690362949ac6808331b8abae17b7c8b5ade21f7bd13735"
    }
  },
  "issues": [
    {
      "code": "ambiguous_mapping",
      "locations": [
        {
          "file": "repos.json",
          "occurrence": 1,
          "pointer": "/pkg:npm~1demo@1.0"
        },
        {
          "file": "repos.json",
          "occurrence": 2,
          "pointer": "/pkg:npm~1demo@1.0"
        },
        {
          "file": "bom.json",
          "pointer": "/components/0"
        }
      ],
      "message": "One exact PURL assigns different canonical repositories; remove the conflicting entries before joining.",
      "purl": "pkg:npm/demo@1.0",
      "repositories": [
        "https://github.com/example/demo",
        "https://github.com/example/other"
      ]
    },
    {
      "code": "unused_mapping",
      "locations": [
        {
          "file": "repos.json",
          "occurrence": 1,
          "pointer": "/pkg:npm~1demo@2.0"
        }
      ],
      "message": "No component uses this exact PURL; check its version, qualifiers, case and escaping or remove the entry.",
      "purl": "pkg:npm/demo@2.0"
    },
    {
      "code": "duplicate_repository_identifier",
      "locations": [
        {
          "file": "repos.json",
          "occurrence": 1,
          "pointer": "/pkg:npm~1demo@1.0"
        },
        {
          "file": "repos.json",
          "occurrence": 1,
          "pointer": "/pkg:npm~1helper@1.0"
        },
        {
          "file": "repos.json",
          "occurrence": 1,
          "pointer": "/pkg:npm~1demo@2.0"
        }
      ],
      "message": "Multiple mapping entries normalize to this repository; shared repositories are valid, but verify the assignments are intentional.",
      "repository": "https://github.com/example/demo"
    },
    {
      "code": "unmapped_component",
      "locations": [
        {
          "file": "bom.json",
          "pointer": "/components/2"
        }
      ],
      "message": "No exact mapping exists; supply an explicit PURL-to-repository assignment. No repository was inferred.",
      "purl": "pkg:npm/demo@3.0"
    },
    {
      "code": "missing_purl",
      "locations": [
        {
          "file": "bom.json",
          "pointer": "/components/3"
        }
      ],
      "message": "Component has no PURL; supply an explicit PURL to map it.",
      "purl": null
    }
  ],
  "mappings": [
    {
      "location": {
        "file": "repos.json",
        "occurrence": 1,
        "pointer": "/pkg:npm~1demo@1.0"
      },
      "purl": "pkg:npm/demo@1.0",
      "repository": "https://github.com/example/demo"
    },
    {
      "location": {
        "file": "repos.json",
        "occurrence": 2,
        "pointer": "/pkg:npm~1demo@1.0"
      },
      "purl": "pkg:npm/demo@1.0",
      "repository": "https://github.com/example/other"
    },
    {
      "location": {
        "file": "repos.json",
        "occurrence": 1,
        "pointer": "/pkg:npm~1helper@1.0"
      },
      "purl": "pkg:npm/helper@1.0",
      "repository": "https://github.com/example/demo"
    },
    {
      "location": {
        "file": "repos.json",
        "occurrence": 1,
        "pointer": "/pkg:npm~1demo@2.0"
      },
      "purl": "pkg:npm/demo@2.0",
      "repository": "https://github.com/example/demo"
    }
  ],
  "reportVersion": "1",
  "summary": {
    "ambiguousComponents": 1,
    "ambiguousMappings": 1,
    "components": 4,
    "duplicateMappings": 0,
    "duplicateRepositoryIdentifiers": 1,
    "mappedComponents": 1,
    "mappingEntries": 4,
    "unmappedComponents": 2,
    "unusedMappings": 1
  },
  "tool": {
    "name": "scorecard-join",
    "version": "0.1.0"
  }
}
```
