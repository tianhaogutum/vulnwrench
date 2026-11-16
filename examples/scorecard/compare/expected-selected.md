# Snapshot comparison

Before cutoff: 2026-11-01T23:59:59.999999Z; after cutoff: 2026-11-11T23:59:59.999999Z; maximum age: 2 UTC calendar days.

Components: **7**; mapped: **5**; unmapped or missing PURL: **2**; compared repositories: **4**; unused mappings: **0**.

Counts describe supplied evidence coverage, not score quality, a security gate or causal attribution. Score direction requires fresh, chronologically comparable snapshots and known scores on both sides. An em dash means unavailable; absent means the raw field was not supplied; null is a supplied JSON null. Full evidence, including unselected and future snapshots, is in the JSON appendix.

Check scope: explicitly selected exact names; only observed matches contribute to check rows and counts. Repository counts and full snapshots are unchanged.

| Selected exact name &#40;JSON literal&#41; |
| --- |
| &quot;Future-Check&quot; |
| &quot;License&quot; |
| &quot;Not-Observed&quot; |

## Coverage

| Partition | Classification | Repositories |
| --- | --- | --- |
| Comparison status | comparable | 2 |
| Comparison status | missing&#95;after | 1 |
| Comparison status | missing&#95;before | 0 |
| Comparison status | missing&#95;both | 0 |
| Comparison status | snapshot&#95;time&#95;ambiguous | 0 |
| Comparison status | snapshot&#95;time&#95;regressed | 0 |
| Comparison status | stale&#95;after | 1 |
| Comparison status | stale&#95;before | 0 |
| Snapshot change | advanced | 3 |
| Snapshot change | not&#95;comparable | 1 |
| Snapshot change | regressed | 0 |
| Snapshot change | same&#95;timestamp&#95;changed | 0 |
| Snapshot change | unchanged | 0 |
| Scanner version | changed | 1 |
| Scanner version | not&#95;comparable | 1 |
| Scanner version | unchanged | 2 |
| Scanner commit | changed | 1 |
| Scanner commit | not&#95;comparable | 1 |
| Scanner commit | unchanged | 2 |

Raw check changes count observed repository/check pairs, including unknown scores; they do not measure score quality.

| Raw check change | Repository/check pairs |
| --- | --- |
| added | 1 |
| changed | 1 |
| deleted | 0 |
| not&#95;comparable | 0 |
| unchanged | 0 |

Score directions count the same observed repository/check pairs; not_comparable includes unknown scores, added/deleted checks and evidence blockers.

| Check score direction | Repository/check pairs |
| --- | --- |
| decreased | 0 |
| increased | 0 |
| not&#95;comparable | 1 |
| unchanged | 1 |

Score directions by check group the same pairs by exact observed name; unobserved names are omitted. Counts describe supplied numeric direction, not score quality, security or causality.

| Check | Score direction | Repository/check pairs |
| --- | --- | --- |
| Future-Check | increased | 0 |
| Future-Check | decreased | 0 |
| Future-Check | unchanged | 0 |
| Future-Check | not&#95;comparable | 1 |
| License | increased | 0 |
| License | decreased | 0 |
| License | unchanged | 1 |
| License | not&#95;comparable | 0 |

Check score comparability counts each observed pair once: a scoreChange other than not_comparable counts comparable; otherwise a repository comparison other than comparable counts evidence_blocked; remaining pairs count observation_blocked. Evidence blockers take priority over observation gaps; counts do not enumerate every simultaneous blocker. Comparable describes support for numeric direction, not security or causality.

| Check score comparability | Repository/check pairs |
| --- | --- |
| comparable | 1 |
| evidence&#95;blocked | 0 |
| observation&#95;blocked | 1 |

Check score comparability by check groups the same pairs by exact observed name and uses the same priority; unobserved names are omitted.

| Check | Comparability | Repository/check pairs |
| --- | --- | --- |
| Future-Check | comparable | 0 |
| Future-Check | evidence&#95;blocked | 0 |
| Future-Check | observation&#95;blocked | 1 |
| License | comparable | 1 |
| License | evidence&#95;blocked | 0 |
| License | observation&#95;blocked | 0 |

Check observations count the same pairs separately on each side; missing scores, absent checks and unavailable snapshots remain distinct. Freshness and chronology do not relabel observations.

| Side | Observation | Repository/check pairs |
| --- | --- | --- |
| Before | known | 1 |
| Before | missing&#95;check | 1 |
| Before | missing&#95;score | 0 |
| Before | missing&#95;snapshot | 0 |
| Before | negative&#95;score | 0 |
| After | known | 2 |
| After | missing&#95;check | 0 |
| After | missing&#95;score | 0 |
| After | missing&#95;snapshot | 0 |
| After | negative&#95;score | 0 |

Check observation transitions count each pair once by its before and after labels; known to known does not establish score direction.

| Before observation | After observation | Repository/check pairs |
| --- | --- | --- |
| known | known | 1 |
| known | missing&#95;check | 0 |
| known | missing&#95;score | 0 |
| known | missing&#95;snapshot | 0 |
| known | negative&#95;score | 0 |
| missing&#95;check | known | 1 |
| missing&#95;check | missing&#95;check | 0 |
| missing&#95;check | missing&#95;score | 0 |
| missing&#95;check | missing&#95;snapshot | 0 |
| missing&#95;check | negative&#95;score | 0 |
| missing&#95;score | known | 0 |
| missing&#95;score | missing&#95;check | 0 |
| missing&#95;score | missing&#95;score | 0 |
| missing&#95;score | missing&#95;snapshot | 0 |
| missing&#95;score | negative&#95;score | 0 |
| missing&#95;snapshot | known | 0 |
| missing&#95;snapshot | missing&#95;check | 0 |
| missing&#95;snapshot | missing&#95;score | 0 |
| missing&#95;snapshot | missing&#95;snapshot | 0 |
| missing&#95;snapshot | negative&#95;score | 0 |
| negative&#95;score | known | 0 |
| negative&#95;score | missing&#95;check | 0 |
| negative&#95;score | missing&#95;score | 0 |
| negative&#95;score | missing&#95;snapshot | 0 |
| negative&#95;score | negative&#95;score | 0 |

## Components

| Name | PURL | Repository | Mapping status | Role | JSON Pointer |
| --- | --- | --- | --- | --- | --- |
| demo | pkg:npm/demo@1 | https://github.com/example/demo | mapped | inventory | /components/0 |
| helper | pkg:npm/helper@1 | https://github.com/example/demo | mapped | inventory | /components/1 |
| stale | pkg:npm/stale@1 | https://github.com/example/stale | mapped | inventory | /components/2 |
| missing | pkg:npm/missing@1 | https://github.com/example/missing | mapped | inventory | /components/3 |
| scanner | pkg:npm/scanner@1 | https://github.com/example/scanner | mapped | inventory | /components/4 |
| unmapped | pkg:npm/unmapped@1 | — | unmapped | inventory | /components/5 |
| local-file | — | — | missing&#95;purl | inventory | /components/6 |

## Repositories

| Repository | Comparison status | Snapshot change | Repository commit change |
| --- | --- | --- | --- |
| https://github.com/example/demo | comparable | advanced | changed |
| https://github.com/example/missing | missing&#95;after | not&#95;comparable | not&#95;comparable |
| https://github.com/example/scanner | comparable | advanced | unchanged |
| https://github.com/example/stale | stale&#95;after | advanced | changed |

### https://github.com/example/demo

| Side | Evidence status | Timestamp | Age days | Repository commit |
| --- | --- | --- | --- | --- |
| Before | fresh | 2026-11-01T00:00:00Z | 0 | 1111111111111111111111111111111111111111 |
| After | fresh | 2026-11-11T00:00:00Z | 0 | 2222222222222222222222222222222222222222 |

| Scanner field | Before | After | Change |
| --- | --- | --- | --- |
| version | v5.0.0 | v5.0.0 | unchanged |
| commit | aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa | aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa | unchanged |

| Check | Raw change | Score direction | Before observation | After observation | Before score | After score | Score field changed | Before reason | After reason | Reason field changed |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Future-Check | added | not&#95;comparable | missing&#95;check | known | — | 10 | true | — | &quot;Synthetic: new check&quot; | true |
| License | changed | unchanged | known | known | 5 | 5 | false | &quot;Synthetic: old explanation&quot; | &quot;Synthetic: new explanation&quot; | true |

### https://github.com/example/missing

| Side | Evidence status | Timestamp | Age days | Repository commit |
| --- | --- | --- | --- | --- |
| Before | fresh | 2026-11-01T00:00:00Z | 0 | 3333333333333333333333333333333333333333 |
| After | missing&#95;scorecard | — | — | — |

| Scanner field | Before | After | Change |
| --- | --- | --- | --- |
| version | v5.0.0 | — | not&#95;comparable |
| commit | aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa | — | not&#95;comparable |

| Check | Raw change | Score direction | Before observation | After observation | Before score | After score | Score field changed | Before reason | After reason | Reason field changed |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |

No observed checks.

### https://github.com/example/scanner

| Side | Evidence status | Timestamp | Age days | Repository commit |
| --- | --- | --- | --- | --- |
| Before | fresh | 2026-11-01T00:00:00Z | 0 | 3333333333333333333333333333333333333333 |
| After | fresh | 2026-11-11T00:00:00Z | 0 | 3333333333333333333333333333333333333333 |

| Scanner field | Before | After | Change |
| --- | --- | --- | --- |
| version | v5.0.0 | v5.1.0 | changed |
| commit | aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa | bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb | changed |

| Check | Raw change | Score direction | Before observation | After observation | Before score | After score | Score field changed | Before reason | After reason | Reason field changed |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |

No observed checks.

### https://github.com/example/stale

| Side | Evidence status | Timestamp | Age days | Repository commit |
| --- | --- | --- | --- | --- |
| Before | fresh | 2026-11-01T00:00:00Z | 0 | 3333333333333333333333333333333333333333 |
| After | stale | 2026-11-02T00:00:00Z | 9 | 4444444444444444444444444444444444444444 |

| Scanner field | Before | After | Change |
| --- | --- | --- | --- |
| version | v5.0.0 | v5.0.0 | unchanged |
| commit | aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa | aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa | unchanged |

| Check | Raw change | Score direction | Before observation | After observation | Before score | After score | Score field changed | Before reason | After reason | Reason field changed |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |

No observed checks.

## Evidence

Complete comparison JSON, including original inputs, raw checks, scanner metadata, source digests and all supplied snapshots.

```json
{
  "after": {
    "asOf": "2026-11-11T23:59:59.999999Z",
    "repositoryIndex": {
      "https://github.com/example/demo": {
        "availableSnapshots": [
          "sha256:e053d45efdb595219ea3d9f2c828e688f99bea35cfa756fce8bcb7620e05fc6f"
        ],
        "futureSnapshots": [],
        "selectedSnapshot": "sha256:e053d45efdb595219ea3d9f2c828e688f99bea35cfa756fce8bcb7620e05fc6f"
      },
      "https://github.com/example/scanner": {
        "availableSnapshots": [
          "sha256:22fe0ec52d5746bd118e2fba6b6275a03051c74a70d92e899552d2cd4d7b0afd"
        ],
        "futureSnapshots": [],
        "selectedSnapshot": "sha256:22fe0ec52d5746bd118e2fba6b6275a03051c74a70d92e899552d2cd4d7b0afd"
      },
      "https://github.com/example/stale": {
        "availableSnapshots": [
          "sha256:eccb176809f6ef2f5961c05fb3b1a3419202ab1595077506f47da320dfd16713"
        ],
        "futureSnapshots": [],
        "selectedSnapshot": "sha256:eccb176809f6ef2f5961c05fb3b1a3419202ab1595077506f47da320dfd16713"
      }
    },
    "snapshots": [
      {
        "document": {
          "checks": [
            {
              "name": "Code-Review",
              "reason": "Synthetic: revised scan",
              "score": 8
            }
          ],
          "date": "2026-11-11",
          "repo": {
            "commit": "3333333333333333333333333333333333333333",
            "name": "github.com/example/scanner"
          },
          "scorecard": {
            "commit": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "version": "v5.1.0"
          }
        },
        "id": "sha256:22fe0ec52d5746bd118e2fba6b6275a03051c74a70d92e899552d2cd4d7b0afd",
        "recordedDate": "2026-11-11",
        "repository": "https://github.com/example/scanner",
        "sources": [
          {
            "file": "scanner.json",
            "sha256": "sha256:87a7461e38befc5097d1fa5e46e8e503a36247460e2ce7539b62e337118cfeff"
          }
        ],
        "timestamp": "2026-11-11T00:00:00Z"
      },
      {
        "document": {
          "checks": [
            {
              "name": "Code-Review",
              "reason": "Synthetic: more reviews",
              "score": 8
            },
            {
              "name": "License",
              "reason": "Synthetic: new explanation",
              "score": 5
            },
            {
              "name": "Maintained",
              "reason": "Synthetic: active",
              "score": 10
            },
            {
              "name": "Future-Check",
              "reason": "Synthetic: new check",
              "score": 10
            }
          ],
          "date": "2026-11-11",
          "repo": {
            "commit": "2222222222222222222222222222222222222222",
            "name": "github.com/example/demo"
          },
          "score": 8.4,
          "scorecard": {
            "commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "version": "v5.0.0"
          }
        },
        "id": "sha256:e053d45efdb595219ea3d9f2c828e688f99bea35cfa756fce8bcb7620e05fc6f",
        "recordedDate": "2026-11-11",
        "repository": "https://github.com/example/demo",
        "sources": [
          {
            "file": "demo.json",
            "sha256": "sha256:7498df4e8a556b4e64094a75dc7d0bc3ea7cae2f4ba2e4e75cb5f8abd73822af"
          }
        ],
        "timestamp": "2026-11-11T00:00:00Z"
      },
      {
        "document": {
          "checks": [
            {
              "name": "Code-Review",
              "reason": "Synthetic: high but stale",
              "score": 10
            }
          ],
          "date": "2026-11-02",
          "repo": {
            "commit": "4444444444444444444444444444444444444444",
            "name": "github.com/example/stale"
          },
          "score": 8.4,
          "scorecard": {
            "commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "version": "v5.0.0"
          }
        },
        "id": "sha256:eccb176809f6ef2f5961c05fb3b1a3419202ab1595077506f47da320dfd16713",
        "recordedDate": "2026-11-02",
        "repository": "https://github.com/example/stale",
        "sources": [
          {
            "file": "stale.json",
            "sha256": "sha256:c2b11cc8e42b2e4c4fe640dada531c1e5c12a88440de68e31fe4d65a3d3615c6"
          }
        ],
        "timestamp": "2026-11-02T00:00:00Z"
      }
    ]
  },
  "before": {
    "asOf": "2026-11-01T23:59:59.999999Z",
    "repositoryIndex": {
      "https://github.com/example/demo": {
        "availableSnapshots": [
          "sha256:66ef46cb6d5a4c25f989e51d8db18ae2809d56ac9c510f35c5d34732c2e9c854"
        ],
        "futureSnapshots": [],
        "selectedSnapshot": "sha256:66ef46cb6d5a4c25f989e51d8db18ae2809d56ac9c510f35c5d34732c2e9c854"
      },
      "https://github.com/example/missing": {
        "availableSnapshots": [
          "sha256:3e524d49fd39fb6a9fac58af03dbe6abce9e15bec9eb65700aade43ff9e23cfd"
        ],
        "futureSnapshots": [],
        "selectedSnapshot": "sha256:3e524d49fd39fb6a9fac58af03dbe6abce9e15bec9eb65700aade43ff9e23cfd"
      },
      "https://github.com/example/scanner": {
        "availableSnapshots": [
          "sha256:e69b61460cf285938eda02259ea64dda7f33eb2104f6b0de0ca19c46cf7b6923"
        ],
        "futureSnapshots": [],
        "selectedSnapshot": "sha256:e69b61460cf285938eda02259ea64dda7f33eb2104f6b0de0ca19c46cf7b6923"
      },
      "https://github.com/example/stale": {
        "availableSnapshots": [
          "sha256:377aae2774233c2441f29527bbd4dbbc03ddeef24fde23ea60c7576fc96d4c77"
        ],
        "futureSnapshots": [],
        "selectedSnapshot": "sha256:377aae2774233c2441f29527bbd4dbbc03ddeef24fde23ea60c7576fc96d4c77"
      }
    },
    "snapshots": [
      {
        "document": {
          "checks": [
            {
              "name": "Code-Review",
              "reason": "Synthetic: baseline",
              "score": 1
            }
          ],
          "date": "2026-11-01",
          "repo": {
            "commit": "3333333333333333333333333333333333333333",
            "name": "github.com/example/stale"
          },
          "score": 8.4,
          "scorecard": {
            "commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "version": "v5.0.0"
          }
        },
        "id": "sha256:377aae2774233c2441f29527bbd4dbbc03ddeef24fde23ea60c7576fc96d4c77",
        "recordedDate": "2026-11-01",
        "repository": "https://github.com/example/stale",
        "sources": [
          {
            "file": "stale.json",
            "sha256": "sha256:bfcf7272725e680b73b88dad891d0e5372702198936c2ff501ea671207e4460b"
          }
        ],
        "timestamp": "2026-11-01T00:00:00Z"
      },
      {
        "document": {
          "checks": [
            {
              "name": "Code-Review",
              "reason": "Synthetic: baseline",
              "score": 1
            }
          ],
          "date": "2026-11-01",
          "repo": {
            "commit": "3333333333333333333333333333333333333333",
            "name": "github.com/example/missing"
          },
          "score": 8.4,
          "scorecard": {
            "commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "version": "v5.0.0"
          }
        },
        "id": "sha256:3e524d49fd39fb6a9fac58af03dbe6abce9e15bec9eb65700aade43ff9e23cfd",
        "recordedDate": "2026-11-01",
        "repository": "https://github.com/example/missing",
        "sources": [
          {
            "file": "missing.json",
            "sha256": "sha256:50017b491956ad33d25f9e00f9859abb0ff87094a573473a8ffe66e42f63c496"
          }
        ],
        "timestamp": "2026-11-01T00:00:00Z"
      },
      {
        "document": {
          "checks": [
            {
              "name": "Code-Review",
              "reason": "Synthetic: few reviews",
              "score": 3
            },
            {
              "name": "License",
              "reason": "Synthetic: old explanation",
              "score": 5
            },
            {
              "name": "Maintained",
              "reason": "Synthetic: unavailable",
              "score": -1
            },
            {
              "name": "Security-Policy",
              "reason": "Synthetic: policy exists",
              "score": 10
            }
          ],
          "date": "2026-11-01",
          "repo": {
            "commit": "1111111111111111111111111111111111111111",
            "name": "github.com/example/demo"
          },
          "score": 8.4,
          "scorecard": {
            "commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "version": "v5.0.0"
          }
        },
        "id": "sha256:66ef46cb6d5a4c25f989e51d8db18ae2809d56ac9c510f35c5d34732c2e9c854",
        "recordedDate": "2026-11-01",
        "repository": "https://github.com/example/demo",
        "sources": [
          {
            "file": "demo.json",
            "sha256": "sha256:392d254f3bc1a33d8843d4b47ace350e41d48e9625dda92894bd4c615d864e3b"
          }
        ],
        "timestamp": "2026-11-01T00:00:00Z"
      },
      {
        "document": {
          "checks": [
            {
              "name": "Code-Review",
              "reason": "Synthetic: prior scan",
              "score": 3
            }
          ],
          "date": "2026-11-01",
          "repo": {
            "commit": "3333333333333333333333333333333333333333",
            "name": "github.com/example/scanner"
          },
          "scorecard": {
            "commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "version": "v5.0.0"
          }
        },
        "id": "sha256:e69b61460cf285938eda02259ea64dda7f33eb2104f6b0de0ca19c46cf7b6923",
        "recordedDate": "2026-11-01",
        "repository": "https://github.com/example/scanner",
        "sources": [
          {
            "file": "scanner.json",
            "sha256": "sha256:1e43dbbb05806239e0cb73ce276446d648f4a9c120f5998a8c8ebed5a822025d"
          }
        ],
        "timestamp": "2026-11-01T00:00:00Z"
      }
    ]
  },
  "checkSelection": {
    "names": [
      "Future-Check",
      "License",
      "Not-Observed"
    ]
  },
  "components": [
    {
      "bomRef": null,
      "component": "pkg:npm/demo@1",
      "mappingStatus": "mapped",
      "name": "demo",
      "path": "/components/0",
      "purl": "pkg:npm/demo@1",
      "repository": "https://github.com/example/demo",
      "role": "inventory",
      "version": null
    },
    {
      "bomRef": null,
      "component": "pkg:npm/helper@1",
      "mappingStatus": "mapped",
      "name": "helper",
      "path": "/components/1",
      "purl": "pkg:npm/helper@1",
      "repository": "https://github.com/example/demo",
      "role": "inventory",
      "version": null
    },
    {
      "bomRef": null,
      "component": "pkg:npm/stale@1",
      "mappingStatus": "mapped",
      "name": "stale",
      "path": "/components/2",
      "purl": "pkg:npm/stale@1",
      "repository": "https://github.com/example/stale",
      "role": "inventory",
      "version": null
    },
    {
      "bomRef": null,
      "component": "pkg:npm/missing@1",
      "mappingStatus": "mapped",
      "name": "missing",
      "path": "/components/3",
      "purl": "pkg:npm/missing@1",
      "repository": "https://github.com/example/missing",
      "role": "inventory",
      "version": null
    },
    {
      "bomRef": null,
      "component": "pkg:npm/scanner@1",
      "mappingStatus": "mapped",
      "name": "scanner",
      "path": "/components/4",
      "purl": "pkg:npm/scanner@1",
      "repository": "https://github.com/example/scanner",
      "role": "inventory",
      "version": null
    },
    {
      "bomRef": null,
      "component": "pkg:npm/unmapped@1",
      "mappingStatus": "unmapped",
      "name": "unmapped",
      "path": "/components/5",
      "purl": "pkg:npm/unmapped@1",
      "repository": null,
      "role": "inventory",
      "version": null
    },
    {
      "bomRef": null,
      "component": "/components/6",
      "mappingStatus": "missing_purl",
      "name": "local-file",
      "path": "/components/6",
      "purl": null,
      "repository": null,
      "role": "inventory",
      "version": null
    }
  ],
  "inputs": {
    "bom": {
      "document": {
        "bomFormat": "CycloneDX",
        "components": [
          {
            "name": "demo",
            "purl": "pkg:npm/demo@1",
            "type": "library"
          },
          {
            "name": "helper",
            "purl": "pkg:npm/helper@1",
            "type": "library"
          },
          {
            "name": "stale",
            "purl": "pkg:npm/stale@1",
            "type": "library"
          },
          {
            "name": "missing",
            "purl": "pkg:npm/missing@1",
            "type": "library"
          },
          {
            "name": "scanner",
            "purl": "pkg:npm/scanner@1",
            "type": "library"
          },
          {
            "name": "unmapped",
            "purl": "pkg:npm/unmapped@1",
            "type": "library"
          },
          {
            "name": "local-file",
            "type": "file"
          }
        ],
        "specVersion": "1.6",
        "version": 1
      },
      "sha256": "sha256:7ef5405833796d2724140b7886ecfc5b2559235b005d8b3f1a17c0a1cc477b64"
    },
    "mapping": {
      "document": {
        "pkg:npm/demo@1": "github.com/example/demo",
        "pkg:npm/helper@1": "github.com/example/demo",
        "pkg:npm/missing@1": "github.com/example/missing",
        "pkg:npm/scanner@1": "github.com/example/scanner",
        "pkg:npm/stale@1": "github.com/example/stale"
      },
      "sha256": "sha256:bb1eaf65ce1d9c323dc652bf5e104c81c004df4afdecd42bee4bc822e60f2d57"
    }
  },
  "maxAgeDays": 2,
  "reportType": "snapshot-comparison",
  "reportVersion": "1",
  "repositories": [
    {
      "after": {
        "ageDays": 0,
        "commit": "2222222222222222222222222222222222222222",
        "snapshotId": "sha256:e053d45efdb595219ea3d9f2c828e688f99bea35cfa756fce8bcb7620e05fc6f",
        "status": "fresh",
        "timestamp": "2026-11-11T00:00:00Z"
      },
      "before": {
        "ageDays": 0,
        "commit": "1111111111111111111111111111111111111111",
        "snapshotId": "sha256:66ef46cb6d5a4c25f989e51d8db18ae2809d56ac9c510f35c5d34732c2e9c854",
        "status": "fresh",
        "timestamp": "2026-11-01T00:00:00Z"
      },
      "checks": [
        {
          "after": {
            "name": "Future-Check",
            "reason": "Synthetic: new check",
            "score": 10
          },
          "afterObservation": "known",
          "before": null,
          "beforeObservation": "missing_check",
          "change": "added",
          "name": "Future-Check",
          "reasonChanged": true,
          "scoreChange": "not_comparable",
          "scoreChanged": true
        },
        {
          "after": {
            "name": "License",
            "reason": "Synthetic: new explanation",
            "score": 5
          },
          "afterObservation": "known",
          "before": {
            "name": "License",
            "reason": "Synthetic: old explanation",
            "score": 5
          },
          "beforeObservation": "known",
          "change": "changed",
          "name": "License",
          "reasonChanged": true,
          "scoreChange": "unchanged",
          "scoreChanged": false
        }
      ],
      "commitChange": "changed",
      "comparison": "comparable",
      "repository": "https://github.com/example/demo",
      "scannerChange": {
        "after": {
          "commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "version": "v5.0.0"
        },
        "before": {
          "commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "version": "v5.0.0"
        },
        "commitChange": "unchanged",
        "versionChange": "unchanged"
      },
      "snapshotChange": "advanced"
    },
    {
      "after": {
        "ageDays": null,
        "commit": null,
        "snapshotId": null,
        "status": "missing_scorecard",
        "timestamp": null
      },
      "before": {
        "ageDays": 0,
        "commit": "3333333333333333333333333333333333333333",
        "snapshotId": "sha256:3e524d49fd39fb6a9fac58af03dbe6abce9e15bec9eb65700aade43ff9e23cfd",
        "status": "fresh",
        "timestamp": "2026-11-01T00:00:00Z"
      },
      "checks": [],
      "commitChange": "not_comparable",
      "comparison": "missing_after",
      "repository": "https://github.com/example/missing",
      "scannerChange": {
        "after": null,
        "before": {
          "commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "version": "v5.0.0"
        },
        "commitChange": "not_comparable",
        "versionChange": "not_comparable"
      },
      "snapshotChange": "not_comparable"
    },
    {
      "after": {
        "ageDays": 0,
        "commit": "3333333333333333333333333333333333333333",
        "snapshotId": "sha256:22fe0ec52d5746bd118e2fba6b6275a03051c74a70d92e899552d2cd4d7b0afd",
        "status": "fresh",
        "timestamp": "2026-11-11T00:00:00Z"
      },
      "before": {
        "ageDays": 0,
        "commit": "3333333333333333333333333333333333333333",
        "snapshotId": "sha256:e69b61460cf285938eda02259ea64dda7f33eb2104f6b0de0ca19c46cf7b6923",
        "status": "fresh",
        "timestamp": "2026-11-01T00:00:00Z"
      },
      "checks": [],
      "commitChange": "unchanged",
      "comparison": "comparable",
      "repository": "https://github.com/example/scanner",
      "scannerChange": {
        "after": {
          "commit": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          "version": "v5.1.0"
        },
        "before": {
          "commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "version": "v5.0.0"
        },
        "commitChange": "changed",
        "versionChange": "changed"
      },
      "snapshotChange": "advanced"
    },
    {
      "after": {
        "ageDays": 9,
        "commit": "4444444444444444444444444444444444444444",
        "snapshotId": "sha256:eccb176809f6ef2f5961c05fb3b1a3419202ab1595077506f47da320dfd16713",
        "status": "stale",
        "timestamp": "2026-11-02T00:00:00Z"
      },
      "before": {
        "ageDays": 0,
        "commit": "3333333333333333333333333333333333333333",
        "snapshotId": "sha256:377aae2774233c2441f29527bbd4dbbc03ddeef24fde23ea60c7576fc96d4c77",
        "status": "fresh",
        "timestamp": "2026-11-01T00:00:00Z"
      },
      "checks": [],
      "commitChange": "changed",
      "comparison": "stale_after",
      "repository": "https://github.com/example/stale",
      "scannerChange": {
        "after": {
          "commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "version": "v5.0.0"
        },
        "before": {
          "commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "version": "v5.0.0"
        },
        "commitChange": "unchanged",
        "versionChange": "unchanged"
      },
      "snapshotChange": "advanced"
    }
  ],
  "summary": {
    "checkChanges": {
      "added": 1,
      "changed": 1,
      "deleted": 0,
      "not_comparable": 0,
      "unchanged": 0
    },
    "checkObservationTransitions": {
      "known": {
        "known": 1,
        "missing_check": 0,
        "missing_score": 0,
        "missing_snapshot": 0,
        "negative_score": 0
      },
      "missing_check": {
        "known": 1,
        "missing_check": 0,
        "missing_score": 0,
        "missing_snapshot": 0,
        "negative_score": 0
      },
      "missing_score": {
        "known": 0,
        "missing_check": 0,
        "missing_score": 0,
        "missing_snapshot": 0,
        "negative_score": 0
      },
      "missing_snapshot": {
        "known": 0,
        "missing_check": 0,
        "missing_score": 0,
        "missing_snapshot": 0,
        "negative_score": 0
      },
      "negative_score": {
        "known": 0,
        "missing_check": 0,
        "missing_score": 0,
        "missing_snapshot": 0,
        "negative_score": 0
      }
    },
    "checkObservations": {
      "after": {
        "known": 2,
        "missing_check": 0,
        "missing_score": 0,
        "missing_snapshot": 0,
        "negative_score": 0
      },
      "before": {
        "known": 1,
        "missing_check": 1,
        "missing_score": 0,
        "missing_snapshot": 0,
        "negative_score": 0
      }
    },
    "checkScoreChanges": {
      "decreased": 0,
      "increased": 0,
      "not_comparable": 1,
      "unchanged": 1
    },
    "checkScoreChangesByCheck": [
      {
        "decreased": 0,
        "increased": 0,
        "name": "Future-Check",
        "not_comparable": 1,
        "unchanged": 0
      },
      {
        "decreased": 0,
        "increased": 0,
        "name": "License",
        "not_comparable": 0,
        "unchanged": 1
      }
    ],
    "checkScoreComparability": {
      "comparable": 1,
      "evidence_blocked": 0,
      "observation_blocked": 1
    },
    "checkScoreComparabilityByCheck": [
      {
        "comparable": 0,
        "evidence_blocked": 0,
        "name": "Future-Check",
        "observation_blocked": 1
      },
      {
        "comparable": 1,
        "evidence_blocked": 0,
        "name": "License",
        "observation_blocked": 0
      }
    ],
    "comparedRepositories": 4,
    "comparisonStatuses": {
      "comparable": 2,
      "missing_after": 1,
      "missing_before": 0,
      "missing_both": 0,
      "snapshot_time_ambiguous": 0,
      "snapshot_time_regressed": 0,
      "stale_after": 1,
      "stale_before": 0
    },
    "components": 7,
    "mappedComponents": 5,
    "scannerChanges": {
      "commit": {
        "changed": 1,
        "not_comparable": 1,
        "unchanged": 2
      },
      "version": {
        "changed": 1,
        "not_comparable": 1,
        "unchanged": 2
      }
    },
    "snapshotChanges": {
      "advanced": 3,
      "not_comparable": 1,
      "regressed": 0,
      "same_timestamp_changed": 0,
      "unchanged": 0
    },
    "unmappedComponents": 2,
    "unusedMappings": []
  },
  "tool": {
    "name": "scorecard-join",
    "version": "0.1.0"
  }
}
```
