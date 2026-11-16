# Scorecard join

As of: 2026-11-11T23:59:59.999999Z

Decision: **unknown**; gate exit code: 1.

Repository health evidence is not a release-commit attestation or a new security score.

| Component | Location | Repository | Decision | Reason | Age (days) | Upstream score |
| --- | --- | --- | --- | --- | --- | --- |
| pkg:npm/demo@1.0 | /components/0 | https://github.com/example/demo | pass | checks_passed | 1 | 8.4 |
| pkg:npm/demo-helper@2.0 | /components/1 | https://github.com/example/demo | pass | checks_passed | 1 | 8.4 |
| pkg:pypi/legacy@1.0 | /components/2 | https://github.com/example/legacy | unknown | stale_snapshot | 102 | 9.1 |
| pkg:npm/unchecked@1.0 | /components/3 | https://github.com/example/unchecked | unknown | unknown_check | 0 | 5.0 |
| pkg:generic/unlisted@1 | /components/4 | — | unknown | unmapped_component | — | — |
| local-file | /components/5 | — | unknown | missing_purl | — | — |
| release | /metadata/component | — | unknown | missing_purl | — | — |

## Evidence and check decisions

The JSON appendix retains every source document, selected check decision and digest.

```json
{
  "asOf": "2026-11-11T23:59:59.999999Z",
  "components": [
    {
      "ageDays": 1,
      "bomRef": "demo",
      "checks": [
        {
          "decision": "pass",
          "name": "Code-Review",
          "observation": "known",
          "reason": "threshold_met",
          "score": 8,
          "threshold": 7
        },
        {
          "decision": "pass",
          "name": "Security-Policy",
          "observation": "known",
          "reason": "threshold_met",
          "score": 10,
          "threshold": 5
        }
      ],
      "component": "pkg:npm/demo@1.0",
      "decision": "pass",
      "name": "demo",
      "path": "/components/0",
      "purl": "pkg:npm/demo@1.0",
      "reason": "checks_passed",
      "repository": "https://github.com/example/demo",
      "role": "inventory",
      "snapshotId": "sha256:b63b5aa9c96d093b4ad756b610c1fd095c2c62f888def45712bb10727b64747b",
      "upstreamScore": 8.4,
      "version": "1.0"
    },
    {
      "ageDays": 1,
      "bomRef": "demo-helper",
      "checks": [
        {
          "decision": "pass",
          "name": "Code-Review",
          "observation": "known",
          "reason": "threshold_met",
          "score": 8,
          "threshold": 7
        },
        {
          "decision": "pass",
          "name": "Security-Policy",
          "observation": "known",
          "reason": "threshold_met",
          "score": 10,
          "threshold": 5
        }
      ],
      "component": "pkg:npm/demo-helper@2.0",
      "decision": "pass",
      "name": "demo-helper",
      "path": "/components/1",
      "purl": "pkg:npm/demo-helper@2.0",
      "reason": "checks_passed",
      "repository": "https://github.com/example/demo",
      "role": "inventory",
      "snapshotId": "sha256:b63b5aa9c96d093b4ad756b610c1fd095c2c62f888def45712bb10727b64747b",
      "upstreamScore": 8.4,
      "version": "2.0"
    },
    {
      "ageDays": 102,
      "bomRef": "legacy",
      "checks": [
        {
          "decision": "unknown",
          "name": "Code-Review",
          "observation": "known",
          "reason": "stale_snapshot",
          "score": 10,
          "threshold": 7
        },
        {
          "decision": "unknown",
          "name": "Security-Policy",
          "observation": "known",
          "reason": "stale_snapshot",
          "score": 10,
          "threshold": 5
        }
      ],
      "component": "pkg:pypi/legacy@1.0",
      "decision": "unknown",
      "name": "legacy",
      "path": "/components/2",
      "purl": "pkg:pypi/legacy@1.0",
      "reason": "stale_snapshot",
      "repository": "https://github.com/example/legacy",
      "role": "inventory",
      "snapshotId": "sha256:1f82d732cdb366ad4bc1166b8025fc7b4d67acd3224764ac359b7f0a6d6a648e",
      "upstreamScore": 9.1,
      "version": "1.0"
    },
    {
      "ageDays": 0,
      "bomRef": "unchecked",
      "checks": [
        {
          "decision": "unknown",
          "name": "Code-Review",
          "observation": "negative_score",
          "reason": "negative_score",
          "score": -1,
          "threshold": 7
        },
        {
          "decision": "unknown",
          "name": "Security-Policy",
          "observation": "missing_check",
          "reason": "missing_check",
          "score": null,
          "threshold": 5
        }
      ],
      "component": "pkg:npm/unchecked@1.0",
      "decision": "unknown",
      "name": "unchecked",
      "path": "/components/3",
      "purl": "pkg:npm/unchecked@1.0",
      "reason": "unknown_check",
      "repository": "https://github.com/example/unchecked",
      "role": "inventory",
      "snapshotId": "sha256:2d5f5ccca78138eb3f6e2987d34f2b8e4e94ddd4f694526ffcfab8f4de77eaca",
      "upstreamScore": 5.0,
      "version": "1.0"
    },
    {
      "ageDays": null,
      "bomRef": "unlisted",
      "checks": [
        {
          "decision": "unknown",
          "name": "Code-Review",
          "observation": "missing_check",
          "reason": "unmapped_component",
          "score": null,
          "threshold": 7
        },
        {
          "decision": "unknown",
          "name": "Security-Policy",
          "observation": "missing_check",
          "reason": "unmapped_component",
          "score": null,
          "threshold": 5
        }
      ],
      "component": "pkg:generic/unlisted@1",
      "decision": "unknown",
      "name": "unlisted",
      "path": "/components/4",
      "purl": "pkg:generic/unlisted@1",
      "reason": "unmapped_component",
      "repository": null,
      "role": "inventory",
      "snapshotId": null,
      "upstreamScore": null,
      "version": null
    },
    {
      "ageDays": null,
      "bomRef": "local-file",
      "checks": [
        {
          "decision": "unknown",
          "name": "Code-Review",
          "observation": "missing_check",
          "reason": "missing_purl",
          "score": null,
          "threshold": 7
        },
        {
          "decision": "unknown",
          "name": "Security-Policy",
          "observation": "missing_check",
          "reason": "missing_purl",
          "score": null,
          "threshold": 5
        }
      ],
      "component": "local-file",
      "decision": "unknown",
      "name": "local-file",
      "path": "/components/5",
      "purl": null,
      "reason": "missing_purl",
      "repository": null,
      "role": "inventory",
      "snapshotId": null,
      "upstreamScore": null,
      "version": null
    },
    {
      "ageDays": null,
      "bomRef": "release",
      "checks": [
        {
          "decision": "unknown",
          "name": "Code-Review",
          "observation": "missing_check",
          "reason": "missing_purl",
          "score": null,
          "threshold": 7
        },
        {
          "decision": "unknown",
          "name": "Security-Policy",
          "observation": "missing_check",
          "reason": "missing_purl",
          "score": null,
          "threshold": 5
        }
      ],
      "component": "release",
      "decision": "unknown",
      "name": "synthetic-release",
      "path": "/metadata/component",
      "purl": null,
      "reason": "missing_purl",
      "repository": null,
      "role": "subject",
      "snapshotId": null,
      "upstreamScore": null,
      "version": "1.0"
    }
  ],
  "decision": "unknown",
  "gate": {
    "exitCode": 1,
    "passed": false
  },
  "inputs": {
    "bom": {
      "document": {
        "bomFormat": "CycloneDX",
        "components": [
          {
            "bom-ref": "demo",
            "name": "demo",
            "properties": [
              {
                "name": "fixture",
                "value": "synthetic"
              }
            ],
            "purl": "pkg:npm/demo@1.0",
            "type": "library",
            "version": "1.0"
          },
          {
            "bom-ref": "demo-helper",
            "name": "demo-helper",
            "purl": "pkg:npm/demo-helper@2.0",
            "type": "library",
            "version": "2.0"
          },
          {
            "bom-ref": "legacy",
            "name": "legacy",
            "purl": "pkg:pypi/legacy@1.0",
            "type": "library",
            "version": "1.0"
          },
          {
            "bom-ref": "unchecked",
            "name": "unchecked",
            "purl": "pkg:npm/unchecked@1.0",
            "type": "library",
            "version": "1.0"
          },
          {
            "bom-ref": "unlisted",
            "name": "unlisted",
            "purl": "pkg:generic/unlisted@1",
            "type": "library"
          },
          {
            "bom-ref": "local-file",
            "name": "local-file",
            "type": "file"
          }
        ],
        "dependencies": [
          {
            "dependsOn": [
              "demo",
              "demo-helper",
              "legacy",
              "unchecked",
              "unlisted",
              "local-file"
            ],
            "ref": "release"
          }
        ],
        "metadata": {
          "component": {
            "bom-ref": "release",
            "name": "synthetic-release",
            "type": "application",
            "version": "1.0"
          }
        },
        "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000065",
        "specVersion": "1.6",
        "version": 1
      },
      "sha256": "sha256:68eb35eca645ee63c144250f06f0af95a184995692b6938f601a74b7cd09778a"
    },
    "mapping": {
      "document": {
        "pkg:npm/demo-helper@2.0": "https://GitHub.com/Example/Demo.git/",
        "pkg:npm/demo@1.0": "https://github.com/example/demo",
        "pkg:npm/unchecked@1.0": "https://github.com/example/unchecked",
        "pkg:pypi/legacy@1.0": "https://github.com/example/legacy"
      },
      "sha256": "sha256:a4728a49dcf179559b10b07dcdac30886ab76d3475328df07cc088b919830e6c"
    },
    "policy": {
      "document": {
        "checks": {
          "Code-Review": 7,
          "Security-Policy": 5
        },
        "maxAgeDays": 30,
        "missing": "unknown"
      },
      "sha256": "sha256:d13cf861ce9f65310717c032b03c1e0bad371c4fdbee69b461bcb0860d5b7951"
    }
  },
  "reportVersion": "1",
  "repositoryIndex": {
    "https://github.com/example/demo": {
      "availableSnapshots": [
        "sha256:b63b5aa9c96d093b4ad756b610c1fd095c2c62f888def45712bb10727b64747b"
      ],
      "futureSnapshots": [],
      "selectedSnapshot": "sha256:b63b5aa9c96d093b4ad756b610c1fd095c2c62f888def45712bb10727b64747b"
    },
    "https://github.com/example/legacy": {
      "availableSnapshots": [
        "sha256:1f82d732cdb366ad4bc1166b8025fc7b4d67acd3224764ac359b7f0a6d6a648e"
      ],
      "futureSnapshots": [],
      "selectedSnapshot": "sha256:1f82d732cdb366ad4bc1166b8025fc7b4d67acd3224764ac359b7f0a6d6a648e"
    },
    "https://github.com/example/unchecked": {
      "availableSnapshots": [
        "sha256:2d5f5ccca78138eb3f6e2987d34f2b8e4e94ddd4f694526ffcfab8f4de77eaca"
      ],
      "futureSnapshots": [],
      "selectedSnapshot": "sha256:2d5f5ccca78138eb3f6e2987d34f2b8e4e94ddd4f694526ffcfab8f4de77eaca"
    }
  },
  "snapshots": [
    {
      "document": {
        "checks": [
          {
            "name": "Code-Review",
            "reason": "Synthetic review",
            "score": 10
          },
          {
            "name": "Security-Policy",
            "reason": "Synthetic policy",
            "score": 10
          }
        ],
        "date": "2026-08-01",
        "repo": {
          "commit": "2222222222222222222222222222222222222222",
          "name": "https://github.com/example/legacy"
        },
        "score": 9.1,
        "scorecard": {
          "commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "version": "v5.0.0"
        }
      },
      "id": "sha256:1f82d732cdb366ad4bc1166b8025fc7b4d67acd3224764ac359b7f0a6d6a648e",
      "recordedDate": "2026-08-01",
      "repository": "https://github.com/example/legacy",
      "sources": [
        {
          "file": "legacy.json",
          "sha256": "sha256:85a015a5193dd71afc24eb0472ce4ab2f57cc8f1b5dd85337762f747ddf72dbe"
        }
      ],
      "timestamp": "2026-08-01T00:00:00Z"
    },
    {
      "document": {
        "checks": [
          {
            "name": "Code-Review",
            "reason": "Synthetic unknown result",
            "score": -1
          }
        ],
        "date": "2026-11-11",
        "repo": {
          "commit": "3333333333333333333333333333333333333333",
          "name": "github.com/example/unchecked"
        },
        "score": 5.0,
        "scorecard": {
          "commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "version": "v5.0.0"
        }
      },
      "id": "sha256:2d5f5ccca78138eb3f6e2987d34f2b8e4e94ddd4f694526ffcfab8f4de77eaca",
      "recordedDate": "2026-11-11",
      "repository": "https://github.com/example/unchecked",
      "sources": [
        {
          "file": "unchecked.json",
          "sha256": "sha256:db83eb6326d3a7bf9c40db9e456f3b9209265dc7cfd653d1494a17596e22f9c4"
        }
      ],
      "timestamp": "2026-11-11T00:00:00Z"
    },
    {
      "document": {
        "checks": [
          {
            "details": [
              "Info: synthetic fixture"
            ],
            "documentation": {
              "short": "Review changes",
              "url": "https://github.com/ossf/scorecard/blob/main/docs/checks.md#code-review"
            },
            "name": "Code-Review",
            "reason": "Synthetic reviews",
            "score": 8
          },
          {
            "name": "Security-Policy",
            "reason": "Synthetic policy",
            "score": 10
          },
          {
            "extension": {
              "synthetic": true
            },
            "name": "Future-Check",
            "reason": "Preserved, not selected by policy",
            "score": 6
          }
        ],
        "date": "2026-11-10T12:00:00Z",
        "metadata": [
          "fixture=synthetic"
        ],
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
      "id": "sha256:b63b5aa9c96d093b4ad756b610c1fd095c2c62f888def45712bb10727b64747b",
      "recordedDate": "2026-11-10T12:00:00Z",
      "repository": "https://github.com/example/demo",
      "sources": [
        {
          "file": "demo.json",
          "sha256": "sha256:363cb9f514e665aeb88e636d436d1d7f3dab487644f058842e2bb43fa0005086"
        }
      ],
      "timestamp": "2026-11-10T12:00:00Z"
    }
  ],
  "summary": {
    "components": 7,
    "fail": 0,
    "freshComponents": 3,
    "joinedComponents": 4,
    "mappedComponents": 4,
    "pass": 2,
    "selectedRepositories": 3,
    "staleComponents": 1,
    "unknown": 5,
    "unmappedComponents": 3,
    "unusedMappings": []
  },
  "tool": {
    "name": "scorecard-join",
    "version": "0.1.0"
  }
}
```
