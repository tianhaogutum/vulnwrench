# vulnwrench delta transition matrix

Scan and inventory evidence only; not proof that all vulnerabilities are found or fixed.

Comparable: true

| Package | Target / package path | Advisory | Before | After | Classification | Fixed | Reasons |
| --- | --- | --- | --- | --- | --- | --- | --- |
| npm:demo | package-lock.json /  | CVE-SYNTH-DEMO | 1.0 | 1.1 | version_changed_still_affected | false |  |
| npm:healed | package-lock.json /  | CVE-SYNTH-HEALED | 1.0 |  | fixed_within_snapshot | true |  |
| npm:new | package-lock.json /  | CVE-SYNTH-NEW |  | 1.0 | introduced | false |  |
| npm:removed | package-lock.json /  | CVE-SYNTH-REMOVED | 1.0 |  | package_removed | false |  |
| npm:stable | package-lock.json /  | CVE-SYNTH-STABLE | 2.0 | 2.0 | persistent | false |  |

## Full evidence and accounting

```json
{
  "accounting": {
    "after_findings": 3,
    "after_inventory_components": 4,
    "after_records_accounted": 3,
    "before_findings": 4,
    "before_inventory_components": 4,
    "before_records_accounted": 4
  },
  "comparability_reasons": [],
  "comparable": true,
  "evidence": {
    "after_bom": {
      "digest_encoding": "canonical-json-ascii-utf8",
      "document": {
        "bomFormat": "CycloneDX",
        "components": [
          {
            "bom-ref": "synthetic-0",
            "name": "demo",
            "properties": [
              {
                "name": "scan-delta:target",
                "value": "package-lock.json"
              }
            ],
            "purl": "pkg:npm/demo@1.1",
            "type": "library",
            "version": "1.1"
          },
          {
            "bom-ref": "synthetic-1",
            "name": "stable",
            "properties": [
              {
                "name": "scan-delta:target",
                "value": "package-lock.json"
              }
            ],
            "purl": "pkg:npm/stable@2.0",
            "type": "library",
            "version": "2.0"
          },
          {
            "bom-ref": "synthetic-2",
            "name": "healed",
            "properties": [
              {
                "name": "scan-delta:target",
                "value": "package-lock.json"
              }
            ],
            "purl": "pkg:npm/healed@1.1",
            "type": "library",
            "version": "1.1"
          },
          {
            "bom-ref": "synthetic-3",
            "name": "new",
            "properties": [
              {
                "name": "scan-delta:target",
                "value": "package-lock.json"
              }
            ],
            "purl": "pkg:npm/new@1.0",
            "type": "library",
            "version": "1.0"
          }
        ],
        "specVersion": "1.5",
        "version": 1
      },
      "sha256": "bad9b9038fe8b3ac2a5be6667266e9272145febd057642ae6f837fadcb77168b"
    },
    "after_report": {
      "digest_encoding": "canonical-json-ascii-utf8",
      "document": {
        "ArtifactName": "synthetic-demo",
        "ArtifactType": "filesystem",
        "Results": [
          {
            "Class": "lang-pkgs",
            "Target": "package-lock.json",
            "Type": "node-pkg",
            "Vulnerabilities": [
              {
                "InstalledVersion": "1.1",
                "PkgIdentifier": {
                  "PURL": "pkg:npm/demo@1.1"
                },
                "PkgName": "demo",
                "Severity": "HIGH",
                "VulnerabilityID": "GHSA-SYNTH-DEMO"
              },
              {
                "InstalledVersion": "2.0",
                "PkgIdentifier": {
                  "PURL": "pkg:npm/stable@2.0"
                },
                "PkgName": "stable",
                "Severity": "HIGH",
                "VulnerabilityID": "CVE-SYNTH-STABLE"
              },
              {
                "InstalledVersion": "1.0",
                "PkgIdentifier": {
                  "PURL": "pkg:npm/new@1.0"
                },
                "PkgName": "new",
                "Severity": "HIGH",
                "VulnerabilityID": "CVE-SYNTH-NEW"
              }
            ]
          }
        ],
        "SchemaVersion": 2
      },
      "sha256": "fc6a98031ff91b16b323a757de8777ffa5146db265bd661284572f7960a04481"
    },
    "before_bom": {
      "digest_encoding": "canonical-json-ascii-utf8",
      "document": {
        "bomFormat": "CycloneDX",
        "components": [
          {
            "bom-ref": "synthetic-0",
            "name": "demo",
            "properties": [
              {
                "name": "scan-delta:target",
                "value": "package-lock.json"
              }
            ],
            "purl": "pkg:npm/demo@1.0",
            "type": "library",
            "version": "1.0"
          },
          {
            "bom-ref": "synthetic-1",
            "name": "stable",
            "properties": [
              {
                "name": "scan-delta:target",
                "value": "package-lock.json"
              }
            ],
            "purl": "pkg:npm/stable@2.0",
            "type": "library",
            "version": "2.0"
          },
          {
            "bom-ref": "synthetic-2",
            "name": "removed",
            "properties": [
              {
                "name": "scan-delta:target",
                "value": "package-lock.json"
              }
            ],
            "purl": "pkg:npm/removed@1.0",
            "type": "library",
            "version": "1.0"
          },
          {
            "bom-ref": "synthetic-3",
            "name": "healed",
            "properties": [
              {
                "name": "scan-delta:target",
                "value": "package-lock.json"
              }
            ],
            "purl": "pkg:npm/healed@1.0",
            "type": "library",
            "version": "1.0"
          }
        ],
        "specVersion": "1.5",
        "version": 1
      },
      "sha256": "70535550ac7033a5a4fbf5fe59cac0bf6e09e2bd22d693150b159a6b135cd21c"
    },
    "before_report": {
      "digest_encoding": "canonical-json-ascii-utf8",
      "document": {
        "ArtifactName": "synthetic-demo",
        "ArtifactType": "filesystem",
        "Results": [
          {
            "Class": "lang-pkgs",
            "Target": "package-lock.json",
            "Type": "node-pkg",
            "Vulnerabilities": [
              {
                "InstalledVersion": "1.0",
                "PkgIdentifier": {
                  "PURL": "pkg:npm/demo@1.0"
                },
                "PkgName": "demo",
                "Severity": "HIGH",
                "VulnerabilityID": "CVE-SYNTH-DEMO"
              },
              {
                "InstalledVersion": "2.0",
                "PkgIdentifier": {
                  "PURL": "pkg:npm/stable@2.0"
                },
                "PkgName": "stable",
                "Severity": "HIGH",
                "VulnerabilityID": "CVE-SYNTH-STABLE"
              },
              {
                "InstalledVersion": "1.0",
                "PkgIdentifier": {
                  "PURL": "pkg:npm/removed@1.0"
                },
                "PkgName": "removed",
                "Severity": "HIGH",
                "VulnerabilityID": "CVE-SYNTH-REMOVED"
              },
              {
                "InstalledVersion": "1.0",
                "PkgIdentifier": {
                  "PURL": "pkg:npm/healed@1.0"
                },
                "PkgName": "healed",
                "Severity": "HIGH",
                "VulnerabilityID": "CVE-SYNTH-HEALED"
              }
            ]
          }
        ],
        "SchemaVersion": 2
      },
      "sha256": "4e6c696f35b3f8e1d4c7a242e0faac7e26ed48aa9ab5bb3e9e1c74a38d86d386"
    },
    "metadata": {
      "digest_encoding": "canonical-json-ascii-utf8",
      "document": {
        "after": {
          "database": {
            "id": "sha256:synthetic-db-A"
          },
          "inventory_complete": true,
          "profile": "synthetic-npm-full-unfiltered-v1",
          "report_complete": true,
          "scanner": {
            "name": "trivy",
            "version": "0.58.0"
          }
        },
        "aliases": {
          "GHSA-SYNTH-DEMO": [
            "CVE-SYNTH-DEMO"
          ]
        },
        "before": {
          "database": {
            "id": "sha256:synthetic-db-A"
          },
          "inventory_complete": true,
          "profile": "synthetic-npm-full-unfiltered-v1",
          "report_complete": true,
          "scanner": {
            "name": "trivy",
            "version": "0.58.0"
          }
        },
        "schema_version": 1
      },
      "sha256": "a07e607e80fb476112a8236216dc521e851a42aee31028e49016239571ba756d"
    }
  },
  "evidence_notice": "Scan and inventory evidence only; not proof that all vulnerabilities are found or fixed.",
  "report_family": "trivy",
  "schema_version": 1,
  "summary": {
    "fixed_within_snapshot": 1,
    "introduced": 1,
    "package_removed": 1,
    "persistent": 1,
    "version_changed_still_affected": 1
  },
  "tool": "scan-delta",
  "transitions": [
    {
      "advisory": "CVE-SYNTH-DEMO",
      "after_ids": [
        "GHSA-SYNTH-DEMO"
      ],
      "after_inventory_records": [
        "/after_bom/components/0"
      ],
      "after_inventory_versions": [
        "1.1"
      ],
      "after_records": [
        "/after_report/Results/0/Vulnerabilities/0"
      ],
      "after_versions": [
        "1.1"
      ],
      "aliases": [
        "CVE-SYNTH-DEMO",
        "GHSA-SYNTH-DEMO"
      ],
      "before_ids": [
        "CVE-SYNTH-DEMO"
      ],
      "before_inventory_records": [
        "/before_bom/components/0"
      ],
      "before_records": [
        "/before_report/Results/0/Vulnerabilities/0"
      ],
      "before_versions": [
        "1.0"
      ],
      "classification": "version_changed_still_affected",
      "fixed": false,
      "package": {
        "ecosystem": "npm",
        "name": "demo",
        "path": "",
        "qualifiers": {},
        "target": "package-lock.json"
      },
      "reasons": [],
      "resolution": "observed"
    },
    {
      "advisory": "CVE-SYNTH-HEALED",
      "after_ids": [],
      "after_inventory_records": [
        "/after_bom/components/2"
      ],
      "after_inventory_versions": [
        "1.1"
      ],
      "after_records": [],
      "after_versions": [],
      "aliases": [
        "CVE-SYNTH-HEALED"
      ],
      "before_ids": [
        "CVE-SYNTH-HEALED"
      ],
      "before_inventory_records": [
        "/before_bom/components/3"
      ],
      "before_records": [
        "/before_report/Results/0/Vulnerabilities/3"
      ],
      "before_versions": [
        "1.0"
      ],
      "classification": "fixed_within_snapshot",
      "fixed": true,
      "package": {
        "ecosystem": "npm",
        "name": "healed",
        "path": "",
        "qualifiers": {},
        "target": "package-lock.json"
      },
      "reasons": [],
      "resolution": "scan_evidence"
    },
    {
      "advisory": "CVE-SYNTH-NEW",
      "after_ids": [
        "CVE-SYNTH-NEW"
      ],
      "after_inventory_records": [
        "/after_bom/components/3"
      ],
      "after_inventory_versions": [
        "1.0"
      ],
      "after_records": [
        "/after_report/Results/0/Vulnerabilities/2"
      ],
      "after_versions": [
        "1.0"
      ],
      "aliases": [
        "CVE-SYNTH-NEW"
      ],
      "before_ids": [],
      "before_inventory_records": [],
      "before_records": [],
      "before_versions": [],
      "classification": "introduced",
      "fixed": false,
      "package": {
        "ecosystem": "npm",
        "name": "new",
        "path": "",
        "qualifiers": {},
        "target": "package-lock.json"
      },
      "reasons": [],
      "resolution": "observed"
    },
    {
      "advisory": "CVE-SYNTH-REMOVED",
      "after_ids": [],
      "after_inventory_records": [],
      "after_inventory_versions": [],
      "after_records": [],
      "after_versions": [],
      "aliases": [
        "CVE-SYNTH-REMOVED"
      ],
      "before_ids": [
        "CVE-SYNTH-REMOVED"
      ],
      "before_inventory_records": [
        "/before_bom/components/2"
      ],
      "before_records": [
        "/before_report/Results/0/Vulnerabilities/2"
      ],
      "before_versions": [
        "1.0"
      ],
      "classification": "package_removed",
      "fixed": false,
      "package": {
        "ecosystem": "npm",
        "name": "removed",
        "path": "",
        "qualifiers": {},
        "target": "package-lock.json"
      },
      "reasons": [],
      "resolution": "inventory_evidence"
    },
    {
      "advisory": "CVE-SYNTH-STABLE",
      "after_ids": [
        "CVE-SYNTH-STABLE"
      ],
      "after_inventory_records": [
        "/after_bom/components/1"
      ],
      "after_inventory_versions": [
        "2.0"
      ],
      "after_records": [
        "/after_report/Results/0/Vulnerabilities/1"
      ],
      "after_versions": [
        "2.0"
      ],
      "aliases": [
        "CVE-SYNTH-STABLE"
      ],
      "before_ids": [
        "CVE-SYNTH-STABLE"
      ],
      "before_inventory_records": [
        "/before_bom/components/1"
      ],
      "before_records": [
        "/before_report/Results/0/Vulnerabilities/1"
      ],
      "before_versions": [
        "2.0"
      ],
      "classification": "persistent",
      "fixed": false,
      "package": {
        "ecosystem": "npm",
        "name": "stable",
        "path": "",
        "qualifiers": {},
        "target": "package-lock.json"
      },
      "reasons": [],
      "resolution": "observed"
    }
  ]
}
```
