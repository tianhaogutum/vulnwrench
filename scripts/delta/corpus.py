"""Small synthetic, hand-labelled scenarios; no real scan or advisory data."""
from copy import deepcopy
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def vulnerability(name="demo", version="1.0", advisory="CVE-SYNTH-001", path=""):
    result = {"VulnerabilityID": advisory, "PkgName": name, "InstalledVersion": version,
              "PkgIdentifier": {"PURL": f"pkg:npm/{name}@{version}"}, "Severity": "HIGH"}
    if path:
        result["PkgPath"] = path
    return result


def report(findings, target="package-lock.json"):
    return {"SchemaVersion": 2, "ArtifactName": "synthetic-demo", "ArtifactType": "filesystem",
            "Results": [{"Target": target, "Class": "lang-pkgs", "Type": "node-pkg",
                         "Vulnerabilities": findings}]}


def bom(packages, target="package-lock.json"):
    components = []
    for i, (name, version, path) in enumerate(packages):
        props = [{"name": "scan-delta:target", "value": target}]
        if path:
            props.append({"name": "scan-delta:package-path", "value": path})
        components.append({"type": "library", "bom-ref": f"synthetic-{i}", "name": name,
                           "version": version, "purl": f"pkg:npm/{name}@{version}", "properties": props})
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": components}


def metadata():
    side = {"scanner": {"name": "trivy", "version": "0.58.0"}, "database": {"id": "sha256:synthetic-db-A"},
            "profile": "synthetic-npm-full-unfiltered-v1", "report_complete": True, "inventory_complete": True}
    return {"schema_version": 1, "before": deepcopy(side), "after": deepcopy(side), "aliases": {}}


def basic():
    return [report([vulnerability()]), report([vulnerability()]),
            bom([("demo", "1.0", "")]), bom([("demo", "1.0", "")]), metadata()]


def cases():
    result = []

    def add(name, docs, expected):
        result.append((name, docs, set(expected.split(","))))

    docs = basic()
    add("unchanged", docs, "persistent")
    docs = basic()
    docs[1] = report([vulnerability(advisory="GHSA-SYNTH-001")])
    docs[4]["aliases"] = {"GHSA-SYNTH-001": ["CVE-SYNTH-001"]}
    add("alias-only", docs, "persistent")
    docs = basic()
    docs[1] = report([vulnerability(version="1.1", advisory="GHSA-SYNTH-001")])
    docs[3] = bom([("demo", "1.1", "")])
    docs[4]["aliases"] = {"GHSA-SYNTH-001": ["CVE-SYNTH-001"]}
    add("alias-and-upgrade", docs, "version_changed_still_affected")
    docs = basic()
    docs[1] = report([vulnerability(version="1.1")])
    docs[3] = bom([("demo", "1.1", "")])
    add("upgrade-still-affected", docs, "version_changed_still_affected")
    docs = basic()
    docs[1] = report([])
    docs[3] = bom([])
    add("package-removal", docs, "package_removed")
    docs = basic()
    docs[1] = report([])
    docs[3] = bom([("demo", "1.1", "")])
    add("same-snapshot-fix", docs, "fixed_within_snapshot")
    docs = basic()
    docs[1] = report([])
    docs[4]["after"]["database"]["id"] = "sha256:synthetic-db-B"
    add("changed-database", docs, "no_longer_reported")
    docs = basic()
    docs[1] = report([])
    docs[4]["after"]["database"] = {}
    add("missing-database", docs, "no_longer_reported")
    docs = basic()
    docs[1] = report([])
    docs[2] = bom([])
    add("missing-inventory-record", docs, "no_longer_reported")
    docs = basic()
    docs[1] = report([])
    docs[3] = bom([])
    docs[4]["after"]["inventory_complete"] = False
    add("incomplete-inventory", docs, "no_longer_reported")
    docs = basic()
    docs[1] = {"SchemaVersion": 2, "Results": []}
    add("missing-target-coverage", docs, "no_longer_reported")
    docs = basic()
    docs[1] = report([])
    docs[4]["after"]["profile"] = "filtered-synthetic"
    add("changed-profile", docs, "no_longer_reported")
    docs = basic()
    docs[0] = report([])
    add("newly-observed", docs, "introduced")
    docs = basic()
    docs[0] = report([vulnerability(path="node_modules/demo"), vulnerability(path="vendor/demo")])
    docs[1] = report([vulnerability(path="node_modules/demo")])
    docs[2] = bom([("demo", "1.0", "node_modules/demo"), ("demo", "1.0", "vendor/demo")])
    docs[3] = deepcopy(docs[2])
    add("separate-package-copies", docs, "persistent,fixed_within_snapshot")
    return result


def example_documents():
    before, after = [], []
    old_packages, new_packages = [], []
    for name, old, new, old_id, new_id in [
        ("demo", "1.0", "1.1", "CVE-SYNTH-DEMO", "GHSA-SYNTH-DEMO"),
        ("stable", "2.0", "2.0", "CVE-SYNTH-STABLE", "CVE-SYNTH-STABLE"),
        ("removed", "1.0", None, "CVE-SYNTH-REMOVED", None),
        ("healed", "1.0", "1.1", "CVE-SYNTH-HEALED", None),
        ("new", None, "1.0", None, "CVE-SYNTH-NEW"),
    ]:
        if old:
            old_packages.append((name, old, ""))
        if new:
            new_packages.append((name, new, ""))
        if old_id:
            before.append(vulnerability(name, old, old_id))
        if new_id:
            after.append(vulnerability(name, new, new_id))
    meta = metadata()
    meta["aliases"] = {"GHSA-SYNTH-DEMO": ["CVE-SYNTH-DEMO"]}
    return [report(before), report(after), bom(old_packages), bom(new_packages), meta]


if __name__ == "__main__":
    for filename, document in zip(("before.json", "after.json", "before-bom.json", "after-bom.json", "scans.json"), example_documents()):
        (ROOT / "examples" / "delta" / filename).write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
