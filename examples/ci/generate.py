"""Regenerate the synthetic examples/ci fixtures: fictional acme-* packages, fictional advisory IDs.

Usage: python3 examples/ci/generate.py   (writes next to this file; then rebuild baseline.json with
`vulnwrench fuse merge` as shown in examples/ci/README.md)
"""
import json
import sys
from pathlib import Path

out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent
(out / "baseline").mkdir(parents=True, exist_ok=True)

# key: (cve or None, ghsa, osv_id, name, eco, version, fixes{scanner: [..]}, severity, scanners)
V = {
 "K1": ("CVE-2099-1001", "GHSA-w1aa-c4hq-0001", None, "acme-http", "npm", "2.1.0", "2.1.4", "HIGH", "tgo"),
 "K2": ("CVE-2099-1002", "GHSA-w1aa-c4hq-0002", None, "acme-yaml", "npm", "1.4.2", "1.4.5", "MEDIUM", "tgo"),
 "K3": ("CVE-2099-1003", "GHSA-w1aa-c4hq-0003", None, "acme-jwt", "npm", "3.0.0", "3.0.2", "CRITICAL", "tg"),
 "K4": ("CVE-2099-1004", "GHSA-w1aa-c4hq-0004", "PYSEC-2099-4", "acme-xml", "pypi", "0.9.1", "0.9.4", "HIGH", "to"),
 "K5": ("CVE-2099-1005", "GHSA-w1aa-c4hq-0005", None, "acme-tar", "npm", "1.0.3", None, "LOW", "tgo"),
 "K6": ("CVE-2099-1006", "GHSA-w1aa-c4hq-0006", "PYSEC-2099-6", "acme-img", "pypi", "5.2.0", "5.3.0", "MEDIUM", "go"),
 "G1": ("CVE-2099-0901", "GHSA-w0zz-c4hq-0901", None, "acme-old", "npm", "1.0.0", "1.0.1", "HIGH", "tgo"),
 "G2": ("CVE-2099-0902", "GHSA-w0zz-c4hq-0902", None, "acme-qs", "npm", "6.0.0", "6.0.1", "MEDIUM", "tg"),
 "N1": ("CVE-2099-2001", "GHSA-w2bb-c4hq-2001", None, "acme-router", "npm", "4.2.0", "4.2.3", "HIGH", "tgo"),
 "N2": ("CVE-2099-2002", "GHSA-w2bb-c4hq-2002", None, "acme-session", "npm", "1.8.0", {"t": "1.8.4", "g": "1.9.0", "o": "1.8.4"}, "CRITICAL", "tgo"),
 "N3": ("CVE-2099-2003", "GHSA-w2bb-c4hq-2003", "PYSEC-2099-23", "acme-csv", "pypi", "2.0.1", "2.0.2", "MEDIUM", "tgo"),
 "N4": ("CVE-2099-2004", "GHSA-w2bb-c4hq-2004", None, "acme-log", "npm", "7.1.0", "7.1.1", "LOW", "tg"),
 "N5": (None, "GHSA-w2bb-c4hq-2005", None, "acme-color", "npm", "0.3.0", "0.3.1", "MEDIUM", "go"),
 "N6": ("CVE-2099-2006", "GHSA-w2bb-c4hq-2006", "PYSEC-2099-26", "acme-zip", "pypi", "3.3.3", "3.4.0", "HIGH", "tgo"),
 "N7": ("CVE-2099-2007", "GHSA-w2bb-c4hq-2007", None, "acme-auth", "npm", "2.2.0", "2.2.1", "HIGH", "tgo"),
 "N8": ("CVE-2099-2008", "GHSA-w2bb-c4hq-2008", "PYSEC-2099-28", "acme-dns", "pypi", "1.1.0", None, "MEDIUM", "go"),
}
TARGET = {"npm": "package-lock.json", "pypi": "requirements.txt"}
SEV_G = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}

def fix(v, s):
    f = v[6]
    return f.get(s) if isinstance(f, dict) else f

def purl(v):
    return f"pkg:{v[4]}/{v[3]}@{v[5]}"

def trivy(keys, extra_targets=()):
    results = {}
    for k in keys:
        v = V[k]
        if "t" not in v[8]: continue
        for target in (TARGET[v[4]], *[t for kk, t in extra_targets if kk == k]):
            vuln = {"VulnerabilityID": v[0], "PkgName": v[3], "PkgIdentifier": {"PURL": purl(v)},
                    "InstalledVersion": v[5], "Severity": v[7], "Title": "Synthetic advisory for a fictional package"}
            if fix(v, "t"): vuln["FixedVersion"] = fix(v, "t")
            results.setdefault(target, (v[4], []))[1].append(vuln)
    return {"SchemaVersion": 2, "ArtifactName": "acme-shop", "ArtifactType": "filesystem",
            "Results": [{"Target": t, "Class": "lang-pkgs", "Type": "npm" if eco == "npm" else "pip", "Vulnerabilities": vs}
                        for t, (eco, vs) in results.items()]}

def grype(keys):
    matches = []
    for k in keys:
        v = V[k]
        if "g" not in v[8]: continue
        f = fix(v, "g")
        m = {"vulnerability": {"id": v[1], "severity": SEV_G[v[7]], "namespace": "github:language:" + ("javascript" if v[4] == "npm" else "python"),
                               "fix": {"versions": [f], "state": "fixed"} if f else {"versions": [], "state": "not-fixed"}},
             "relatedVulnerabilities": [{"id": v[0], "namespace": "nvd:cpe"}] if v[0] else [],
             "matchDetails": [{"type": "exact-direct-match", "matcher": "synthetic"}],
             "artifact": {"name": v[3], "version": v[5], "type": "npm" if v[4] == "npm" else "python", "purl": purl(v),
                          "locations": [{"path": "/" + TARGET[v[4]]}]}}
        matches.append(m)
    return {"descriptor": {"name": "grype", "version": "synthetic", "configuration": {}},
            "source": {"type": "directory", "target": "/src/acme-shop"}, "matches": matches}

def osv(keys):
    results = {}
    for k in keys:
        v = V[k]
        if "o" not in v[8]: continue
        ident = v[2] or v[1]
        aliases = [a for a in (v[0], v[1]) if a and a != ident]
        f = fix(v, "o")
        eco = "npm" if v[4] == "npm" else "PyPI"
        events = [{"introduced": "0"}] + ([{"fixed": f}] if f else [])
        vuln = {"id": ident, "aliases": aliases, "summary": "Synthetic advisory for a fictional package",
                "affected": [{"package": {"ecosystem": eco, "name": v[3]}, "ranges": [{"type": "ECOSYSTEM", "events": events}]}],
                "database_specific": {"severity": v[7]}}
        results.setdefault(TARGET[v[4]], []).append({"package": {"name": v[3], "version": v[5], "ecosystem": eco},
                                                    "vulnerabilities": [vuln]})
    return {"results": [{"source": {"path": t, "type": "lockfile"}, "packages": ps} for t, ps in results.items()]}

def dump(path, doc):
    path.write_text(json.dumps(doc, indent=2) + "\n")

base = ["K1", "K2", "K3", "K4", "K5", "K6", "G1", "G2"]
cur = ["K1", "K2", "K3", "K4", "K5", "K6", "N1", "N2", "N3", "N4", "N5", "N6", "N7", "N8"]
dump(out / "baseline/trivy.json", trivy(base))
dump(out / "baseline/grype.json", grype(base))
dump(out / "baseline/osv.json", osv(base))
dump(out / "trivy.json", trivy(cur, extra_targets=[("N1", "packages/admin/package-lock.json")]))
dump(out / "grype.json", grype(cur))
dump(out / "osv.json", osv(cur))

epss = {"CVE-2099-1001": 0.04, "CVE-2099-1002": 0.31, "CVE-2099-1003": 0.02, "CVE-2099-1004": 0.05,
        "CVE-2099-1005": 0.01, "CVE-2099-1006": 0.02, "CVE-2099-0901": 0.03, "CVE-2099-0902": 0.01,
        "CVE-2099-2001": 0.12, "CVE-2099-2002": 0.62, "CVE-2099-2003": 0.03, "CVE-2099-2004": 0.01,
        "CVE-2099-2006": 0.71, "CVE-2099-2007": 0.09, "CVE-2099-2008": 0.02}
lines = ["#model_version:synthetic,score_date:2026-11-11T00:00:00+0000",
         "# Synthetic fixture for examples/ci: fictional CVE IDs, not FIRST EPSS data.", "cve,epss,percentile"]
lines += [f"{c},{s:.5f},{min(0.99, s + 0.5):.5f}" for c, s in sorted(epss.items())]
(out / "epss.csv").write_text("\n".join(lines) + "\n")
kev = {"title": "Synthetic KEV catalog for examples/ci; not CISA data", "catalogVersion": "2026.11.10",
       "dateReleased": "2026-11-10T00:00:00.000Z", "count": 1,
       "vulnerabilities": [{"cveID": "CVE-2099-2001", "vendorProject": "Synthetic", "product": "acme-router",
                            "vulnerabilityName": "Synthetic entry", "dateAdded": "2026-11-09",
                            "shortDescription": "Fictional entry for a fictional package", "requiredAction": "Test only",
                            "dueDate": "2026-11-30", "knownRansomwareCampaignUse": "Unknown", "notes": "Synthetic fixture"}]}
dump(out / "kev.json", kev)
(out / ".trivyignore").write_text("""# Synthetic exceptions for the vulnwrench ci example (fictional IDs).
CVE-2099-1004 exp:2026-10-31
CVE-2099-2006 exp:2026-11-30
CVE-2099-0777
""")
(out / "osv-scanner.toml").write_text("""# Synthetic exceptions for the vulnwrench ci example (fictional IDs).
[[IgnoredVulns]]
id = "PYSEC-2099-28"
effectiveUntil = 2027-03-31
reason = "acme-dns is only used by the offline test harness"
""")
