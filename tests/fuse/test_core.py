import hashlib
import json
from pathlib import Path
import unittest

from vulnwrench.fuse import InputError, Report, dumps, merge_reports, read_report, render_markdown
from vulnwrench.fuse.identity import package_identity, parse_purl

ROOT = Path(__file__).resolve().parents[2]


def trivy(vulns, type_="node-pkg"):
    return {"Results": [{"Target": "app/package-lock.json", "Type": type_, "Vulnerabilities": vulns}]}


def tv(id_="CVE-DEMO", name="demo", version="1.0", **extra):
    return {"VulnerabilityID": id_, "PkgName": name, "InstalledVersion": version, **extra}


def grype(id_="GHSA-demo", aliases=(), **extra):
    return {"matches": [{"vulnerability": {"id": id_, "severity": "High", **extra},
                         "relatedVulnerabilities": [{"id": a} for a in aliases],
                         "artifact": {"name": "demo", "version": "1.0", "type": "npm"}}]}


def osv(vulns, package=None):
    return {"results": [{"source": {"path": "app/package-lock.json", "type": "lockfile"},
                         "packages": [{"package": package or {"name": "demo", "version": "1.0", "ecosystem": "npm"},
                                       "vulnerabilities": vulns}]}]}


def merge(*items):
    return merge_reports(Report.from_document(scanner, document) for scanner, document in items)


def resolve(document, pointer):
    for part in pointer.split("/")[1:]:
        document = document[int(part)] if isinstance(document, list) else document[part]
    return document


class CoreTests(unittest.TestCase):
    def test_real_shape_examples_conserve_observations_and_digests(self):
        reports = [read_report(s, ROOT / "examples" / "fuse" / (s + ".json")) for s in ("trivy", "grype", "osv")]
        result = merge_reports(reports)
        self.assertEqual((result["inputCount"], result["observationCount"], result["findingCount"]), (3, 6, 4))
        self.assertEqual(sum(f["observationCount"] for f in result["findings"]), 6)
        sources = {s["sourceId"]: s for s in result["inputs"]}
        seen = set()
        for f in result["findings"]:
            for observation in f["observations"]:
                source = sources[observation["sourceId"]]
                original = resolve(source["rawReport"], observation["pointer"])
                self.assertIsInstance(original, dict)
                self.assertNotIn(observation["observationId"], seen)
                seen.add(observation["observationId"])
        for source in sources.values():
            raw = Path(source["input"]).read_bytes()
            self.assertEqual(source["sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(source["byteCount"], len(raw))
            self.assertEqual(source["observationCount"], 2)

    def test_alias_bridge_is_transitive_across_reports(self):
        result = merge(("trivy", trivy([tv("CVE-A")])),
                       ("grype", grype("GHSA-B", ["CVE-A"])),
                       ("osv", osv([{"id": "OSV-C", "aliases": ["GHSA-B"]}])))
        self.assertEqual(result["findingCount"], 1)
        f = result["findings"][0]
        self.assertEqual(f["ids"], ["CVE-A", "GHSA-B", "OSV-C"])
        self.assertEqual(f["observedBy"], ["grype", "osv", "trivy"])
        self.assertEqual(len(result["aliasEdges"]), 2)
        self.assertEqual({o["originalId"] for o in f["observations"]}, set(f["ids"]))

    def test_aliases_are_global_but_package_scopes_are_separate(self):
        result = merge(("trivy", trivy([tv("A"), tv("B", version="2.0")])),
                       ("osv", osv([{"id": "A", "aliases": ["B"]}])))
        self.assertEqual(result["findingCount"], 2)
        self.assertTrue(all(f["ids"] == ["A", "B"] for f in result["findings"]))

    def test_same_titles_and_same_name_do_not_imply_aliases(self):
        result = merge(("trivy", trivy([tv("A", Title="identical"), tv("B", Title="identical")])))
        self.assertEqual(result["findingCount"], 2)
        self.assertEqual(result["aliasEdges"], [])

    def test_separate_ecosystem_version_qualifier_subpath_and_namespace(self):
        purls = ["pkg:npm/demo@1.0", "pkg:pypi/demo@1.0", "pkg:npm/demo@2.0",
                 "pkg:npm/demo@1.0?arch=arm64", "pkg:npm/demo@1.0?arch=amd64",
                 "pkg:npm/demo@1.0#lib", "pkg:npm/%40scope/demo@1.0"]
        result = merge(("trivy", trivy([tv(PkgIdentifier={"PURL": p}, version="2.0" if "@2.0" in p else "1.0")
                                         for p in purls], type_=None)))
        self.assertEqual(result["findingCount"], len(purls))
        self.assertEqual(len({f["package"]["identity"] for f in result["findings"]}), len(purls))

    def test_unknown_identity_is_isolated_not_discarded(self):
        result = merge(("trivy", trivy([tv(), tv()], type_="vendor-unknown")),
                       ("osv", osv([{"id": "CVE-DEMO"}], {"name": "demo", "version": "1.0", "ecosystem": "vendor-unknown"})))
        self.assertEqual((result["findingCount"], result["observationCount"]), (3, 3))
        for f in result["findings"]:
            self.assertFalse(f["package"]["known"])
            self.assertIsNone(f["package"]["identity"])
            self.assertIsNotNone(f["package"]["reason"])

    def test_os_package_without_purl_is_unknown(self):
        p = package_identity("libdemo", "1.0-1", "deb")
        self.assertFalse(p["known"])
        self.assertEqual(p["version"], "1.0-1")

    def test_os_purl_requires_distribution_evidence(self):
        bare = package_identity("demo", "1.0", "deb", "pkg:deb/demo@1.0")
        self.assertFalse(bare["known"])
        self.assertEqual(bare["reason"], "missing-os-distribution")
        first = package_identity("demo", "1.0", "deb", "pkg:deb/debian/demo@1.0?distro=debian-12")
        second = package_identity("demo", "1.0", "deb", "pkg:deb/ubuntu/demo@1.0?distro=ubuntu-24.04")
        qualified = package_identity("demo", "1.0", "deb", "pkg:deb/demo@1.0?distro=debian-12")
        self.assertTrue(first["known"] and second["known"] and qualified["known"])
        self.assertNotEqual(first["identity"], second["identity"])

    def test_unknown_purl_type_is_preserved_and_isolated(self):
        purl = "pkg:vendor-special/demo@1.0?flavor=custom#source"
        result = merge(("trivy", trivy([tv(PkgIdentifier={"PURL": purl}), tv(PkgIdentifier={"PURL": purl})], None)))
        self.assertEqual(result["findingCount"], 2)
        self.assertEqual(result["findings"][0]["package"]["purl"], purl)

    def test_missing_scanner_does_not_indicate_safety(self):
        f = merge(("trivy", trivy([tv()])), ("grype", {"matches": []}))["findings"][0]
        self.assertEqual(f["scannerPresence"], {"trivy": "observed", "grype": "not_observed", "osv": "not_supplied"})
        self.assertEqual(set(f["inputPresence"].values()), {"observed", "not_observed"})

    def test_conflicts_preserve_raw_evidence(self):
        t = trivy([tv("A", Severity="HIGH", FixedVersion="1.1, 1.2")])
        g = grype("A", severity="Critical", fix={"versions": [], "state": "not-fixed"})
        f = merge(("trivy", t), ("grype", g))["findings"][0]
        self.assertEqual(f["severityValues"], ["CRITICAL", "HIGH"])
        self.assertTrue(f["severityConflict"])
        self.assertTrue(f["fixVersionConflict"])
        self.assertTrue(f["fixStateConflict"])
        self.assertEqual(f["fixVersions"], ["1.1", "1.2"])
        self.assertEqual(f["severityAssessment"], "conflict")
        self.assertEqual({o["rawSeverities"][0] for o in f["observations"]}, {"HIGH", "Critical"})

    def test_unknown_values_are_not_votes(self):
        f = merge(("trivy", trivy([tv("A", Severity="VENDOR-MAX")])), ("grype", grype("A")))["findings"][0]
        self.assertFalse(f["severityConflict"])
        self.assertEqual(f["severityAssessment"], "partial")
        self.assertEqual(f["unknownSeverityObservationCount"], 1)
        self.assertEqual(f["severityValues"], ["HIGH"])
        self.assertFalse(f["fixConflict"])
        self.assertIn(["VENDOR-MAX"], [o["rawSeverities"] for o in f["observations"]])

    def test_osv_cvss_vector_is_not_guessed_as_label(self):
        v = {"id": "OSV-A", "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/synthetic"}]}
        f = merge(("osv", osv([v])))["findings"][0]
        self.assertEqual(f["severityAssessment"], "unknown")
        self.assertEqual(f["observations"][0]["rawSeverities"], v["severity"])

    def test_conflicting_osv_metadata_is_visible(self):
        v = {"id": "OSV-A", "database_specific": {"severity": "HIGH"}, "ecosystem_specific": {"severity": "LOW"}}
        f = merge(("osv", osv([v])))["findings"][0]
        self.assertTrue(f["severityConflict"])
        self.assertEqual(f["severityValues"], ["HIGH", "LOW"])

    def test_osv_fix_is_scoped_to_matching_affected_package(self):
        def affected(name, version):
            return {"package": {"ecosystem": "npm", "name": name},
                    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": version}]}]}
        v = {"id": "OSV-A", "affected": [affected("demo", "1.1"), affected("other", "9.9")]}
        f = merge(("osv", osv([v])))["findings"][0]
        self.assertEqual(f["fixVersions"], ["1.1"])
        self.assertEqual(f["observations"][0]["fix"]["matchedAffectedIndices"], [0])
        self.assertIn("no-range-evaluation", f["observations"][0]["fix"]["basis"])

    def test_osv_affected_missing_package_is_retained_not_guessed(self):
        v = {"id": "OSV-A", "affected": [{"ranges": [{"events": [{"fixed": "9.9"}]}]}]}
        r = merge(("osv", osv([v])))
        self.assertEqual(r["findings"][0]["fixVersions"], [])
        self.assertEqual(resolve(r["inputs"][0]["rawReport"], "/results/0/packages/0/vulnerabilities/0"), v)

    def test_empty_recognized_reports(self):
        for scanner, doc in [("trivy", {"Results": []}), ("trivy", {"Results": None}),
                             ("trivy", {"Results": [{"Target": "empty"}]}),
                             ("grype", {"matches": []}), ("osv", {"results": []})]:
            with self.subTest(scanner=scanner, doc=doc):
                r = merge((scanner, doc))
                self.assertEqual((r["findingCount"], r["observationCount"]), (0, 0))
                self.assertEqual(r["inputs"][0]["rawReport"], doc)

    def test_unknown_fields_retained_at_every_level(self):
        t = trivy([tv(VendorExtension={"new": [1, 2, 3]})])
        t["Extension"] = {"custom": True}
        t["Results"][0]["Metadata"] = ["opaque"]
        self.assertEqual(merge(("trivy", t))["inputs"][0]["rawReport"], t)

    def test_repeat_inputs_are_separate_observations(self):
        t = trivy([tv()])
        r = merge(("trivy", t), ("trivy", t))
        self.assertEqual((r["inputCount"], r["findingCount"], r["observationCount"]), (2, 1, 2))
        self.assertEqual(len(r["findings"][0]["inputPresence"]), 2)

    def test_deterministic_input_order(self):
        reports = [Report.from_document("trivy", trivy([tv("A")])), Report.from_document("grype", grype("A")),
                   Report.from_document("osv", osv([{"id": "B", "aliases": ["A"]}]))]
        self.assertEqual(dumps(merge_reports(reports)), dumps(merge_reports(reversed(reports))))

    def test_markdown_escapes_untrusted_content(self):
        t = trivy([tv("A|[click](https://evil.invalid)<script>`x`", name="demo")])
        t["Results"][0]["Target"] = "<img src=x onerror=alert(1)>|[x](url)"
        md = render_markdown(merge(("trivy", t)))
        self.assertNotIn("<script>", md)
        self.assertNotIn("<img", md)
        self.assertNotIn("[click]", md)
        self.assertIn("&#124;", md)
        self.assertIn("&lt;img", md)
        self.assertNotIn("&&#35;", md)

    def test_unsupported_shapes(self):
        for scanner, doc in [("trivy", {}), ("trivy", {"Results": {},}), ("trivy", {"Results": [], "matches": []}),
                             ("grype", {"matches": None}), ("osv", {"results": None}),
                             ("osv", {"results": [{"packages": [{"package": {"name": "demo", "version": "1", "ecosystem": "npm"}, "groups": []}]}]}),
                             ("trivy", []), ("grype", {"runs": []})]:
            with self.subTest(scanner=scanner, doc=doc), self.assertRaises(InputError):
                merge((scanner, doc))

    def test_malformed_observations_are_errors(self):
        for vuln in [tv(name=None), tv(version=None), tv(name=""), tv(version=12), tv(version="1 0"),
                     tv(Severity=3), tv(FixedVersion=[]), tv(PkgIdentifier=[]),
                     tv(PkgIdentifier={"PURL": "pkg:npm/demo@2"}),
                     tv(name="different", PkgIdentifier={"PURL": "pkg:npm/demo@1.0"}),
                     tv(PkgIdentifier={"PURL": "pkg:pypi/demo@1.0"})]:
            with self.subTest(vuln=vuln), self.assertRaises(InputError):
                merge(("trivy", trivy([vuln])))
        for g in [grype(fix=[]), grype(fix={"versions": [3]}), grype(fix={"state": False})]:
            with self.subTest(g=g), self.assertRaises(InputError):
                merge(("grype", g))
        for v in [{"id": None}, {"id": "X", "aliases": "A"}, {"id": "X", "severity": [3]},
                  {"id": "X", "severity": [{"type": "CVSS_V3", "score": 9.8}]},
                  {"id": "X", "affected": [{"ranges": [{"events": [{"fixed": 12}]}]}]}]:
            with self.subTest(v=v), self.assertRaises(InputError):
                merge(("osv", osv([v])))

    def test_no_reports_and_unsupported_scanner(self):
        with self.assertRaises(InputError):
            merge_reports([])
        with self.assertRaises(InputError):
            merge(("other", {}))


class IdentityTests(unittest.TestCase):
    def test_normalization_and_fallback_equivalence(self):
        cases = [
            ("Demo_pkg.Name", "PyPI", "pkg:pypi/demo-pkg-name@1.0"),
            ("@scope/demo", "node-pkg", "pkg:npm/%40scope/demo@1.0"),
            ("org.example:Demo", "java-archive", "pkg:maven/org.example/Demo@1.0"),
            ("example.org/team/demo", "Go", "pkg:golang/example.org/team/demo@1.0"),
            ("Demo", "NuGet", "pkg:nuget/demo@1.0"),
            ("demo", "RubyGems", "pkg:gem/demo@1.0"),
            ("demo", "crates.io", "pkg:cargo/demo@1.0"),
        ]
        for name, eco, expected in cases:
            with self.subTest(eco=eco):
                self.assertEqual(package_identity(name, "1.0", eco)["identity"], expected)
                self.assertEqual(package_identity(name, "1.0", eco, expected)["identity"], expected)

    def test_malformed_fallback_namespace(self):
        for name in ["example.org//demo", "example.org/../demo", "example.org/./demo"]:
            with self.subTest(name=name), self.assertRaises(InputError):
                package_identity(name, "1.0", "Go")

    def test_purl_canonical_qualifiers_version_and_subpath(self):
        p = package_identity("demo", "1.0+vendor:1", "npm",
                             "pkg:NPM/DEMO@1.0%2Bvendor%3A1?Distro=debian%3A12&arch=arm64#lib/file")
        self.assertEqual(p["identity"], "pkg:npm/demo@1.0%2Bvendor%3A1?arch=arm64&distro=debian%3A12#lib/file")
        self.assertEqual(p["version"], "1.0+vendor:1")
        self.assertEqual(p["qualifiers"], {"arch": "arm64", "distro": "debian:12"})
        self.assertEqual(p["subpath"], "lib/file")

    def test_purl_fills_version_and_identity(self):
        p = package_identity(None, None, None, "pkg:npm/demo@1.0")
        self.assertEqual(p["identity"], "pkg:npm/demo@1.0")
        p = package_identity("demo", "1.0", None, "pkg:npm/demo")
        self.assertEqual(p["identity"], "pkg:npm/demo@1.0")

    def test_versions_are_not_semver_coerced(self):
        ids = [package_identity("demo", v, "npm")["identity"] for v in ("1", "1.0", "v1.0")]
        self.assertEqual(len(set(ids)), 3)

    def test_malformed_purls(self):
        for purl in ["https://example.invalid/demo", "pkg:npm/", "pkg:npm/demo@", "pkg:npm/demo@1@2",
                     "pkg:npm/demo@1?arch=", "pkg:npm/demo@1?arch=x&ARCH=y", "pkg:npm/demo@1?x=%zz",
                     "pkg:npm/demo@1#../lib", "pkg:npm/demo@1#", "pkg:npm//demo@1", "pkg:npm/demo@1#lib//file",
                     "pkg:npm/demo@1?", "pkg:npm/demo@1?x=%ff", "pkg:npm/demo@1?x=%00",
                     "pkg:npm/demo@1?x=y?z=q", "pkg:123/demo@1", "pkg:npm/a%2Fb@1", "pkg:pypi/namespace/demo@1",
                     "pkg:npm/invalid-scope/demo@1", "pkg:maven/demo@1"]:
            with self.subTest(purl=purl), self.assertRaises(InputError):
                parse_purl(purl)


if __name__ == "__main__":
    unittest.main()
