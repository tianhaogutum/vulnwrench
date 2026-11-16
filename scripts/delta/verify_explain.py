#!/usr/bin/env python3
"""Exercise synthetic explain fixtures through a source or installed CLI."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
FLAGS = ("--before", "--after", "--before-bom", "--after-bom", "--metadata")


def verify(command=None, cwd=ROOT):
    command = command or [sys.executable, "-m", "vulnwrench", "delta"]
    cases = json.loads((ROOT / "examples/delta/explain/cases.json").read_text())

    def run(mode, paths, *extra, expected=0):
        args = [*command, mode]
        for flag, path in zip(FLAGS, paths):
            args.extend([flag, str(path)])
        result = subprocess.run(args + list(extra), cwd=cwd, capture_output=True, text=True, timeout=60)
        assert result.returncode == expected, result.stderr
        return result

    for case in cases:
        paths = [ROOT / "examples" / "delta" / name for name in case["inputs"]]
        batch = json.loads(run("compare", paths).stdout)
        explained = json.loads(run("explain", paths, "--advisory", case["advisory"]).stdout)
        explanation = explained.pop("explanation")
        assert explained == batch, case["name"] + ": explain changed batch evidence or decisions"
        assert "unknown_findings" not in explanation
        finding, = explanation["findings"]
        expected = case["expected"]
        assert finding["decision"]["classification"] == expected["classification"], case["name"]
        assert finding["decision"]["fixed"] == (expected["classification"] == "fixed_within_snapshot")
        assert set(expected["reason_codes"]) <= {r["code"] for r in finding["reasons"]}
        assert set(expected["failed_prerequisites"]) == {p["code"] for p in finding["fix_prerequisites"] if not p["satisfied"]}
        documents = {key: entry["document"] for key, entry in explained["evidence"].items()}
        pointers = set()
        for item in finding["reasons"] + finding["fix_prerequisites"] + [finding["decision"]]:
            assert item["sources"]
            for pointer in item["sources"]:
                value = documents
                for part in pointer.lstrip("/").split("/"):
                    part = part.replace("~1", "/").replace("~0", "~")
                    value = value[int(part)] if isinstance(value, list) else value[part]
                pointers.add(pointer)
        assert set(expected["source_references"]) <= pointers

    paths = [ROOT / "examples" / "delta" / name for name in cases[0]["inputs"]]
    markdown = run("explain", paths, "--advisory", "CVE-SYNTH-001", "--format", "markdown").stdout
    assert '"fix_prerequisites"' in markdown and '"explicit_alias_equivalence"' in markdown
    assert "## Finding explanations" in markdown and "| Fix prerequisite | Satisfied |" in markdown
    with tempfile.TemporaryDirectory(prefix="vulnwrench-delta-explain-") as folder:
        output = Path(folder) / "explanation.json"
        output.write_text("previous output", encoding="utf-8")
        failure = run("explain", paths, "--advisory", "SYNTHETIC_SECRET_UNKNOWN", "--output", str(output), expected=2)
        assert not failure.stdout and "SYNTHETIC_SECRET" not in failure.stderr and "Traceback" not in failure.stderr
        assert output.read_text() == "previous output"
        run("explain", paths, "--advisory", "CVE-SYNTH-001", "--output", str(output))
        assert json.loads(output.read_text())["explanation"]["findings"][0]["decision"]["fixed"] is False
        assert not list(Path(folder).glob(".vulnwrench-delta-*"))

    unknown_cases = json.loads((ROOT / "examples/delta/explain/unknown-cases.json").read_text())
    for case in unknown_cases:
        paths = [ROOT / "examples" / "delta" / name for name in case["inputs"]]
        batch = json.loads(run("compare", paths).stdout)
        explained = json.loads(run("explain", paths, "--advisory", case["advisory"]).stdout)
        explanation = explained.pop("explanation")
        assert explained == batch, case["name"] + ": unknown explain changed batch result"
        assert [f["decision"]["classification"] for f in explanation["findings"]] == case["expected"]["classifications"]
        assert not batch["comparable"] and "report_identity_unknown" in batch["comparability_reasons"]
        assert not any(row["fixed"] or row["classification"] == "package_removed" for row in batch["transitions"])
        for side in ("before", "after"):
            assert batch["accounting"][side + "_findings"] == case["expected"][side + "_findings"]
            assert batch["accounting"][side + "_records_accounted"] == case["expected"][side + "_findings"]
        assert len(explanation["unknown_findings"]) == len(case["expected"]["unknown"])
        for entry, expected in zip(explanation["unknown_findings"], case["expected"]["unknown"]):
            native_unknown = batch["unknown_findings"][entry["side"]][entry["unknown_index"]]
            assert entry == dict(side=expected["side"], unknown_index=expected["unknown_index"],
                                 advisory=case["advisory"], source=expected["source"],
                                 reasons=[dict(code=code, sources=expected["reason_sources"][code])
                                          for code in expected["reason_codes"]])
            assert entry["source"] == native_unknown["source"]
            assert [r["code"] for r in entry["reasons"]] == native_unknown["reasons"]
            value = {k: v["document"] for k, v in batch["evidence"].items()}
            for part in entry["source"].lstrip("/").split("/"):
                value = value[int(part)] if isinstance(value, list) else value[part]
            assert value["vulnerability"]["id"] == case["advisory"]
            for reason in entry["reasons"]:
                for pointer in reason["sources"]:
                    value = {k: v["document"] for k, v in batch["evidence"].items()}
                    for part in pointer.lstrip("/").split("/"):
                        part = part.replace("~1", "/").replace("~0", "~")
                        value = value[int(part)] if isinstance(value, list) else value[part]
        markdown = run("explain", paths, "--advisory", case["advisory"], "--format", "markdown").stdout
        tables, appendix = markdown.split("## Full evidence and accounting", 1)
        assert "## Selected unknown evidence" in tables
        for entry in explanation["unknown_findings"]:
            assert entry["source"] in tables
            assert all(reason["code"] in tables for reason in entry["reasons"])
            assert all(pointer in tables for reason in entry["reasons"] for pointer in reason["sources"])
        assert json.loads(appendix.split("```json\n", 1)[1].rsplit("```", 1)[0]) == dict(batch, explanation=explanation)
    identity_case = next(c for c in unknown_cases if c["name"] == "unknown-identity-absent-purl")
    paths = [ROOT / "examples" / "delta" / name for name in identity_case["inputs"]]
    with tempfile.TemporaryDirectory(prefix="vulnwrench-delta-unknown-explain-") as folder:
        output = Path(folder) / "existing.txt"
        for format in ("json", "markdown"):
            for selector in (None, "", "SYNTHETIC_SECRET_UNKNOWN", "CVE-SYNTH-001"):
                output.write_text("previous output", encoding="utf-8")
                flags = [] if selector is None else ["--advisory", selector]
                failure = run("explain", paths, *flags, "--format", format, "--output", str(output), expected=2)
                assert not failure.stdout and "SYNTHETIC_SECRET" not in failure.stderr and "Traceback" not in failure.stderr
                assert output.read_text() == "previous output"
                assert not list(Path(folder).glob(".vulnwrench-delta-*"))
        for format in ("json", "markdown"):
            result = run("explain", paths, "--advisory", "GHSA-SYNTH-001", "--format", format, "--output", str(output))
            assert not result.stdout and not result.stderr and output.read_text()
        for change in ("locations", "version", "name", "type", "artifact-version"):
            document = json.loads(paths[1].read_text())
            if change == "version":
                document["descriptor"]["version"] = "SYNTHETIC_SECRET_VERSION"
            else:
                del document["matches"][0]["artifact"]["version" if change == "artifact-version" else change]
            invalid = Path(folder) / "invalid-after.json"
            invalid.write_text(json.dumps(document), encoding="utf-8")
            invalid_paths = [paths[0], invalid, *paths[2:]]
            for format in ("json", "markdown"):
                output.write_text("previous output", encoding="utf-8")
                failure = run("explain", invalid_paths, "--advisory", "GHSA-SYNTH-001", "--format", format,
                              "--output", str(output), expected=2)
                assert not failure.stdout and "SYNTHETIC_SECRET" not in failure.stderr and "Traceback" not in failure.stderr
                assert output.read_text() == "previous output"
                assert not list(Path(folder).glob(".vulnwrench-delta-*"))
    binding_case = next(c for c in unknown_cases if c["name"] == "unknown-binding-type")
    paths = [ROOT / "examples" / "delta" / name for name in binding_case["inputs"]]
    with tempfile.TemporaryDirectory(prefix="vulnwrench-delta-binding-type-") as folder:
        output = Path(folder) / "existing.txt"
        for format in ("json", "markdown"):
            for selector in (None, "", "CVE-SYNTH-001", "SYNTHETIC_SECRET_RELATED", "SYNTHETIC_SECRET_EXTENSION"):
                output.write_text("previous output", encoding="utf-8")
                flags = [] if selector is None else ["--advisory", selector]
                failure = run("explain", paths, *flags, "--format", format, "--output", str(output), expected=2)
                assert not failure.stdout and "SYNTHETIC_SECRET" not in failure.stderr and "Traceback" not in failure.stderr
                assert output.read_text() == "previous output"
                assert not list(Path(folder).glob(".vulnwrench-delta-*"))
        for change in ("undeclared-target", "duplicate-id"):
            metadata = json.loads(paths[4].read_text())
            config = metadata["after"]["grype"]
            if change == "undeclared-target":
                config["bindings"][2]["target"] = "SYNTHETIC_SECRET_UNDECLARED"
            else:
                config["bindings"][0]["artifact_id"] = config["bindings"][2]["artifact_id"]
            invalid = Path(folder) / "invalid-metadata.json"
            invalid.write_text(json.dumps(metadata), encoding="utf-8")
            for format in ("json", "markdown"):
                output.write_text("previous output", encoding="utf-8")
                failure = run("explain", [*paths[:4], invalid], "--advisory", binding_case["advisory"],
                              "--format", format, "--output", str(output), expected=2)
                assert not failure.stdout and "SYNTHETIC_SECRET" not in failure.stderr and "Traceback" not in failure.stderr
                assert output.read_text() == "previous output"
                assert not list(Path(folder).glob(".vulnwrench-delta-*"))
    conflict_cases = [c for c in unknown_cases if "artifact-conflict" in c["name"]]
    with tempfile.TemporaryDirectory(prefix="vulnwrench-delta-artifact-conflict-") as folder:
        output = Path(folder) / "existing.txt"
        for case in conflict_cases:
            paths = [ROOT / "examples" / "delta" / name for name in case["inputs"]]
            # Unselected conflicting matches are validated even for a different selector.
            side_index, peer_index = (0, 0) if case["name"].startswith("unknown") else (1, 1)
            for field in ("id", "locations", "vulnerability"):
                document = json.loads(paths[side_index].read_text())
                peer = document["matches"][peer_index]
                del (peer if field == "vulnerability" else peer["artifact"])[field]
                invalid = Path(folder) / "invalid-report.json"
                invalid.write_text(json.dumps(document), encoding="utf-8")
                invalid_paths = list(paths)
                invalid_paths[side_index] = invalid
                for format in ("json", "markdown"):
                    output.write_text("previous output", encoding="utf-8")
                    failure = run("explain", invalid_paths, "--advisory", case["advisory"], "--format", format,
                                  "--output", str(output), expected=2)
                    assert not failure.stdout and "SYNTHETIC_SECRET" not in failure.stderr and "Traceback" not in failure.stderr
                    assert output.read_text() == "previous output"
                    assert not list(Path(folder).glob(".vulnwrench-delta-*"))
        case = next(c for c in conflict_cases if c["name"].startswith("unknown"))
        paths = [ROOT / "examples" / "delta" / name for name in case["inputs"]]
        for format in ("json", "markdown"):
            for selector in (None, "", "CVE-SYNTH-001", "SYNTHETIC_SECRET_ABSENT", "SYNTHETIC_SECRET_RELATED", "SYNTHETIC_SECRET_EXTENSION"):
                output.write_text("previous output", encoding="utf-8")
                flags = [] if selector is None else ["--advisory", selector]
                failure = run("explain", paths, *flags, "--format", format, "--output", str(output), expected=2)
                assert not failure.stdout and "SYNTHETIC_SECRET" not in failure.stderr and "Traceback" not in failure.stderr
                assert output.read_text() == "previous output"
                assert not list(Path(folder).glob(".vulnwrench-delta-*"))
            result = run("explain", paths, "--advisory", case["advisory"], "--format", format, "--output", str(output))
            assert not result.stdout and not result.stderr and output.read_text()
            assert not list(Path(folder).glob(".vulnwrench-delta-*"))
    print(f"verified {len(cases)} normalized and {len(unknown_cases)} unknown/mixed explain fixtures, exact batch parity, location/binding/identity/artifact-conflict context pointers, JSON/Markdown, atomic output and safe selector/required-field/binding/unselected-conflict failures")


if __name__ == "__main__":
    verify()
