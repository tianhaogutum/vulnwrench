#!/usr/bin/env python3
"""Execute the documented CLI examples offline and compare real output to goldens."""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASE = [sys.executable, "-m", "vulnwrench", "scorecard", "check", "examples/scorecard/bom.json",
        "--map", "examples/scorecard/repos.json", "--scorecards", "examples/scorecard/scorecards",
        "--policy", "examples/scorecard/policy.json", "--as-of", "2026-11-11"]


def run(extra=(), expected=0, bom=None):
    command = list(BASE)
    if bom is not None:
        command[4] = str(bom)
    result = subprocess.run([*command, *map(str, extra)], cwd=ROOT, capture_output=True, timeout=120)
    assert result.returncode == expected, f"unexpected CLI exit: {result.returncode}, expected {expected}"
    return result


def write(path, document):
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def main():
    passed = []
    first = run().stdout
    assert first == (ROOT / "examples/scorecard/expected.json").read_bytes(), "JSON golden mismatch"
    passed.append("native JSON example matches recorded output")
    report = json.loads(first)
    assert report["summary"]["components"] == 7
    assert report["summary"]["pass"] == 2 and report["summary"]["unknown"] == 5
    assert report["summary"]["selectedRepositories"] == 3
    assert report["components"][0]["snapshotId"] == report["components"][1]["snapshotId"]
    assert len(report["snapshots"]) == 3
    assert report["components"][2]["reason"] == "stale_snapshot"
    assert [item["observation"] for item in report["components"][3]["checks"]] == ["negative_score", "missing_check"]
    passed.append("all seven components, repository reuse, stale and unknown observations retained")
    assert run(["--format", "markdown"]).stdout == (ROOT / "examples/scorecard/expected.md").read_bytes(), "Markdown golden mismatch"
    passed.append("Markdown example matches recorded output")
    assert run().stdout == first, "nondeterministic output"
    passed.append("repeat run is byte-identical")
    gated = run(["--gate"], expected=1)
    assert gated.stdout == first and report["gate"]["exitCode"] == 1
    passed.append("unknown evidence withholds gate but keeps report")

    lint_command = [sys.executable, "-m", "vulnwrench", "scorecard", "lint-mappings",
                    "examples/scorecard/lint-mappings/bom.json", "--map", "examples/scorecard/lint-mappings/repos.json"]
    lint = subprocess.run(lint_command, cwd=ROOT, capture_output=True, timeout=120)
    assert lint.returncode == 0 and not lint.stderr
    assert lint.stdout == (ROOT / "examples/scorecard/lint-mappings/expected.json").read_bytes()
    passed.append("advisory mapping lint matches recorded output with all unknown components retained")
    strict_lint = subprocess.run([*lint_command, "--strict"], cwd=ROOT, capture_output=True, timeout=120)
    assert strict_lint.returncode == 1 and strict_lint.stdout == lint.stdout and not strict_lint.stderr
    passed.append("strict mapping lint fails on ambiguity and keeps identical diagnostics")
    for flags, code in [((), 0), (("--strict",), 1), (("--fail-on-unmapped",), 1),
                        (("--strict", "--fail-on-unmapped"), 1)]:
        markdown = subprocess.run([*lint_command, "--format", "markdown", *flags],
                                  cwd=ROOT, capture_output=True, timeout=120)
        assert markdown.returncode == code and not markdown.stderr
        assert markdown.stdout == (ROOT / "examples/scorecard/lint-mappings/expected.md").read_bytes()
    passed.append("literal lint Markdown contract matches every advisory/strict/coverage flag combination")
    run(["--map", "examples/scorecard/lint-mappings/repos.json"], expected=2)
    passed.append("advisory lint does not relax the join's repeated-key rejection")

    comparison = [sys.executable, "-m", "vulnwrench", "scorecard", "compare", "examples/scorecard/compare/bom.json",
                  "--map", "examples/scorecard/compare/repos.json", "--before", "examples/scorecard/compare/before",
                  "--after", "examples/scorecard/compare/after", "--before-as-of", "2026-11-01",
                  "--after-as-of", "2026-11-11", "--max-age-days", "2"]
    compared = subprocess.run(comparison, cwd=ROOT, capture_output=True, timeout=120)
    assert compared.returncode == 0 and not compared.stderr
    assert compared.stdout == (ROOT / "examples/scorecard/compare/expected.json").read_bytes()
    passed.append("two dated bundles match the recorded deterministic JSON comparison")
    explicit_json = subprocess.run([*comparison, "--format", "json"], cwd=ROOT, capture_output=True, timeout=120)
    assert explicit_json.returncode == 0 and not explicit_json.stderr and explicit_json.stdout == compared.stdout
    markdown = subprocess.run([*comparison, "--format", "markdown"], cwd=ROOT, capture_output=True, timeout=120)
    assert markdown.returncode == 0 and not markdown.stderr
    assert markdown.stdout == (ROOT / "examples/scorecard/compare/expected.md").read_bytes()
    assert json.loads(markdown.stdout.split(b'```json\n', 1)[1].rsplit(b'\n```', 1)[0]) == json.loads(compared.stdout)
    passed.append("comparison Markdown matches the literal fixture and lossless JSON appendix; explicit/default JSON bytes agree")
    selection = ["--check", "License", "--check", "Not-Observed", "--check", "Future-Check", "--check", "License"]
    for fmt, name in (("json", "expected-selected.json"), ("markdown", "expected-selected.md")):
        selected = subprocess.run([*comparison, "--format", fmt, *selection, "--fail-on-decrease"],
                                  cwd=ROOT, capture_output=True, timeout=120)
        assert selected.returncode == 0 and not selected.stderr
        assert selected.stdout == (ROOT / "examples/scorecard/compare" / name).read_bytes()
    passed.append("exact --check selection matches literal JSON/Markdown fixtures and retains full snapshots")
    summary = json.loads(compared.stdout)["summary"]
    assert sum(summary["comparisonStatuses"].values()) == summary["comparedRepositories"]
    assert sum(summary["snapshotChanges"].values()) == summary["comparedRepositories"]
    assert summary["checkChanges"] == {"changed": 5, "unchanged": 0, "added": 1, "deleted": 1, "not_comparable": 1}
    assert summary["checkScoreChanges"] == {"increased": 2, "decreased": 0, "unchanged": 1, "not_comparable": 5}
    assert sum(summary["checkScoreChanges"].values()) == sum(summary["checkChanges"].values())
    assert summary['checkObservations'] == {
        'before': {'known': 6, 'negative_score': 1, 'missing_score': 0, 'missing_check': 1, 'missing_snapshot': 0},
        'after': {'known': 6, 'negative_score': 0, 'missing_score': 0, 'missing_check': 1, 'missing_snapshot': 1}}
    for counts in summary['checkObservations'].values():
        assert sum(counts.values()) == sum(summary['checkChanges'].values())
        assert sum(counts.values()) == sum(summary['checkScoreChanges'].values())
    comparability = summary['checkScoreComparability']
    assert comparability == {'comparable': 3, 'evidence_blocked': 2, 'observation_blocked': 3}
    assert sum(comparability.values()) == sum(summary['checkChanges'].values())
    assert comparability['evidence_blocked'] + comparability['observation_blocked'] == summary['checkScoreChanges']['not_comparable']
    directions_by_check = summary['checkScoreChangesByCheck']
    assert directions_by_check == [
        {'decreased': 0, 'increased': 2, 'name': 'Code-Review', 'not_comparable': 2, 'unchanged': 0},
        {'decreased': 0, 'increased': 0, 'name': 'Future-Check', 'not_comparable': 1, 'unchanged': 0},
        {'decreased': 0, 'increased': 0, 'name': 'License', 'not_comparable': 0, 'unchanged': 1},
        {'decreased': 0, 'increased': 0, 'name': 'Maintained', 'not_comparable': 1, 'unchanged': 0},
        {'decreased': 0, 'increased': 0, 'name': 'Security-Policy', 'not_comparable': 1, 'unchanged': 0}]
    support = {row['name']: row for row in summary['checkScoreComparabilityByCheck']}
    for row in directions_by_check:
        assert row['increased'] + row['decreased'] + row['unchanged'] == support[row['name']]['comparable']
        assert row['not_comparable'] == support[row['name']]['evidence_blocked'] + support[row['name']]['observation_blocked']
    for key, count in summary['checkScoreChanges'].items():
        assert sum(row[key] for row in directions_by_check) == count
    by_check = summary['checkScoreComparabilityByCheck']
    assert by_check == [
        {'name': 'Code-Review', 'comparable': 2, 'evidence_blocked': 2, 'observation_blocked': 0},
        {'name': 'Future-Check', 'comparable': 0, 'evidence_blocked': 0, 'observation_blocked': 1},
        {'name': 'License', 'comparable': 1, 'evidence_blocked': 0, 'observation_blocked': 0},
        {'name': 'Maintained', 'comparable': 0, 'evidence_blocked': 0, 'observation_blocked': 1},
        {'name': 'Security-Policy', 'comparable': 0, 'evidence_blocked': 0, 'observation_blocked': 1}]
    for key, count in comparability.items():
        assert sum(row[key] for row in by_check) == count
    transitions = summary['checkObservationTransitions']
    assert transitions == {
        'known': {'known': 4, 'negative_score': 0, 'missing_score': 0, 'missing_check': 1, 'missing_snapshot': 1},
        'negative_score': {'known': 1, 'negative_score': 0, 'missing_score': 0, 'missing_check': 0, 'missing_snapshot': 0},
        'missing_score': {'known': 0, 'negative_score': 0, 'missing_score': 0, 'missing_check': 0, 'missing_snapshot': 0},
        'missing_check': {'known': 1, 'negative_score': 0, 'missing_score': 0, 'missing_check': 0, 'missing_snapshot': 0},
        'missing_snapshot': {'known': 0, 'negative_score': 0, 'missing_score': 0, 'missing_check': 0, 'missing_snapshot': 0}}
    assert sum(sum(row.values()) for row in transitions.values()) == sum(summary['checkChanges'].values())
    for label, row in transitions.items():
        assert sum(row.values()) == summary['checkObservations']['before'][label]
        assert sum(counts[label] for counts in transitions.values()) == summary['checkObservations']['after'][label]
    assert sum(summary["checkChanges"].values()) == sum(len(row["checks"]) for row in json.loads(compared.stdout)["repositories"])
    assert summary == json.loads(
        (ROOT / "examples/scorecard/compare/expected-summary.json").read_text())
    passed.append("literal coverage partitions count four canonical repositories and eight repository/check pairs by raw change, score direction, before/after observation, joint transition and global/per-check score comparability/direction")
    actual = {row["repository"].rsplit("/", 1)[1]: {
        "comparison": row["comparison"], "commitChange": row["commitChange"],
        "scannerChange": row["scannerChange"],
        "checks": {check["name"]: [check["change"], check["scoreChange"],
                                   check["scoreChanged"], check["reasonChanged"]]
                   for check in row["checks"]}} for row in json.loads(compared.stdout)["repositories"]}
    assert actual == json.loads((ROOT / "examples/scorecard/compare/expected-changes.json").read_text())
    passed.append("hand-authored expectations separate checks, evidence gaps, repository commits and scanner revisions")
    repeated = subprocess.run(comparison, cwd=ROOT, capture_output=True, timeout=120)
    assert repeated.returncode == 0 and not repeated.stderr and repeated.stdout == compared.stdout
    passed.append("repeat comparison is byte-identical")

    with tempfile.TemporaryDirectory(prefix="vulnwrench-scorecard-examples-") as temp:
        work = Path(temp)
        bom = json.loads((ROOT / "examples/scorecard/bom.json").read_text())
        bom.pop("metadata")
        bom["components"] = bom["components"][:2]
        bom.pop("dependencies")
        bom_path = write(work / "passing-bom.json", bom)
        passing = run(["--gate"], bom=bom_path)
        passing_report = json.loads(passing.stdout)
        assert passing_report["decision"] == "pass" and passing_report["summary"]["pass"] == 2
        passed.append("mapped two-package release passes real CLI gate")

        policy = {"checks": {"Code-Review": 9}, "maxAgeDays": 30, "missing": "unknown"}
        policy_path = write(work / "failing-policy.json", policy)
        failing = run(["--policy", policy_path, "--gate"], expected=1, bom=bom_path)
        assert json.loads(failing.stdout)["decision"] == "fail"
        passed.append("below-threshold check fails real CLI gate")

        empty = work / "empty-scorecards"
        empty.mkdir()
        missing = run(["--scorecards", empty], bom=bom_path)
        assert all(row["reason"] == "missing_scorecard" for row in json.loads(missing.stdout)["components"])
        passed.append("missing native snapshot remains explicit unknown")

        secret = "SYNTHETIC-DO-NOT-ECHO"
        malformed = write(work / "bad-map.json", {"pkg:npm/demo@1.0": f"https://user:{secret}@github.com/example/demo"})
        output = work / "out.json"
        output.write_bytes(b"previous report\n")
        invalid = run(["--map", malformed, "--output", output], expected=2)
        assert secret.encode() not in invalid.stderr and not invalid.stdout
        assert output.read_bytes() == b"previous report\n"
        passed.append("invalid URL rejected without secret leakage or output replacement")

        duplicate = work / "duplicate-map.json"
        duplicate.write_text('{"pkg:npm/demo@1.0":"https://github.com/example/demo",'
                             '"pkg:npm/demo@1.0":"https://github.com/example/other"}')
        run(["--map", duplicate], expected=2)
        passed.append("contradictory mapping rejected by real CLI")

    for item in passed:
        print("PASS:", item)
    print(f"{len(passed)} offline example checks passed ({sys.version.split()[0]}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
