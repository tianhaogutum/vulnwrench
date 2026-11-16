"""`vulnwrench ci`: funnel counts, outcomes, stale exceptions, gate and error paths on examples/ci."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from vulnwrench.ci import SCHEMA, cli
from vulnwrench.ci.core import DEFAULT_POLICY, exception_format

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples" / "ci"
RECORDED = ROOT / "benchmarks" / "ci"
REPORTS = ["--trivy", "trivy.json", "--grype", "grype.json", "--osv", "osv.json"]
FULL = [*REPORTS, "--baseline", "baseline.json", "--ignores", ".trivyignore", "--ignores", "osv-scanner.toml",
        "--epss", "epss.csv", "--kev", "kev.json", "--as-of", "2026-11-12", "--reports-unfiltered"]


@pytest.fixture(autouse=True)
def in_example(monkeypatch):
    monkeypatch.chdir(EXAMPLE)
    monkeypatch.setenv("NO_COLOR", "1")


def run(args, capsys):
    code = cli.main(list(args))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def doc(args, capsys):
    code, out, err = run([*args, "--format", "json"], capsys)
    assert err == ""
    return code, json.loads(out)


def by_package(result):
    return {(row["package"], row["advisory"]): row for row in result["findings"]}


def test_full_pipeline_funnel(capsys):
    code, result = doc(FULL, capsys)
    assert code == 1
    assert result["schema"] == SCHEMA
    assert result["funnel"] == {
        "rawFindings": 37, "scanners": ["grype", "osv", "trivy"], "reports": 3, "fused": 14, "new": 8,
        "unsuppressed": 6, "needAction": 2, "unknown": 1, "low": 3, "suppressed": 2, "baselineKnown": 6,
        "baselineGone": 2}
    assert result["gate"] == {"failOn": "exploitable", "failing": 2, "staleSnapshots": [], "status": "failed",
                              "exitCode": 1}


def test_outcomes_per_finding(capsys):
    _, result = doc(FULL, capsys)
    rows = by_package(result)
    router = rows[("pkg:npm/acme-router@4.2.0", "CVE-2099-2001")]
    assert router["outcome"] == "action" and router["exploit"]["kev"] is True
    assert router["scanners"] == ["grype", "osv", "trivy"] and router["observations"] == 4
    assert router["paths"][0] == "package-lock.json"  # relative paths first
    session = rows[("pkg:npm/acme-session@1.8.0", "CVE-2099-2002")]
    assert session["outcome"] == "action" and session["exploit"]["epss"] == pytest.approx(0.62)
    assert session["fixConflict"] is True and session["fixVersions"] == ["1.8.4", "1.9.0"]
    color = rows[("pkg:npm/acme-color@0.3.0", "GHSA-w2bb-c4hq-2005")]
    assert color["outcome"] == "unknown" and "no_cve_mapping" in color["exploit"]["reasons"]
    assert rows[("pkg:npm/acme-auth@2.2.0", "CVE-2099-2007")]["outcome"] == "low"  # EPSS 0.09 < 0.1
    zip_row = rows[("pkg:pypi/acme-zip@3.3.3", "CVE-2099-2006")]
    assert zip_row["outcome"] == "suppressed" and zip_row["suppressedBy"] == [".trivyignore:line:3"]
    dns = rows[("pkg:pypi/acme-dns@1.1.0", "CVE-2099-2008")]
    assert dns["outcome"] == "suppressed" and dns["suppressedBy"] == ["osv-scanner.toml:IgnoredVulns:0"]
    xml = rows[("pkg:pypi/acme-xml@0.9.1", "CVE-2099-1004")]
    assert xml["outcome"] == "baseline" and xml["expiredExceptions"] == [".trivyignore:line:2"]
    assert {row["package"] for row in result["baselineGone"]} == {"pkg:npm/acme-old@1.0.0", "pkg:npm/acme-qs@6.0.0"}
    order = [row["outcome"] for row in result["findings"]]
    assert order == sorted(order, key=["action", "unknown", "low", "suppressed", "baseline"].index)


def test_stale_exceptions_and_commands(capsys):
    _, result = doc(FULL, capsys)
    stale = {(item["file"], item["key"]): item for item in result["staleExceptions"]}
    assert set(stale) == {(".trivyignore", "line:2"), (".trivyignore", "line:3"), (".trivyignore", "line:4")}
    assert stale[(".trivyignore", "line:2")]["status"] == ["expired"]
    assert stale[(".trivyignore", "line:3")]["status"] == ["soon_expiring"]
    assert stale[(".trivyignore", "line:4")]["status"] == ["orphan_candidate"]
    assert stale[(".trivyignore", "line:4")]["command"][:3] == ["vulnwrench", "ignores", "cleanup-plan"]
    assert stale[(".trivyignore", "line:2")]["command"][-2:] == ["--rule-key", "line:2"]
    assert result["exceptionHygiene"] == {"rules": 4, "missingReason": 3, "missingOwner": 4, "unverifiedOrphans": 0}
    router = by_package(result)[("pkg:npm/acme-router@4.2.0", "CVE-2099-2001")]
    assert router["command"] == ["vulnwrench", "fuse", "explain", *REPORTS, "--advisory", "CVE-2099-2001",
                                 "--package", "pkg:npm/acme-router@4.2.0"]


@pytest.mark.parametrize("module,args", [
    ("fuse", ["explain", *REPORTS, "--advisory", "CVE-2099-2001", "--package", "pkg:npm/acme-router@4.2.0"]),
    ("ignores", ["explain", "--format", "trivy", "--rules", ".trivyignore", "--report", "trivy.json",
                 "--report-unfiltered", "--as-of", "2026-11-12", "--rule-key", "line:2"]),
    ("ignores", ["cleanup-plan", "--format", "trivy", "--rules", ".trivyignore", "--report", "trivy.json",
                 "--report-unfiltered", "--as-of", "2026-11-12", "--output-format", "markdown"]),
])
def test_suggested_commands_run(module, args):
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    result = subprocess.run([sys.executable, "-m", "vulnwrench", module, *args], cwd=EXAMPLE, env=env,
                            capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr


def test_without_reports_unfiltered_orphans_are_not_claimed(capsys):
    args = [a for a in FULL if a != "--reports-unfiltered"]
    _, result = doc(args, capsys)
    assert all("orphan_candidate" not in item["status"] for item in result["staleExceptions"])
    assert result["exceptionHygiene"]["unverifiedOrphans"] == 1


def test_without_exploit_data_every_new_finding_counts(capsys):
    code, result = doc([*REPORTS, "--baseline", "baseline.json", "--as-of", "2026-11-12"], capsys)
    assert code == 1
    assert result["exploit"] is None
    assert result["funnel"]["needAction"] == result["funnel"]["new"] == 8


def test_without_baseline_everything_is_new(capsys):
    _, result = doc([*REPORTS, "--as-of", "2026-11-12"], capsys)
    assert result["funnel"]["new"] == result["funnel"]["fused"] == 14
    assert result["baselineGone"] == []


@pytest.mark.parametrize("fail_on,expected_code,failing", [
    ("exploitable", 1, 2), ("unknown", 1, 3), ("new", 1, 6), ("none", 0, 0)])
def test_fail_on_levels(fail_on, expected_code, failing, capsys):
    code, result = doc([*FULL, "--fail-on", fail_on], capsys)
    assert code == expected_code
    assert result["gate"]["failing"] == failing


def test_stale_snapshots_fail_closed(capsys):
    args = [*FULL[:-3], "--as-of", "2026-12-30", "--reports-unfiltered"]
    code, result = doc(args, capsys)
    assert result["gate"]["staleSnapshots"] == ["epss", "kev"]
    assert result["funnel"]["needAction"] == 0 and code == 1


def test_passing_gate_exits_zero(capsys, tmp_path, monkeypatch):
    for name in ("trivy.json", "epss.csv", "kev.json"):
        shutil.copy(EXAMPLE / name, tmp_path / name)
    baseline = tmp_path / "baseline.json"
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    made = subprocess.run([sys.executable, "-m", "vulnwrench", "fuse", "merge", "--trivy", "trivy.json",
                           "--output", str(baseline)], cwd=tmp_path, env=env, capture_output=True, text=True,
                          timeout=120)
    assert made.returncode == 0, made.stderr
    monkeypatch.chdir(tmp_path)
    code, out, _ = run(["--trivy", "trivy.json", "--baseline", "baseline.json", "--epss", "epss.csv",
                        "--kev", "kev.json", "--as-of", "2026-11-12"], capsys)
    assert code == 0
    assert "Nothing new and exploitable." in out and "pass (exit 0)" in out


def test_text_report_matches_recording(capsys):
    code, out, err = run(FULL, capsys)
    assert code == 1 and err == ""
    assert out == (RECORDED / "report.txt").read_text()
    assert "37 raw findings from 3 scanners -> 2 need action." in out
    assert "\x1b[" not in out


def test_json_and_sarif_match_recordings(capsys):
    for fmt, name in (("json", "report.json"), ("sarif", "report.sarif")):
        _, out, _ = run([*FULL, "--format", fmt], capsys)
        assert out == (RECORDED / name).read_text(), fmt
    sarif = json.loads((RECORDED / "report.sarif").read_text())
    levels = sorted(r["level"] for r in sarif["runs"][0]["results"])
    assert levels == ["error", "error", "note", "note", "note", "warning"]


def test_results_summary_backs_the_claim():
    summary = json.loads((RECORDED / "results.json").read_text())
    assert summary["synthetic"] is True
    assert summary["claim"] == "37 raw findings from 3 scanners -> 2 that need action"
    assert summary["funnel"] == json.loads((RECORDED / "report.json").read_text())["funnel"]


@pytest.mark.parametrize("args,message", [
    ([], "give at least one report"),
    (["--trivy", "trivy.json", "--epss", "epss.csv"], "--epss and --kev go together"),
    (["--trivy", "trivy.json", "--policy", "x.json"], "--policy and --aliases need"),
    (["--trivy", "trivy.json", "--soon-days", "-1"], "--soon-days must be >= 0"),
    (["--trivy", "trivy.json", "--fail-on", "maybe"], "invalid choice"),
])
def test_usage_errors_exit_2(args, message, capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(args)
    assert exc.value.code == 2
    assert message in capsys.readouterr().err


@pytest.mark.parametrize("args", [
    ["--trivy", "missing.json"],
    ["--grype", "trivy.json"],  # wrong scanner profile
    ["--trivy", "trivy.json", "--baseline", "trivy.json"],  # not a saved merge
    ["--trivy", "trivy.json", "--ignores", "trivy.json"],  # not an ignore file
    ["--trivy", "trivy.json", "--as-of", "12/11/2026"],
    ["--trivy", "trivy.json", "--epss", "kev.json", "--kev", "kev.json"],
])
def test_input_errors_exit_2_without_traceback(args, capsys):
    code, out, err = run(args, capsys)
    assert code == 2 and out == ""
    assert err.startswith("vulnwrench ci: ") and "Traceback" not in err


def test_helpers():
    assert exception_format("osv-scanner.toml") == "osv"
    assert exception_format(".trivyignore") == "trivy"
    assert DEFAULT_POLICY["epssThreshold"] == 0.1 and DEFAULT_POLICY["blockKev"] is True


def test_dispatcher_routes_ci():
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    result = subprocess.run([sys.executable, "-m", "vulnwrench.ci", "--help"], env=env, capture_output=True,
                            text=True, timeout=120)
    assert result.returncode == 0 and "usage: vulnwrench ci" in result.stdout
