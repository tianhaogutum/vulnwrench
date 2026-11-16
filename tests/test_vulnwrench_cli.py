"""Top-level `vulnwrench` dispatcher: overview, version, routing and error paths."""
import subprocess
import sys

import pytest

import vulnwrench
from vulnwrench import cli


def run(*args, module=("-m", "vulnwrench")):
    return subprocess.run([sys.executable, *module, *map(str, args)], capture_output=True, text=True, timeout=120)


SUBCOMMANDS = {
    "ci": [],
    "fuse": ["merge", "explain", "validate", "validate-input", "validate-coverage"],
    "delta": ["compare", "explain"],
    "path": ["explain"],
    "layers": ["explain", "compare"],
    "scorecard": ["check", "lint-mappings", "compare"],
    "ignores": ["audit", "explain", "cleanup-plan", "verify-cleanup-plan-identity", "verify-cleanup-source",
                "verify-cleanup-report", "verify-cleanup-alias-map", "verify-cleanup-metadata",
                "verify-cleanup-inputs"],
    "triage": ["compile", "preview-renewal", "import-trivy", "finalize-import"],
    "secrets": ["init", "snapshot", "compare", "import-renames"],
    "exploit": ["check", "compare", "manifest"],
    "sarif": ["check"],
}
SUBPACKAGES = {
    "ci": "ci", "fuse": "fuse", "delta": "scandelta", "path": "sbompath", "layers": "layers", "scorecard": "scorecard",
    "ignores": "ignoreaudit", "triage": "triage", "secrets": "secretledger", "exploit": "exploitgate",
    "sarif": "sarifgate",
}
ALL_HELP = [(name, None) for name in SUBCOMMANDS] + [(name, sub) for name, subs in SUBCOMMANDS.items() for sub in subs]


def _main(argv, capsys):
    try:
        code = cli.main(argv)
    except SystemExit as exc:
        code = exc.code
    captured = capsys.readouterr()
    return code, captured.out, captured.err


@pytest.mark.parametrize("args", [[], ["--help"], ["-h"], ["help"]])
def test_overview_lists_every_group_and_command(args, capsys):
    assert cli.main(args) == 0
    out = capsys.readouterr().out
    assert out.startswith(f"vulnwrench {vulnwrench.__version__} ")
    for group in cli.GROUPS:
        assert f"\n{group}:\n" in out
    for command in cli.COMMANDS:
        assert f"\n  {command.name} " in out
    assert "(coming soon)" not in out and "(needs " not in out


def test_hero_command_is_listed_first():
    assert cli.COMMANDS[0].name == "ci" and cli.COMMANDS[0].group == cli.GROUPS[0]
    assert "ci" not in cli.LEGACY.values()


def test_command_table_shape():
    assert [c.name for c in cli.COMMANDS if c.group == "Merge & compare"] == ["ci", "fuse", "delta"]
    assert [c.name for c in cli.COMMANDS if c.group == "SBOM & images"] == ["path", "layers", "scorecard"]
    assert [c.name for c in cli.COMMANDS if c.group == "Exceptions & reviews"] == ["ignores", "triage", "secrets"]
    assert [c.name for c in cli.COMMANDS if c.group == "CI gates"] == ["exploit", "sarif"]
    assert {c.name: c.module for c in cli.COMMANDS} == {
        name: f"vulnwrench.{package}.cli" for name, package in SUBPACKAGES.items()}
    assert all(c.group in cli.GROUPS and c.summary for c in cli.COMMANDS)
    assert not any(c.extra or c.requires for c in cli.COMMANDS)  # every tool is standard-library only
    assert set(cli.LEGACY.values()) == set(cli.BY_NAME) - {"ci"}  # ci is new: no former tool name
    assert len(cli.BY_NAME) == len(cli.COMMANDS)


def test_no_subcommand_stutters():
    for name, subs in SUBCOMMANDS.items():
        assert name not in subs, name


@pytest.mark.parametrize("flag", ["--version", "-V"])
def test_version(flag, capsys):
    assert cli.main([flag]) == 0
    assert capsys.readouterr().out == f"vulnwrench {vulnwrench.__version__}\n"


@pytest.mark.parametrize("tool", sorted(SUBCOMMANDS))
def test_tool_version_uses_new_program_name(tool, capsys):
    code, out, err = _main([tool, "--version"], capsys)
    assert code == 0, err
    assert out == f"vulnwrench {tool} {vulnwrench.__version__}\n"


@pytest.mark.parametrize("tool", sorted(SUBCOMMANDS))
def test_tool_help_uses_new_program_name(tool):
    result = run(tool, "--help")
    assert result.returncode == 0, result.stderr
    assert f"usage: vulnwrench {tool}" in result.stdout


@pytest.mark.parametrize("tool", sorted(SUBCOMMANDS))
def test_help_subcommand_routes_to_tool_help(tool, capsys):
    code, out, _ = _main(["help", tool], capsys)
    assert code == 0
    assert f"usage: vulnwrench {tool}" in out


@pytest.mark.parametrize("tool", sorted(SUBCOMMANDS))
def test_tool_without_subcommand_is_a_usage_error(tool, capsys):
    code, out, err = _main([tool], capsys)
    assert code == 2, (out, err)
    assert "Traceback" not in err


def test_tool_exit_codes_pass_through():
    bad = run("sarif", "no-such-subcommand")
    assert bad.returncode == 2 and bad.stdout == ""
    assert "vulnwrench sarif" in bad.stderr


def test_unknown_command_suggests_close_match(capsys):
    assert cli.main(["scorecrd"]) == 2
    err = capsys.readouterr().err
    assert "unknown command 'scorecrd'" in err and "did you mean 'scorecard'?" in err


def test_close_match_to_legacy_name_suggests_new_command(capsys):
    assert cli.main(["sarif-gat"]) == 2
    assert "did you mean 'sarif'?" in capsys.readouterr().err


@pytest.mark.parametrize("old,new", sorted(cli.LEGACY.items()))
def test_unknown_legacy_name_points_to_new_command(old, new, capsys):
    assert cli.main([old]) == 2
    assert f"{old} is now 'vulnwrench {new}'" in capsys.readouterr().err


def test_unknown_command_without_match(capsys):
    assert cli.main(["zzzzzz"]) == 2
    err = capsys.readouterr().err
    assert "unknown command 'zzzzzz'" in err and "did you mean" not in err


def test_unknown_option(capsys):
    assert cli.main(["--frobnicate"]) == 2
    assert "unknown option '--frobnicate'" in capsys.readouterr().err


def test_missing_module_reports_not_available(monkeypatch, capsys):
    ghost = cli.Command("ghost", "vulnwrench.ghost_tool.cli", "not shipped", "CI gates")
    monkeypatch.setitem(cli.BY_NAME, "ghost", ghost)
    monkeypatch.setattr(cli, "COMMANDS", (*cli.COMMANDS, ghost))
    assert "ghost" in cli.overview() and "(coming soon)" in cli.overview()
    assert cli.main(["ghost", "--help"]) == 2
    err = capsys.readouterr().err
    assert err.startswith("vulnwrench: command 'ghost' is not available") and "Traceback" not in err


def test_missing_extra_prints_install_hint(monkeypatch, capsys):
    needy = cli.Command("needy", "vulnwrench.sarifgate.cli", "needs a backend", "CI gates",
                        extra="needy", requires=("vulnwrench_no_such_backend",))
    monkeypatch.setitem(cli.BY_NAME, "needy", needy)
    monkeypatch.setattr(cli, "COMMANDS", (*cli.COMMANDS, needy))
    assert "(needs vulnwrench[needy])" in cli.overview()
    assert cli.main(["needy", "check", "x"]) == 2
    assert capsys.readouterr().err == ("vulnwrench needy: missing optional dependencies; "
                                       "install them with: pip install 'vulnwrench[needy]'\n")


@pytest.mark.parametrize("tool", sorted(SUBCOMMANDS))
def test_subpackage_main_routes_through_dispatcher(tool):
    result = run("--help", module=("-m", f"vulnwrench.{SUBPACKAGES[tool]}"))
    assert result.returncode == 0, result.stderr
    assert f"usage: vulnwrench {tool}" in result.stdout


def test_subcommand_table_covers_every_command():
    assert set(SUBCOMMANDS) == set(cli.BY_NAME) == set(SUBPACKAGES)


@pytest.mark.parametrize("flag", ["--help", "-h"])
@pytest.mark.parametrize("command,sub", ALL_HELP, ids=lambda v: v or "-")
def test_every_command_and_subcommand_help_exits_0(command, sub, flag, capsys):
    argv = [command, *([sub] if sub else []), flag]
    code, out, err = _main(argv, capsys)
    assert code == 0, (argv, err)
    assert "usage" in out.lower(), (argv, out)
    if sub:
        assert f"vulnwrench {command} {sub}" in out, (argv, out)
