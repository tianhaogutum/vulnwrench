"""Top-level ``vulnwrench`` command: dispatches to one tool per subcommand.

Each tool lives in its own subpackage exposing ``cli.main(argv) -> int``. Tools
are imported lazily, so ``vulnwrench --help`` stays fast and one tool's import
cost or failure never affects another command.
"""
from __future__ import annotations

from dataclasses import dataclass
import difflib
import importlib
import importlib.util
import sys

from . import __version__

PROG = "vulnwrench"
REPO_URL = "https://github.com/tianhaogutum/vulnwrench"


@dataclass(frozen=True)
class Command:
    name: str
    module: str
    summary: str
    group: str
    # Every current tool is standard-library only. The fields stay so a future command
    # with an optional dependency gets the same install hint as the sibling packages.
    extra: str | None = None
    requires: tuple[str, ...] = ()


GROUPS = ("Merge & compare", "SBOM & images", "Exceptions & reviews", "CI gates")

COMMANDS: tuple[Command, ...] = (
    Command("ci", "vulnwrench.ci.cli",
            "One CI gate: fuse reports, skip baseline and excepted findings, fail on exploitable ones",
            "Merge & compare"),
    Command("fuse", "vulnwrench.fuse.cli",
            "Merge Trivy, Grype and OSV-Scanner reports into one agreement/conflict matrix",
            "Merge & compare"),
    Command("delta", "vulnwrench.scandelta.cli",
            "Diff two Trivy/Grype scans against their CycloneDX inventories: fixed, new, removed",
            "Merge & compare"),
    Command("path", "vulnwrench.sbompath.cli",
            "Show the shortest CycloneDX/SPDX dependency path from each root to a Grype finding",
            "SBOM & images"),
    Command("layers", "vulnwrench.layers.cli",
            "Attribute each Trivy image finding to the base image or the application layers",
            "SBOM & images"),
    Command("scorecard", "vulnwrench.scorecard.cli",
            "Join CycloneDX components to local OpenSSF Scorecard results and apply a policy",
            "SBOM & images"),
    Command("ignores", "vulnwrench.ignoreaudit.cli",
            "Audit .trivyignore / osv-scanner.toml rules: orphans, expiry, owners, broad matches",
            "Exceptions & reviews"),
    Command("triage", "vulnwrench.triage.cli",
            "Compile one typed decision file to .trivyignore.yaml, osv-scanner.toml and OpenVEX",
            "Exceptions & reviews"),
    Command("secrets", "vulnwrench.secretledger.cli",
            "Keep a redacted, keyed review ledger of Gitleaks findings and classify new reports",
            "Exceptions & reviews"),
    Command("exploit", "vulnwrench.exploitgate.cli",
            "Gate Trivy/Grype/OSV findings on local EPSS and CISA KEV snapshots",
            "CI gates"),
    Command("sarif", "vulnwrench.sarifgate.cli",
            "Gate CI on SARIF 2.1.0 with suppressions, baselines and scanner-failure checks",
            "CI gates"),
)
BY_NAME = {command.name: command for command in COMMANDS}

# Former standalone tool names, used only to point users at the new subcommand.
LEGACY = {
    "vulnfuse": "fuse", "scan-delta": "delta", "exploit-gate": "exploit", "layer-attribution": "layers",
    "sbom-pathfinder": "path", "scorecard-join": "scorecard", "ignore-audit": "ignores",
    "triage-bridge": "triage", "sarif-gate": "sarif", "secret-ledger": "secrets",
}


def _present(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


def _installed(command: Command) -> bool:
    return _present(command.module.rpartition(".")[0])


def _missing_requirements(command: Command) -> bool:
    return any(not _present(name) for name in command.requires)


def _install_hint(command: Command) -> str:
    return (f"{PROG} {command.name}: missing optional dependencies; "
            f"install them with: pip install '{PROG}[{command.extra}]'")


def overview() -> str:
    width = max(len(command.name) for command in COMMANDS) + 2
    lines = [
        f"{PROG} {__version__} - offline tools to merge, diff, triage and gate vulnerability-scanner reports",
        "",
        f"usage: {PROG} <command> [args...]",
        f"       {PROG} <command> --help",
    ]
    for group in GROUPS:
        lines += ["", f"{group}:"]
        for command in COMMANDS:
            if command.group != group:
                continue
            note = ""
            if not _installed(command):
                note = "  (coming soon)"
            elif command.extra and _missing_requirements(command):
                note = f"  (needs {PROG}[{command.extra}])"
            lines.append(f"  {command.name.ljust(width)}{command.summary}{note}")
    lines += [
        "",
        "options:",
        "  -h, --help     show this overview",
        "  -V, --version  show the version and exit",
        "",
        "Every command reads local files only: no scanner runs, no network access.",
        f"Docs and issues: {REPO_URL}",
    ]
    return "\n".join(lines) + "\n"


def _unknown(name: str) -> int:
    message = f"{PROG}: unknown command {name!r}"
    if name in LEGACY:
        message += f"; {name} is now '{PROG} {LEGACY[name]}'"
    else:
        match = difflib.get_close_matches(name, [*BY_NAME, *LEGACY], n=1, cutoff=0.6)
        if match:
            suggestion = LEGACY.get(match[0], match[0])
            message += f"; did you mean '{suggestion}'?"
    sys.stderr.write(message + f"\nRun '{PROG} --help' to list commands.\n")
    return 2


def run(command: Command, argv: list[str]) -> int:
    if not _installed(command):
        sys.stderr.write(f"{PROG}: command {command.name!r} is not available in "
                         f"{PROG} {__version__} yet; see {REPO_URL}\n")
        return 2
    if command.extra and _missing_requirements(command):
        sys.stderr.write(_install_hint(command) + "\n")
        return 2
    try:
        module = importlib.import_module(command.module)
    except ModuleNotFoundError as exc:
        missing = exc.name or ""
        if command.extra and any(req == missing or req.startswith(missing + ".") for req in command.requires):
            sys.stderr.write(_install_hint(command) + "\n")
            return 2
        raise
    result = module.main(argv)
    return 0 if result is None else result


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in ("-h", "--help"):
        sys.stdout.write(overview())
        return 0
    first, rest = args[0], args[1:]
    if first in ("-V", "--version"):
        sys.stdout.write(f"{PROG} {__version__}\n")
        return 0
    if first == "help":
        if not rest:
            sys.stdout.write(overview())
            return 0
        first, rest = rest[0], ["--help"]
    if first.startswith("-"):
        sys.stderr.write(f"{PROG}: unknown option {first!r}\nRun '{PROG} --help' for usage.\n")
        return 2
    command = BY_NAME.get(first)
    if command is None:
        return _unknown(first)
    return run(command, rest)


if __name__ == "__main__":
    raise SystemExit(main())
