# vulnwrench documentation

One page per command. Each page starts with the problem the command solves and a quick
start, followed by the full reference. Run `vulnwrench <command> --help` for the flags.
Quick starts use the synthetic sample inputs under [`examples/`](../examples/), so run them
from a clone of the repository (`git clone https://github.com/tianhaogutum/vulnwrench`).
Every command reads local files only: none of them runs a scanner, executes target code or
uses the network.

## Merge and compare

| Command | Use it to |
| --- | --- |
| [`vulnwrench ci`](ci.md) | Gate CI on one report: fuse Trivy/Grype/OSV-Scanner results, skip findings already in the baseline or covered by an unexpired exception, fail only on exploitable ones (KEV/EPSS), and flag stale exceptions |
| [`vulnwrench fuse`](fuse.md) | Merge Trivy, Grype and OSV-Scanner JSON into one deduplicated agreement/conflict matrix that keeps every source observation |
| [`vulnwrench delta`](delta.md) | Diff two Trivy or Grype scans against their CycloneDX inventories and tell real fixes from removed packages and renamed advisories |

## SBOM and images

| Command | Use it to |
| --- | --- |
| [`vulnwrench path`](path.md) | Show which declared roots of a CycloneDX/SPDX SBOM reach a Grype finding, with one shortest dependency path each |
| [`vulnwrench layers`](layers.md) | Attribute each Trivy image finding to the base image or the application layers using exact OCI DiffID evidence |
| [`vulnwrench scorecard`](scorecard.md) | Join CycloneDX components to saved OpenSSF Scorecard results, apply a policy and compare dated snapshots |

## Exceptions and reviews

| Command | Use it to |
| --- | --- |
| [`vulnwrench ignores`](ignores.md) | Audit `.trivyignore` and `osv-scanner.toml` rules for orphans, expiry, missing owners and over-broad matches |
| [`vulnwrench triage`](triage.md) | Keep exceptions in one typed decision file and compile it to `.trivyignore.yaml`, `osv-scanner.toml` and OpenVEX |
| [`vulnwrench secrets`](secrets.md) | Track Gitleaks findings in a redacted, keyed review ledger and classify each new report against it |

## CI gates

| Command | Use it to |
| --- | --- |
| [`vulnwrench exploit`](exploit.md) | Gate Trivy, Grype or OSV-Scanner findings on local EPSS and CISA KEV snapshots with an explained policy |
| [`vulnwrench sarif`](sarif.md) | Gate CI on a SARIF 2.1.0 file, honouring accepted suppressions, rule default levels, baselines and scanner failures |

Additional reference: [`vulnwrench triage` decision and OpenVEX schemas](triage/schemas/).
Third-party attribution is in [THIRD_PARTY.md](../THIRD_PARTY.md).
