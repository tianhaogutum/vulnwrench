# vulnwrench fuse report

Not observed is not proof of safety. Aliases are input assertions, not independently verified. Fixed versions are reported evidence, not remediation advice.

Inputs: 3; observations: 6; findings: 4.

Coverage: unknown; reasons: manifest-not-supplied. Coverage declarations do not establish remediation.

Full raw input documents and observation pointers are retained in JSON. This Markdown is a summary.

| Finding / package | IDs | Grype | OSV | Trivy | Severity evidence | Fix conflict |
| --- | --- | --- | --- | --- | --- | --- |
| f0001 / pkg:npm/demo@1.0 | CVE-2025-0001, GHSA-demo-0001, OSV-DEMO-0001 | observed | observed | observed | CRITICAL, HIGH &#40;conflict&#41; | true |
| f0002 / pkg:npm/demo@1.0?arch=arm64 | CVE-2025-0001, GHSA-demo-0001, OSV-DEMO-0001 | not&#95;observed | observed | not&#95;observed | MEDIUM &#40;consistent&#95;observed&#41; | false |
| f0003 / pkg:npm/demo@2.0 | CVE-2025-0001, GHSA-demo-0001, OSV-DEMO-0001 | not&#95;observed | not&#95;observed | observed | LOW &#40;consistent&#95;observed&#41; | false |
| f0004 / pkg:pypi/demo@1.0 | CVE-2025-0001, GHSA-demo-0001, OSV-DEMO-0001 | observed | not&#95;observed | not&#95;observed | LOW &#40;consistent&#95;observed&#41; | false |

## f0001

- s0001&#35;/matches/0 — grype; original ID: GHSA-demo-0001; paths: /app/node&#95;modules/demo/package.json; severity: CRITICAL; fix state: fixed; fixed versions: 1.2
- s0002&#35;/results/0/packages/0/vulnerabilities/0 — osv; original ID: OSV-DEMO-0001; paths: app/package-lock.json; severity: HIGH; fix state: fixed; fixed versions: 1.1
- s0003&#35;/Results/0/Vulnerabilities/0 — trivy; original ID: CVE-2025-0001; paths: app/package-lock.json, node&#95;modules/demo/package.json; severity: HIGH; fix state: fixed; fixed versions: 1.1

## f0002

- Absent in s0001; coverage: unknown; reasons: manifest-not-supplied; cannot establish fixed by absence.
- Absent in s0003; coverage: unknown; reasons: manifest-not-supplied; cannot establish fixed by absence.
- s0002&#35;/results/0/packages/1/vulnerabilities/0 — osv; original ID: CVE-2025-0001; paths: app/package-lock.json; severity: MEDIUM; fix state: unknown; fixed versions: not reported

## f0003

- Absent in s0001; coverage: unknown; reasons: manifest-not-supplied; cannot establish fixed by absence.
- Absent in s0002; coverage: unknown; reasons: manifest-not-supplied; cannot establish fixed by absence.
- s0003&#35;/Results/0/Vulnerabilities/1 — trivy; original ID: CVE-2025-0001; paths: app/package-lock.json; severity: LOW; fix state: fixed; fixed versions: 2.1

## f0004

- Absent in s0002; coverage: unknown; reasons: manifest-not-supplied; cannot establish fixed by absence.
- Absent in s0003; coverage: unknown; reasons: manifest-not-supplied; cannot establish fixed by absence.
- s0001&#35;/matches/1 — grype; original ID: CVE-2025-0001; paths: /app/requirements.txt; severity: LOW; fix state: not-fixed; fixed versions: not reported

## Input provenance

- s0001: grype; examples/fuse/grype.json; SHA-256 6e1a645320f7d7623a1088cd8414a95d491db3c816343212d217145219c3696f; observations 2
  - Coverage: unknown; reasons: manifest-not-supplied; target: None; scan complete: None; database timestamp: None; database identity: None; scan policy: None; manifest entry: None
- s0002: osv; examples/fuse/osv.json; SHA-256 566f71834a0dd853287da2b79c4395441c615bdefe06ab6d45867e85c7bd0db5; observations 2
  - Coverage: unknown; reasons: manifest-not-supplied; target: None; scan complete: None; database timestamp: None; database identity: None; scan policy: None; manifest entry: None
- s0003: trivy; examples/fuse/trivy.json; SHA-256 15b98d3ade943a1b89e6aa63a7d40256d0e8405829fdd53e73ae50b646063b0b; observations 2
  - Coverage: unknown; reasons: manifest-not-supplied; target: None; scan complete: None; database timestamp: None; database identity: None; scan policy: None; manifest entry: None
