#!/usr/bin/env python3
"""Compare attribution correctness, not throughput, on labeled synthetic cases."""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))
from vulnwrench.layers import explain  # noqa: E402


def read(name):
    return json.loads((ROOT / 'examples' / 'layers' / name).read_text())


def compare():
    report, base, image, labels = (read(name) for name in
                                   ('trivy.json', 'base.json', 'image.json', 'comparison.json'))
    expected = labels['expected']
    names = set(labels['basePackageNames'])
    attributed = explain(report, base, image)
    exact = {f['finding']['VulnerabilityID']: f['origin']
             for group in attributed['groups'].values() for f in group}
    findings = [f for result in report['Results'] for f in result.get('Vulnerabilities', [])]
    naive = {f['VulnerabilityID']: 'base' if f['PkgName'] in names else 'app' for f in findings}
    assert len(expected) == len(exact) == len(findings), 'Comparison must cover every finding exactly once'
    assert set(expected) == set(exact) == set(naive), 'Labels and results must agree'
    rows = [{'id': key, 'expected': expected[key], 'nameOnly': naive[key], 'exactEvidence': exact[key]}
            for key in expected]
    summary = {
        'cases': len(rows),
        'baseline': {'method': 'Name-only base package subtraction',
                     'attributionErrors': sum(r['nameOnly'] != r['expected'] for r in rows),
                     'falseBaseAttributions': sum(r['nameOnly'] == 'base' and r['expected'] != 'base' for r in rows)},
        'exactEvidence': {'attributionErrors': sum(r['exactEvidence'] != r['expected'] for r in rows),
                          'unknownRetained': attributed['counts']['unknown']},
        'casesDetail': rows,
        'scope': 'Synthetic correctness comparison; unknown means insufficient evidence, not ground-truth origin. No throughput claim.',
    }
    assert summary['exactEvidence']['attributionErrors'] == 0, 'Exact classifier diverged from safety labels'
    assert summary['baseline']['attributionErrors'] > 0, 'Fixtures must exercise naive failure modes'
    return summary


def main():
    print(json.dumps(compare(), indent=2, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
