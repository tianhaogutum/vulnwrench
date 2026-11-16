#!/usr/bin/env python3
"""Regenerate synthetic examples via the real CLI; assert committed bytes/privacy."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / 'examples' / 'secrets'
# Run the CLI from this clone, installed or not.
ENV = {**os.environ, 'PYTHONPATH': os.pathsep.join(filter(None, (str(ROOT / 'src'), os.environ.get('PYTHONPATH'))))}


def main():
    reports = [json.loads((EXAMPLES / name).read_text())
               for name in ('before-gitleaks.json', 'after-gitleaks.json')]
    sensitive = {row[field] for rows in reports for row in rows
                 for field in ('Secret', 'Match', 'Author', 'Email', 'Message', 'Description')
                 if isinstance(row.get(field), str) and row[field]}
    with tempfile.TemporaryDirectory(prefix='vulnwrench-secrets-examples-') as directory:
        temp = Path(directory)
        key = temp / 'TEST-ONLY.key'
        key.write_bytes((EXAMPLES / 'TEST-ONLY.key').read_bytes())
        key.chmod(0o600)  # Git does not preserve POSIX read/write mode bits.
        def run(*args, expected=0):
            result = subprocess.run([sys.executable, '-m', 'vulnwrench', 'secrets', *map(str, args)],
                                    cwd=ROOT, env=ENV, text=True, capture_output=True, timeout=60)
            assert result.returncode == expected, 'unexpected CLI exit code'
            for raw in sensitive:
                assert raw not in result.stdout + result.stderr, 'CLI leaked synthetic sensitive data'
            return result
        before = temp / 'before-ledger.json'
        run('snapshot', '--key-file', key, '--report', EXAMPLES / 'before-gitleaks.json', '--output', before)
        out, after, md = [temp / n for n in ('expected-comparison.json', 'after-ledger.json', 'expected-comparison.md')]
        run('compare', '--key-file', key, '--before', before,
            '--report', EXAMPLES / 'after-gitleaks.json', '--output', out,
            '--ledger-output', after, '--markdown', md)
        for artifact in (before, out, after, md):
            assert artifact.read_bytes() == (EXAMPLES / artifact.name).read_bytes(), 'example drift'
            text = artifact.read_text()
            assert all(raw not in text for raw in sensitive), 'artifact leaked sensitive data'
            assert '"Secret"' not in text and '"Match"' not in text
        summary = json.loads(out.read_text())['summary']
        assert summary == {'unchanged': 1, 'same_secret_moved': 1, 'new_content_same_location': 1,
                           'new_content': 0, 'absent': 2, 'uncomparable': 2}
        failed = temp / 'must-not-exist.json'
        malformed = temp / 'malformed.json'
        malformed.write_text('{"Secret":"SYNTHETIC_SECRET_A_000000"')
        run('snapshot', '--key-file', key, '--report', malformed, '--output', failed, expected=2)
        assert not failed.exists()
        print('PASS: 4 byte-identical generated artifacts; snapshot/compare CLI; privacy; failure path')
        print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
