#!/usr/bin/env python3
"""Re-run documented CLI examples in an isolated temporary directory, offline."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def main():
    common = [sys.executable, '-m', 'vulnwrench', 'layers', 'explain', '--report', 'examples/layers/trivy.json',
              '--base-config', 'examples/layers/base.json', '--image-config', 'examples/layers/image.json']
    with tempfile.TemporaryDirectory(prefix='.verify-', dir=ROOT) as directory:
        output = Path(directory) / 'out.json'
        checks = [
            ([], 0, {'base': 1, 'app': 2, 'unknown': 5, 'total': 8}),
            (['--gate', 'app'], 1, {'base': 1, 'app': 2, 'unknown': 5, 'total': 8}),
            (['--digest-map', 'examples/layers/digest-map.json'], 0,
             {'base': 1, 'app': 3, 'unknown': 4, 'total': 8}),
            (['--image-manifest', 'examples/layers/image-manifest.json',
              '--digest-map', 'examples/layers/manifest-digest-map.json'], 0,
             {'base': 1, 'app': 3, 'unknown': 4, 'total': 8}),
        ]
        for extra, code, counts in checks:
            result = subprocess.run([*common, *extra, '--output', str(output)], cwd=ROOT,
                                    capture_output=True, text=True, timeout=60)
            assert result.returncode == code, (result.returncode, result.stderr)
            assert result.stderr == '' and result.stdout == ''
            doc = json.loads(output.read_text())
            assert doc['counts'] == counts, doc['counts']
            assert doc['provenance']['report'] == json.loads((ROOT / 'examples/layers/trivy.json').read_text())
            if '--image-manifest' in extra:
                assert doc['ancestry']['imageManifestBinding']['status'] == 'verified_local'
                assert doc['ancestry']['imageManifestBinding']['layerContentVerified'] is False
            if not extra:
                assert output.read_bytes() == (ROOT / 'examples/layers/expected.json').read_bytes()
                assert doc['groups']['app'][0]['history'][0]['historyIndex'] == 3
        output.unlink()
        result = subprocess.run([*common, '--base-config', 'examples/layers/non-prefix-base.json',
                                 '--output', str(output)], cwd=ROOT,
                                capture_output=True, text=True, timeout=60)
        assert result.returncode == 2 and not output.exists(), result.stderr
        result = subprocess.run([
            sys.executable, '-m', 'vulnwrench', 'layers', 'compare',
            '--before-report', 'examples/layers/upgrade-before.json',
            '--before-base-config', 'examples/layers/base.json', '--before-image-config', 'examples/layers/image.json',
            '--after-report', 'examples/layers/upgrade-after.json',
            '--after-base-config', 'examples/layers/upgraded-base.json',
            '--after-image-config', 'examples/layers/upgraded-image.json', '--output', str(output)],
            cwd=ROOT, capture_output=True, text=True, timeout=60)
        assert result.returncode == 0, result.stderr
        assert output.read_bytes() == (ROOT / 'examples/layers/upgrade-expected.json').read_bytes()
        original_comparison = json.loads(output.read_text())
        result = subprocess.run([
            sys.executable, '-m', 'vulnwrench', 'layers', 'compare',
            '--before-report', 'examples/layers/upgrade-before.json',
            '--before-base-config', 'examples/layers/base.json', '--before-image-config', 'examples/layers/image.json',
            '--after-report', 'examples/layers/upgrade-renamed-after.json',
            '--after-base-config', 'examples/layers/upgraded-base.json',
            '--after-image-config', 'examples/layers/upgraded-image.json',
            '--target-map', 'examples/layers/target-map.json', '--output', str(output)],
            cwd=ROOT, capture_output=True, text=True, timeout=60)
        assert result.returncode == 0, result.stderr
        mapped = json.loads(output.read_text())
        assert mapped['counts'] == original_comparison['counts']
        assert mapped['targetMap'] == {'synthetic-upgrade': 'synthetic-upgrade:v2'}
        for old, new in zip(original_comparison['rows'], mapped['rows'], strict=True):
            assert all(new[key] == value for key, value in old.items())
            assert new['beforeTarget'] == 'synthetic-upgrade'
            assert new['afterTarget'] == 'synthetic-upgrade:v2'
        assert mapped['snapshots']['before'] == original_comparison['snapshots']['before']
        assert mapped['snapshots']['after']['provenance']['report'] == json.loads(
            (ROOT / 'examples/layers/upgrade-renamed-after.json').read_text())
        result = subprocess.run([
            sys.executable, '-m', 'vulnwrench', 'layers', 'explain',
            '--report', 'examples/layers/upgrade-after.json', '--base-config', 'examples/layers/upgraded-base.json',
            '--image-config', 'examples/layers/upgraded-image.json',
            '--base-manifest', 'examples/layers/upgraded-base-manifest.json',
            '--base-digest-map', 'examples/layers/upgraded-base-digest-map.json', '--output', str(output)],
            cwd=ROOT, capture_output=True, text=True, timeout=60)
        assert result.returncode == 0, result.stderr
        doc = json.loads(output.read_text())
        assert doc['counts'] == {'base': 1, 'app': 0, 'unknown': 1, 'total': 2}
        assert doc['ancestry']['baseManifestBinding'] == {
            'status': 'verified_local', 'orderedLayerCount': 2, 'layerContentVerified': False,
            'configDigest': json.loads((ROOT / 'examples/layers/upgraded-base-manifest.json').read_text())['config']['digest']}
        assert doc['provenance']['baseDigestMap'] == json.loads(
            (ROOT / 'examples/layers/upgraded-base-digest-map.json').read_text())
        assert 'imageManifestBinding' not in doc['ancestry']
    print('Verified 8 CLI examples: exact attribution, fail-closed gate, explicit mapping, local manifest binding, invalid ancestry, base-upgrade comparison, explicit target correspondence, base-manifest boundary.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
