import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from vulnwrench.layers import InputError
from vulnwrench.layers.cli import load_bytes

ROOT = Path(__file__).resolve().parents[2]


class CLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.report = json.loads((ROOT / 'examples/layers/trivy.json').read_text())

    def invoke(self, *args):
        return subprocess.run([sys.executable, '-m', 'vulnwrench', 'layers', *args], cwd=ROOT,
                              capture_output=True, text=True, timeout=60)

    def command(self, report=None):
        return ['explain', '--report', str(report or ROOT / 'examples/layers/trivy.json'),
                '--base-config', str(ROOT / 'examples/layers/base.json'),
                '--image-config', str(ROOT / 'examples/layers/image.json')]

    def write(self, name, value):
        path = self.directory / name
        path.write_text(json.dumps(value))
        return path

    def test_help_and_version(self):
        for args in (['--help'], ['explain', '--help'], ['--version']):
            with self.subTest(args=args):
                result = self.invoke(*args)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(result.stdout)

    def test_real_format_stdout_and_deterministic_output(self):
        result = self.invoke(*self.command())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')
        self.assertEqual(json.loads(result.stdout)['counts']['total'], 8)
        self.assertEqual(result.stdout, (ROOT / 'examples/layers/expected.json').read_text())
        self.assertEqual(result.stdout, self.invoke(*self.command()).stdout)

    def test_app_gate_exit_one_still_writes_every_finding(self):
        path = self.directory / 'output.json'
        result = self.invoke(*self.command(), '--gate', 'app', '--output', str(path))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout, '')
        doc = json.loads(path.read_text())
        self.assertEqual(doc['counts']['total'], 8)
        self.assertEqual(doc['gate']['blockingFindings'], 7)
        self.assertEqual(doc['counts']['unknown'], 5)

    def test_base_only_passes_app_gate_but_all_fails(self):
        self.report['Results'][0]['Vulnerabilities'] = self.report['Results'][0]['Vulnerabilities'][:1]
        path = self.write('base-only.json', self.report)
        self.assertEqual(self.invoke(*self.command(path), '--gate', 'app').returncode, 0)
        self.assertEqual(self.invoke(*self.command(path), '--gate', 'all').returncode, 1)

    def test_unknown_only_fails_closed(self):
        self.report['Results'][0]['Vulnerabilities'] = self.report['Results'][0]['Vulnerabilities'][3:4]
        path = self.write('unknown.json', self.report)
        result = self.invoke(*self.command(path), '--gate', 'app')
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)['counts']['unknown'], 1)

    def test_digest_map_cli(self):
        result = self.invoke(*self.command(), '--digest-map', str(ROOT / 'examples/layers/digest-map.json'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['counts']['app'], 3)

    def manifest_command(self):
        return [*self.command(), '--image-manifest', str(ROOT / 'examples/layers/image-manifest.json'),
                '--digest-map', str(ROOT / 'examples/layers/manifest-digest-map.json')]

    def test_manifest_cli_binding_counts_gate_and_determinism(self):
        result = self.invoke(*self.manifest_command(), '--gate', 'app')
        self.assertEqual(result.returncode, 1, result.stderr)
        doc = json.loads(result.stdout)
        self.assertEqual(doc['counts'], {'base': 1, 'app': 3, 'unknown': 4, 'total': 8})
        self.assertEqual(doc['ancestry']['imageManifestBinding']['status'], 'verified_local')
        self.assertFalse(doc['ancestry']['imageManifestBinding']['layerContentVerified'])
        self.assertEqual(doc['ancestry']['reportConfigBinding'], 'diff_ids_consistent')
        self.assertEqual(result.stdout, self.invoke(*self.manifest_command(), '--gate', 'app').stdout)

    def test_manifest_rejections_preserve_output(self):
        manifest = json.loads((ROOT / 'examples/layers/image-manifest.json').read_text())
        manifest['layers'].reverse()
        reordered = self.write('reordered.json', manifest)
        incomplete = self.write('missing-map.json', {})
        tampered = self.directory / 'tampered.json'
        tampered.write_bytes((ROOT / 'examples/layers/image.json').read_bytes().replace(b'amd64', b'arm64'))
        invalid = self.directory / 'invalid.json'
        invalid.write_bytes(b'{"mediaType":"SECRET", "mediaType":"duplicate"}')
        output = self.directory / 'out.json'
        output.write_text('preserved')
        for extra, error in [(['--image-config', str(tampered)], 'config digest mismatch'),
                             (['--image-manifest', str(reordered)], 'ordered layer mapping mismatch'),
                             (['--digest-map', str(incomplete)], 'missing layer mapping'),
                             (['--image-manifest', str(invalid)], 'duplicate object keys')]:
            with self.subTest(error=error):
                result = self.invoke(*self.manifest_command(), *extra, '--output', str(output))
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, '')
                self.assertIn(error, result.stderr)
                self.assertNotIn('SECRET', result.stderr)
                self.assertEqual(output.read_text(), 'preserved')
        # No map flag must also fail, rather than zipping descriptors with DiffIDs.
        result = self.invoke(*self.command(), '--image-manifest', str(ROOT / 'examples/layers/image-manifest.json'))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('missing layer mapping', result.stderr)

    def test_manifest_input_alias_cannot_be_replaced(self):
        manifest = self.write('manifest.json', json.loads((ROOT / 'examples/layers/image-manifest.json').read_text()))
        before = manifest.read_bytes()
        alias = self.directory / 'manifest-alias.json'
        alias.symlink_to(manifest)
        result = self.invoke(*self.manifest_command(), '--image-manifest', str(manifest),
                             '--output', str(alias))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(manifest.read_bytes(), before)

    def test_local_byte_reader_is_bounded(self):
        path = self.directory / 'bounded.json'
        path.write_bytes(b'123456789')
        with patch('vulnwrench.layers.cli.MAX_INPUT_BYTES', 8):
            with self.assertRaisesRegex(InputError, '32 MiB limit'):
                load_bytes(path, 'input')

    def test_nonprefix_is_rejected_without_output(self):
        path = self.directory / 'out.json'
        result = self.invoke(*self.command(), '--base-config', str(ROOT / 'examples/layers/non-prefix-base.json'),
                             '--output', str(path))
        self.assertEqual(result.returncode, 2)
        self.assertFalse(path.exists())
        self.assertEqual(result.stdout, '')
        self.assertIn('exact prefix', result.stderr)

    def test_unsupported_nonimage(self):
        self.report['ArtifactType'] = 'filesystem'
        result = self.invoke(*self.command(self.write('fs.json', self.report)))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, '')
        self.assertIn('container_image', result.stderr)

    def test_invalid_input_does_not_replace_existing_output(self):
        bad = self.write('bad.json', {'SchemaVersion': 99})
        output = self.directory / 'output.json'
        output.write_text('preserved')
        result = self.invoke(*self.command(bad), '--output', str(output))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(output.read_text(), 'preserved')

    def test_input_alias_replacement_is_rejected(self):
        path = self.write('input.json', self.report)
        before = path.read_bytes()
        symlink = self.directory / 'link.json'
        symlink.symlink_to(path)
        hardlink = self.directory / 'hardlink.json'
        os.link(path, hardlink)
        for output in (path, symlink, hardlink):
            with self.subTest(output=output):
                result = self.invoke(*self.command(path), '--output', str(output))
                self.assertEqual(result.returncode, 2)
                self.assertEqual(path.read_bytes(), before)

    def test_io_errors_do_not_echo_paths_or_secrets(self):
        missing = self.directory / 'SECRET-PATH.json'
        result = self.invoke(*self.command(missing))
        self.assertEqual(result.returncode, 2)
        self.assertNotIn('SECRET-PATH', result.stderr)
        self.assertNotIn('Traceback', result.stderr)
        result = self.invoke(*self.command(), '--output', str(missing / 'out.json'))
        self.assertEqual(result.returncode, 2)
        self.assertNotIn('SECRET-PATH', result.stderr)

    def test_bad_json_and_invalid_utf8_are_quiet(self):
        for raw in (b'{"SECRET":"unterminated', b'\xff', b'[]', b'{"x": NaN}',
                    b'{"x": 1, "x": 2}', b'[' * 2000):
            with self.subTest(raw=raw[:20]):
                path = self.directory / 'bad.json'
                path.write_bytes(raw)
                result = self.invoke(*self.command(path))
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, '')
                self.assertNotIn('SECRET', result.stderr)
                self.assertNotIn('Traceback', result.stderr)

    def test_malformed_layer_error_does_not_echo_secret(self):
        self.report['Results'][0]['Vulnerabilities'][0]['Layer']['DiffID'] = 'SECRET-DIFFID'
        path = self.write('bad-layer.json', self.report)
        result = self.invoke(*self.command(path))
        self.assertEqual(result.returncode, 2)
        self.assertIn('DiffID', result.stderr)
        self.assertNotIn('SECRET-DIFFID', result.stderr)

    def test_bad_cli_arguments_do_not_echo_values(self):
        result = self.invoke(*self.command(), '--gate', 'SECRET-VALUE')
        self.assertEqual(result.returncode, 2)
        self.assertNotIn('SECRET-VALUE', result.stderr)

    def test_no_input_code_execution(self):
        marker = self.directory / 'MUST-NOT-EXIST'
        image = json.loads((ROOT / 'examples/layers/image.json').read_text())
        image['history'][3]['created_by'] = f'touch {marker}'
        image['config'] = {'Entrypoint': ['touch', str(marker)]}
        path = self.write('inert-config.json', image)
        result = self.invoke(*self.command(), '--image-config', str(path))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(marker.exists())
        self.assertEqual(json.loads(result.stdout)['groups']['app'][0]['history'][0]['createdBy'],
                         f'touch {marker}')


if __name__ == '__main__':
    unittest.main()
