"""Raw numeric parsing: finite floats only, after byte integrity checks.

Parsed dictionaries remain a separate caller-owned JSON-compatible input contract.
Maps have no extension schema; numeric overflow must reject before map validation.
"""
from copy import deepcopy
import hashlib
import json
import math
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from vulnwrench.layers import InputError, compare, explain
from vulnwrench.layers._inputs import parse_json
from test_base_manifest import A, B, C, D, E, F, manifest_for

ROOT = Path(__file__).resolve().parents[2]
OVERFLOW = (b'1e9999', b'-1e9999')


def digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def extension(value, token):
    separator = b',' if value else b''
    return json.dumps(value).encode()[:-1] + separator + b'"PRIVATE_NUMBER":{"nested":[{"value":' + token + b'}]}}'


class JsonNumberTests(unittest.TestCase):
    def setUp(self):
        self.inputs = {key: json.loads((ROOT / 'examples' / 'layers' / name).read_bytes())
                       for key, name in [('report', 'upgrade-after.json'),
                                         ('base_config', 'upgraded-base.json'),
                                         ('image_config', 'upgraded-image.json')]}

    def compare_inputs(self):
        return {side + '_' + key: value for side in ('before', 'after')
                for key, value in self.inputs.items()}

    def raw_inputs(self):
        return self.inputs | dict(base_manifest=manifest_for(json.dumps(self.inputs['base_config']).encode(), [E, F]),
                                 image_manifest=manifest_for(json.dumps(self.inputs['image_config']).encode(), [E, F, A]),
                                 digest_map={E: D, F: B, A: C}, base_digest_map={E: D, F: B}, target_map={})

    def test_pinned_image_config_overflow_rejected_before_returning_provenance(self):
        # Before the fix this returns infinity in provenance; allow_nan=False fails.
        raw = extension(self.inputs['image_config'], b'1e9999')
        with self.assertRaisesRegex(InputError, 'non-finite'):
            explain(**(self.inputs | dict(image_config=raw, image_config_sha256=digest(raw))))

    def test_shared_parser_rejects_overflow_at_any_depth_without_echo(self):
        for token in OVERFLOW:
            for raw in (b'{"PRIVATE_NUMBER":'+token+b'}',
                        b'{"PRIVATE_NUMBER":[[0,{"nested":'+token+b'}]]}'):
                with self.subTest(raw=raw), self.assertRaisesRegex(InputError, 'non-finite') as err:
                    parse_json(raw, 'document')
                self.assertNotIn('PRIVATE_NUMBER', str(err.exception))
                self.assertNotIn(token.decode(), str(err.exception))

    def test_every_pinned_boundary_hashes_before_numeric_parsing(self):
        for field, value in self.raw_inputs().items():
            for token in OVERFLOW:
                raw = extension(value, token)
                for pin, error in ((digest(b'wrong'), 'digest mismatch'), (digest(raw), 'non-finite')):
                    with self.subTest(field=field, token=token, pin=pin), self.assertRaisesRegex(InputError, error):
                        changes = {field: raw, field+'_sha256': pin}
                        if field == 'target_map':
                            compare(**self.compare_inputs(), **changes)
                        else:
                            explain(**(self.inputs | changes))

    def test_both_compare_snapshots_reject_each_pinned_numeric_boundary(self):
        for side in ('before', 'after'):
            for field, value in self.raw_inputs().items():
                if field == 'target_map':
                    continue
                for token in OVERFLOW:
                    raw = extension(value, token)
                    changes = {side+'_'+field: raw, side+'_'+field+'_sha256': digest(raw)}
                    with self.subTest(side=side, field=field, token=token), self.assertRaisesRegex(InputError, 'non-finite'):
                        compare(**(self.compare_inputs() | changes))

    def test_manifest_size_and_hash_precede_config_numeric_parsing(self):
        for source, digests, mapping in (('base', [E, F], {E: D, F: B}),
                                         ('image', [E, F, A], {E: D, F: B, A: C})):
            field = source+'_config'; map_field = 'base_digest_map' if source == 'base' else 'digest_map'
            for token in OVERFLOW:
                raw = extension(self.inputs[field], token)
                manifest = manifest_for(raw, digests)
                for pinned in (False, True):
                    changes = {field: raw, source+'_manifest': manifest, map_field: mapping}
                    if pinned:
                        changes[field+'_sha256'] = digest(raw)
                    for changed, error in ((manifest | dict(config=manifest['config'] | dict(size=len(raw)+1)), 'config size mismatch'),
                                           (manifest | dict(config=manifest['config'] | dict(digest=digest(b'wrong'))), 'config digest mismatch'),
                                           (manifest, 'non-finite')):
                        changes[source+'_manifest'] = changed
                        with self.subTest(source=source, token=token, pinned=pinned, error=error), self.assertRaisesRegex(InputError, error):
                            explain(**(self.inputs | changes))

    def test_size_limit_precedes_hash_for_all_pinned_boundaries(self):
        for field, value in self.raw_inputs().items():
            raw = extension(value, b'1e9999')
            changes = {field: raw, field+'_sha256': digest(raw)}
            module = 'comparison' if field == 'target_map' else 'core'
            with self.subTest(field=field), patch('vulnwrench.layers.'+module+'.MAX_INPUT_BYTES', len(raw)-1), \
                 patch('vulnwrench.layers.'+module+'.hashlib.sha256') as hashed:
                with self.assertRaisesRegex(InputError, 'input exceeds 32 MiB limit'):
                    if field == 'target_map':
                        compare(**self.compare_inputs(), **changes)
                    else:
                        explain(**(self.inputs | changes))
                hashed.assert_not_called()
        with patch('vulnwrench.layers._inputs.MAX_INPUT_BYTES', 1), self.assertRaisesRegex(InputError, 'input exceeds'):
            parse_json(b'{"n":1e9999}', 'document')

    def test_existing_strict_json_controls(self):
        for raw, message in ((b'{"PRIVATE":1,"PRIVATE":2}', 'duplicate object keys'),
                             (b'{"n":NaN}', 'non-finite'), (b'{"n":Infinity}', 'non-finite'),
                             (b'{"n":-Infinity}', 'non-finite'), (b'\xff', 'invalid UTF-8 JSON'),
                             (b'[]', 'expected JSON object'), (b'1.0', 'expected JSON object'),
                             (b'{"PRIVATE":', 'invalid UTF-8 JSON')):
            with self.subTest(raw=raw), self.assertRaisesRegex(InputError, message):
                parse_json(raw, 'document')

    def test_finite_numbers_keep_values_types_and_serialization(self):
        raw = b'{"nested":[1e3,-2.5e-2,0,-0.0,123456789012345678901234567890,1.25,1e-9999,1.7976931348623157e308]}'
        result = parse_json(raw, 'document'); expected = json.loads(raw)
        self.assertEqual(result, expected)
        self.assertEqual([type(x) for x in result['nested']], [type(x) for x in expected['nested']])
        self.assertEqual(math.copysign(1, result['nested'][3]), -1)
        self.assertEqual(json.dumps(result, allow_nan=False), json.dumps(expected, allow_nan=False))
        for field in ('report', 'base_config', 'image_config'):
            raw = extension(self.inputs[field], b'1.25e2')
            parsed_inputs = self.inputs | {field: json.loads(raw)}
            expected = explain(**parsed_inputs)
            original = deepcopy(parsed_inputs)
            result = explain(**(self.inputs | {field: raw, field+'_sha256': digest(raw)}))
            prefix = {'report':'report', 'base_config':'baseConfig', 'image_config':'imageConfig'}[field]
            self.assertEqual(result['provenance'].pop(prefix+'Digest'), digest(raw))
            self.assertEqual(result['provenance'].pop(prefix+'PinAgreement'), 'matched_local')
            self.assertEqual(json.dumps(result, allow_nan=False), json.dumps(expected, allow_nan=False))
            self.assertEqual(parsed_inputs, original)


class JsonNumberCliTests(unittest.TestCase):
    def test_all_cli_raw_inputs_reject_overflow_with_sanitized_output_preservation(self):
        inputs = JsonNumberTests(); inputs.setUp()
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp); output = directory/'out.json'
            plain = ['explain']
            for field, value in inputs.inputs.items():
                path = directory/(field+'.json'); path.write_text(json.dumps(value))
                plain += ['--'+field.replace('_','-'), str(path)]
            for field, value in inputs.raw_inputs().items():
                for token in OVERFLOW:
                    raw = extension(value, token)
                    path = directory/('PRIVATE_'+field+'.json'); path.write_bytes(raw)
                    for pinned in (False, True):
                        args = plain.copy()
                        if field == 'target_map':
                            args = ['compare']
                            for side in ('before', 'after'):
                                for flag, val in zip(plain[1::2], plain[2::2]):
                                    args += ['--'+side+'-'+flag[2:], val]
                        flag = '--'+field.replace('_','-')
                        if flag in args:
                            args[args.index(flag)+1] = str(path)
                        else:
                            args += [flag, str(path)]
                        if pinned:
                            args += [flag+'-sha256', digest(raw)]
                        output.write_bytes(b'KEEP')
                        with self.subTest(field=field, token=token, pinned=pinned):
                            proc = subprocess.run([sys.executable, '-m', 'vulnwrench', 'layers', *args, '--output', str(output)],
                                                  cwd=ROOT, capture_output=True, timeout=60)
                            self.assertEqual(proc.returncode, 2, proc.stderr)
                            self.assertEqual(proc.stdout, b'')
                            self.assertIn(b'non-finite', proc.stderr)
                            self.assertNotIn(b'PRIVATE', proc.stderr)
                            self.assertNotIn(str(directory).encode(), proc.stderr)
                            self.assertNotIn(token, proc.stderr)
                            self.assertNotIn(b'Traceback', proc.stderr)
                            self.assertEqual(output.read_bytes(), b'KEEP')
                            self.assertEqual(path.read_bytes(), raw)


if __name__ == '__main__':
    unittest.main()
