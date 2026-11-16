"""Raw container-depth boundary; parsed dictionary contracts stay caller-owned."""
import hashlib
import json
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
LIMIT = 128  # Contract: root object is 1; nested objects/arrays each add 1.


def digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def extension(value, depth, kind='array'):
    """Build exact container depth without depending on recursive serialization."""
    pairs = {'array': (b'[', b']'), 'object': (b'{"x":', b'}')}
    opening, closing = pairs[kind]
    raw = json.dumps(value).encode()
    return (raw[:-1] + (b',' if value else b'') + b'"PRIVATE_DEPTH":' +
            opening * (depth - 1) + b'0' + closing * (depth - 1) + b'}')


class JsonDepthTests(unittest.TestCase):
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

    def test_pinned_image_config_600_arrays_rejects_before_provenance_copy(self):
        # Before the fix parse_json succeeds, then explain leaks RecursionError.
        raw = extension(self.inputs['image_config'], 601)
        with self.assertRaisesRegex(InputError, 'nesting exceeds 128 levels'):
            explain(**(self.inputs | dict(image_config=raw, image_config_sha256=digest(raw))))

    def test_exact_limit_for_arrays_objects_and_mixed_containers(self):
        for kind in ('array', 'object'):
            raw = extension({}, LIMIT, kind)
            with self.subTest(kind=kind):
                self.assertEqual(parse_json(raw, 'document'), json.loads(raw))
                for depth in (LIMIT + 1, 601, 10001):
                    raw = extension({}, depth, kind)
                    with self.subTest(depth=depth), self.assertRaisesRegex(InputError, 'nesting exceeds 128 levels') as err:
                        parse_json(raw, 'document')
                    self.assertNotIn('PRIVATE_DEPTH', str(err.exception))
        for depth in (LIMIT, LIMIT+1):
            raw = b'{"x":' + b'[{"x":' * ((depth-2)//2) + b'[]' + b'}]' * ((depth-2)//2) + b'}'
            # Explicit mixed shape is root + pairs of array/object + empty array.
            if depth == LIMIT:
                self.assertEqual(parse_json(raw, 'document'), json.loads(raw))
            else:
                raw = b'{"x":' + raw + b'}'
                with self.assertRaisesRegex(InputError, 'nesting exceeds 128 levels'):
                    parse_json(raw, 'document')

    def test_strings_escapes_empty_containers_and_siblings(self):
        # Quoted brackets/braces, escaped quotes and backslashes add no depth.
        text = '[{\\\"' * 1000 + '}]' * 1000
        raw = json.dumps({text: [text, {}, [], '\\', '"', '\\"', '雪'] * 1000}).encode()
        self.assertEqual(parse_json(raw, 'document'), json.loads(raw))
        for container in (b'[]', b'{}'):
            for depth in (LIMIT, LIMIT+1):
                raw = b'{"x":' + b'[' * (depth-2) + container + b']' * (depth-2) + b'}'
                if depth == LIMIT:
                    self.assertEqual(parse_json(raw, 'document'), json.loads(raw))
                else:
                    with self.assertRaisesRegex(InputError, 'nesting exceeds 128 levels'):
                        parse_json(raw, 'document')

    def test_each_pinned_boundary_hash_before_depth_check(self):
        for field, value in self.raw_inputs().items():
            raw = extension(value, LIMIT+1)
            for pin, error in ((digest(b'wrong'), 'digest mismatch'), (digest(raw), 'nesting exceeds 128 levels')):
                changes = {field: raw, field+'_sha256': pin}
                with self.subTest(field=field, pin=pin), self.assertRaisesRegex(InputError, error):
                    if field == 'target_map':
                        compare(**self.compare_inputs(), **changes)
                    else:
                        explain(**(self.inputs | changes))

    def test_both_comparison_snapshots_reject_each_raw_depth_boundary(self):
        for side in ('before', 'after'):
            for field, value in self.raw_inputs().items():
                if field == 'target_map':
                    continue
                raw = extension(value, LIMIT+1)
                changes = {side+'_'+field: raw, side+'_'+field+'_sha256': digest(raw)}
                with self.subTest(side=side, field=field), self.assertRaisesRegex(InputError, 'nesting exceeds 128 levels'):
                    compare(**(self.compare_inputs() | changes))

    def test_size_before_hash_and_depth_checks(self):
        for field, value in self.raw_inputs().items():
            raw = extension(value, LIMIT+1)
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
            parse_json(extension({}, LIMIT+1), 'document')

    def test_manifest_config_size_and_hash_precede_depth_with_or_without_pin(self):
        for source, digests, mapping in (('base', [E, F], {E: D, F: B}),
                                         ('image', [E, F, A], {E: D, F: B, A: C})):
            field = source+'_config'; map_field = 'base_digest_map' if source == 'base' else 'digest_map'
            raw = extension(self.inputs[field], LIMIT+1)
            manifest = manifest_for(raw, digests)
            for pinned in (False, True):
                changes = {field: raw, source+'_manifest': manifest, map_field: mapping}
                if pinned:
                    changes[field+'_sha256'] = digest(raw)
                for changed, error in ((manifest | dict(config=manifest['config'] | dict(size=len(raw)+1)), 'config size mismatch'),
                                       (manifest | dict(config=manifest['config'] | dict(digest=digest(b'wrong'))), 'config digest mismatch'),
                                       (manifest, 'nesting exceeds 128 levels')):
                    changes[source+'_manifest'] = changed
                    with self.subTest(source=source, pinned=pinned, error=error), self.assertRaisesRegex(InputError, error):
                        explain(**(self.inputs | changes))

    def test_at_limit_metadata_is_copied_and_serializes_in_explain_and_compare(self):
        for field in ('report', 'base_config', 'image_config', 'base_manifest', 'image_manifest'):
            for kind in ('array', 'object'):
                raw = extension(self.raw_inputs()[field], LIMIT, kind)
                changes = {field: raw, field+'_sha256': digest(raw)}
                if field.endswith('_manifest'):
                    source = field[:-9]
                    changes[source+'_config'] = json.dumps(self.inputs[source+'_config']).encode()
                    changes['base_digest_map' if source == 'base' else 'digest_map'] = {E: D, F: B} if source == 'base' else {E: D, F: B, A: C}
                expected_inputs = self.inputs | changes
                expected_inputs[field] = json.loads(raw)
                del expected_inputs[field+'_sha256']
                expected = explain(**expected_inputs)
                with self.subTest(field=field, kind=kind):
                    output = explain(**(self.inputs | changes))
                    prefix = {'report':'report', 'base_config':'baseConfig', 'image_config':'imageConfig',
                              'base_manifest':'baseManifest', 'image_manifest':'imageManifest'}[field]
                    self.assertEqual(output['provenance'][prefix], json.loads(raw))
                    if field.endswith('_manifest'):
                        binding = output['ancestry'][prefix+'Binding']
                        self.assertEqual(binding.pop('manifestDigest'), digest(raw))
                        self.assertEqual(binding.pop('manifestPinAgreement'), 'matched_local')
                    else:
                        self.assertEqual(output['provenance'].pop(prefix+'Digest'), digest(raw))
                        self.assertEqual(output['provenance'].pop(prefix+'PinAgreement'), 'matched_local')
                    self.assertEqual(json.dumps(output, allow_nan=False), json.dumps(expected, allow_nan=False))
                    both = self.compare_inputs() | {side+'_'+key: value for side in ('before','after') for key,value in changes.items()}
                    result = compare(**both)
                    json.dumps(result, allow_nan=False)
                    self.assertEqual(result['snapshots']['before']['provenance'][prefix], json.loads(raw))
                    self.assertEqual(result['snapshots']['after']['provenance'][prefix], json.loads(raw))

    def test_parsed_dictionaries_are_not_subject_to_raw_limit(self):
        # Above the raw limit but still below Python's default copy recursion bound.
        value = json.loads(extension(self.inputs['image_config'], LIMIT+1))
        with patch('vulnwrench.layers.core.parse_json', side_effect=AssertionError('raw parsing')):
            output = explain(**(self.inputs | dict(image_config=value)))
        self.assertEqual(output['provenance']['imageConfig'], value)
        self.assertIsNot(output['provenance']['imageConfig']['PRIVATE_DEPTH'], value['PRIVATE_DEPTH'])


class JsonDepthCliTests(unittest.TestCase):
    def test_all_raw_cli_inputs_preserve_output_on_excessive_nesting(self):
        inputs = JsonDepthTests(); inputs.setUp()
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp); output = directory/'out.json'
            plain = ['explain']
            for field, value in inputs.inputs.items():
                path = directory/(field+'.json'); path.write_text(json.dumps(value))
                plain += ['--'+field.replace('_','-'), str(path)]
            for field, value in inputs.raw_inputs().items():
                raw = extension(value, LIMIT+1)
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
                    with self.subTest(field=field, pinned=pinned):
                        proc = subprocess.run([sys.executable, '-m', 'vulnwrench', 'layers', *args, '--output', str(output)],
                                              cwd=ROOT, capture_output=True, timeout=60)
                        self.assertEqual(proc.returncode, 2, proc.stderr)
                        self.assertEqual(proc.stdout, b'')
                        self.assertIn(b'JSON nesting exceeds 128 levels', proc.stderr)
                        self.assertNotIn(b'PRIVATE', proc.stderr)
                        self.assertNotIn(str(directory).encode(), proc.stderr)
                        self.assertNotIn(b'Traceback', proc.stderr)
                        self.assertEqual(output.read_bytes(), b'KEEP')
                        self.assertEqual(path.read_bytes(), raw)


if __name__ == '__main__':
    unittest.main()
