import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ExampleScriptsTests(unittest.TestCase):
    def test_all_documented_examples(self):
        result = subprocess.run([sys.executable, 'scripts/layers/verify_examples.py'], cwd=ROOT,
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Verified 8 CLI examples', result.stdout)

    def test_comparison_covers_all_findings_and_matches_saved_measurement(self):
        result = subprocess.run([sys.executable, 'scripts/layers/compare_naive.py'], cwd=ROOT,
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        measured = json.loads(result.stdout)
        self.assertEqual(measured, json.loads((ROOT / 'examples/layers/comparison-result.json').read_text()))
        self.assertEqual(measured['cases'], 8)
        self.assertEqual(measured['baseline']['attributionErrors'], 6)
        self.assertEqual(measured['exactEvidence']['attributionErrors'], 0)
        self.assertEqual(measured['exactEvidence']['unknownRetained'], 5)


if __name__ == '__main__':
    unittest.main()
