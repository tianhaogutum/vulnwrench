# Synthetic examples only

Every finding, source fragment, name, email and commit here is fabricated.
`TEST-ONLY.key` is the public literal ASCII bytes
`0123456789abcdef0123456789abcdef` (32 bytes). It is deliberately committed,
never suitable for real secrets, and never generated automatically.

Git does not retain mode 0600; run `chmod 600 examples/secrets/TEST-ONLY.key` before
using the examples directly. The verification script instead makes a temporary
0600 copy, without generating any key.

- `before-gitleaks.json` and `after-gitleaks.json`: Gitleaks-shaped full arrays.
- `before-ledger.json`, `after-ledger.json`: actual CLI-generated snapshots.
- `expected-comparison.json`, `expected-comparison.md`: actual CLI outputs.
- `comparison-measurement.json`: measured synthetic baseline comparison;
  exact timing varies on reruns.
- `renames.name-status.z`: synthetic UTF-8 binary rename-only name-status fixture,
  with NUL-delimited R087/R100 records for Unicode and space-containing paths.
- `renames-path-map.json`: exact normalized, sorted importer output for that fixture;
  accepted directly by `compare --path-map`. No Git execution is needed.

`python scripts/secrets/verify_examples.py` regenerates and byte-compares all four
ledger/comparison artifacts and checks success/failure output privacy.
The before/after example includes same-line replacement, commit/line movement,
repeated occurrences, unchanged content, disappearance and unavailable content.
