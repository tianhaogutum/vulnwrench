# Secret ledger comparison

Key ID: 7f70560c373115bac5b9b0921c94cf5dc873ce7797c09afff3d11be41650f5c0

Counts describe content groups, not a security verdict.

| Classification | Groups |
| --- | ---: |
| unchanged | 1 |
| same_secret_moved | 1 |
| new_content_same_location | 1 |
| new_content | 0 |
| absent | 2 |
| uncomparable | 2 |

| Classification | Rule | Relative path | Current lines |
| --- | --- | --- | --- |
| new_content_same_location | generic-api-key | src/config.py | 4 |
| uncomparable | generic-api-key | src/missing.py | 1 |
| same_secret_moved | generic-api-key | src/moved.py | 12, 30 |
| unchanged | generic-api-key | src/stable.py | 8 |
| uncomparable | generic-api-key | src/unknown.py | 7 |
| absent | generic-api-key | src/config.py | absent/unknown |
| absent | generic-api-key | src/removed.py | absent/unknown |
