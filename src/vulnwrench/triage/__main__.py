import sys

from vulnwrench.cli import main

raise SystemExit(main(["triage", *sys.argv[1:]]))
