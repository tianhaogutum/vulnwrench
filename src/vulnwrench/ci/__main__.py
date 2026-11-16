import sys

from vulnwrench.cli import main

raise SystemExit(main(["ci", *sys.argv[1:]]))
