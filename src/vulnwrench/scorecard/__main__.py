import sys

from vulnwrench.cli import main

raise SystemExit(main(["scorecard", *sys.argv[1:]]))
