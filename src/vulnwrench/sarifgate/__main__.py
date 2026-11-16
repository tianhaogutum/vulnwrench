import sys

from vulnwrench.cli import main

raise SystemExit(main(["sarif", *sys.argv[1:]]))
