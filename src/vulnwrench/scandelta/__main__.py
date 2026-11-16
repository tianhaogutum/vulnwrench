import sys

from vulnwrench.cli import main

raise SystemExit(main(["delta", *sys.argv[1:]]))
