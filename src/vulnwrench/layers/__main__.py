import sys

from vulnwrench.cli import main

raise SystemExit(main(["layers", *sys.argv[1:]]))
