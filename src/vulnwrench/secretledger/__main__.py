import sys

from vulnwrench.cli import main

raise SystemExit(main(["secrets", *sys.argv[1:]]))
