import sys

from vulnwrench.cli import main

raise SystemExit(main(["fuse", *sys.argv[1:]]))
