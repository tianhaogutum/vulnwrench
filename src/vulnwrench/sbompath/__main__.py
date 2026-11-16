import sys

from vulnwrench.cli import main

raise SystemExit(main(["path", *sys.argv[1:]]))
