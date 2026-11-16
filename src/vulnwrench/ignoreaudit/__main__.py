import sys

from vulnwrench.cli import main

raise SystemExit(main(["ignores", *sys.argv[1:]]))
