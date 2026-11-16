"""Shared configuration for all tool suites.

Every tool is standard-library only, so ``pip install -e .[test]`` runs everything.

Several tools refuse symlinked path components when they read or write files (a guard
against redirected outputs). On macOS the default temporary directory lives under
``/var -> /private/var``, so point ``tempfile`` at its resolved location before any
suite creates a temporary directory.
"""
import os
import tempfile

tempfile.tempdir = os.path.realpath(tempfile.gettempdir())
