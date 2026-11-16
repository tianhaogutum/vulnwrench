"""Bounded input and create-only output. Local trusted filesystem only."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat

from .compiler import Compilation
from .model import MAX_INPUT_BYTES, decode_document, fail


ARTIFACT_NAMES = frozenset({".trivyignore.yaml", "osv-scanner.toml", "openvex.json", "conversion-report.json"})
_PAYLOAD_NAMES = ARTIFACT_NAMES - {"conversion-report.json"}


def verify_report_artifacts(report: object, directory: str | Path) -> dict:
    """Validate a report, then verify its saved payload bytes without applying them.

    Explicit I/O, Linux/POSIX trusted local filesystem only. Unrelated entries
    and the optional report sidecar are not read. This is not an atomic snapshot
    or authenticated provenance; original decision verification is a separate opt-in.
    """
    from .report_baseline import report_decision_document
    report_decision_document(report)  # Validate all metadata before using sizes/names.
    artifacts = report["artifacts"]
    directory_fd = None

    def reject():
        fail("E_ARTIFACT", "cannot verify saved artifacts; require matching regular files in a nonsymlink directory")

    def signature(info):
        # Ignore access time, which can change as a result of our own reads.
        return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
                info.st_mtime_ns, info.st_ctime_ns)

    def snapshot():
        found = {}
        for name in sorted(_PAYLOAD_NAMES):
            try:
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if name not in artifacts or not stat.S_ISREG(info.st_mode):
                reject()
            found[name] = signature(info)
        if set(found) != set(artifacts):
            reject()
        return found

    try:
        if not directory:
            reject()
        path = Path(directory)
        if ".." in path.parts:
            reject()
        directory_fd = os.open("/" if path.is_absolute() else ".", os.O_RDONLY | os.O_DIRECTORY)
        parts = path.parts[1:] if path.is_absolute() else path.parts
        for part in parts:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        before = snapshot()
        verified = {}
        for name, metadata in sorted(artifacts.items()):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
            try:
                info = os.fstat(fd)
                size = metadata["bytes"]
                if (not stat.S_ISREG(info.st_mode) or info.st_size != size
                        or signature(info) != before[name]):
                    reject()
                sha = hashlib.sha256()
                count = 0
                while count <= size:
                    block = os.read(fd, min(65536, size + 1 - count))
                    if not block:
                        break
                    count += len(block)
                    sha.update(block)
                if (count != size or sha.hexdigest() != metadata["sha256"]
                        or signature(os.fstat(fd)) != before[name]):
                    reject()
                verified[name] = {"sha256": sha.hexdigest(), "bytes": count}
            finally:
                os.close(fd)
        if snapshot() != before:
            reject()
        return {"status": "verified", "artifacts": verified}
    except (OSError, ValueError, TypeError):
        reject()
    finally:
        if directory_fd is not None:
            os.close(directory_fd)


def load_document(path: str | Path, *, regular_only: bool = False) -> object:
    """Read bounded JSON; optionally refuse nonregular files before any read.

    regular_only opens nonblockingly and checks the opened descriptor. Symlinks
    to regular files remain supported on the trusted local filesystem.
    """
    return decode_document(_read_input(path, regular_only=regular_only))


def load_trivy_ignore(path: str | Path, *, regular_only: bool = False) -> dict:
    """Read bounded native Trivy YAML and return a review-only import draft.

    regular_only opts into the same nonblocking descriptor policy as load_document;
    symlinks to readable regular files remain supported. The default is unchanged.
    """
    from .import_trivy import import_trivy_ignore
    return import_trivy_ignore(_read_input(path, regular_only=regular_only))


def _open_nonblocking(path, flags):
    return os.open(path, flags | os.O_NONBLOCK)


def _read_input(path: str | Path, *, regular_only: bool = False) -> bytes:
    try:
        with open(path, "rb", opener=_open_nonblocking if regular_only else None) as stream:
            if regular_only and not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                fail("E_IO", "cannot read input document; require a readable regular file")
            raw = stream.read(MAX_INPUT_BYTES + 1)
    except (OSError, ValueError):
        fail("E_IO", "cannot read input document")
    return raw


def write_compilation(compilation: Compilation, out_dir: str | Path) -> None:
    """Write fixed filenames to a NEW directory; refuse traversal and symlinks.

    Parent must exist. No overwrites, arbitrary filenames, or implicit cleanup of
    preexisting directories. A write failure removes only this invocation's files.
    """
    path = Path(out_dir)
    if ".." in path.parts or not path.name or path.name in {".", ".."}:
        fail("E_OUTPUT", "output directory must be new, without parent traversal")
    if not set(compilation.files) <= ARTIFACT_NAMES or "conversion-report.json" not in compilation.files:
        fail("E_OUTPUT", "unsupported artifact filenames")
    # Open each ancestor with O_NOFOLLOW, so symlink components cannot redirect
    # the writes. Keep the final parent fd for all subsequent relative operations.
    parent_fd = None
    output_fd = None
    created = False
    written = []
    try:
        parent_fd = os.open("/" if path.is_absolute() else ".", os.O_RDONLY | os.O_DIRECTORY)
        parts = path.parts[1:] if path.is_absolute() else path.parts
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = next_fd
        os.mkdir(parts[-1], mode=0o700, dir_fd=parent_fd)
        created = True
        output_fd = os.open(parts[-1], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        for name, data in sorted(compilation.files.items()):
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=output_fd)
            written.append(name)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
    except (OSError, ValueError):
        if output_fd is not None:
            for name in written:
                try:
                    os.unlink(name, dir_fd=output_fd)
                except OSError:
                    pass
        if created and parent_fd is not None:
            try:
                os.rmdir(parts[-1], dir_fd=parent_fd)
            except OSError:
                pass
        fail("E_OUTPUT", "cannot create output; parent must exist, destination must be new, and symlinks are forbidden")
    finally:
        if output_fd is not None:
            os.close(output_fd)
        if parent_fd is not None:
            os.close(parent_fd)
