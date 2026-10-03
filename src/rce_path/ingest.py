"""Bounded inventory and isolated parsing/analysis. Targets are read as data only."""

from __future__ import annotations

import fnmatch
import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import time
import tokenize
from pathlib import Path

from .config import ScanConfig, load_config
from .findings import Diagnostic, Finding, ScanReport


def _reparse(path: Path) -> bool:
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


def _read(path: Path, root: Path, limit: int) -> bytes:
    if _reparse(path) or not path.resolve().is_relative_to(root):
        raise ValueError("symlink/reparse source was skipped")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    if os.name == "nt":
        descriptor = os.open(path, flags)
    else:
        # Traverse relative to directory handles: ancestor symlink races cannot escape.
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY") | getattr(os, "O_NOFOLLOW")
        directory = os.open(root, directory_flags)
        try:
            parts = path.relative_to(root).parts
            for part in parts[:-1]:
                child = os.open(part, directory_flags, dir_fd=directory)
                os.close(directory)
                directory = child
            descriptor = os.open(parts[-1], flags, dir_fd=directory)
        finally:
            os.close(directory)
    with os.fdopen(descriptor, "rb") as stream:
        if os.name == "nt":
            _verify_windows_handle(stream.fileno(), root)
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("source is not a regular file")
        if before.st_size > limit:
            raise ValueError("file size budget exceeded")
        # Recheck the pathname identity after opening, including every ancestor.
        if _reparse(path) or not path.resolve().is_relative_to(root):
            raise ValueError("source path changed during inventory")
        after = path.stat()
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise ValueError("source changed during inventory")
        content = stream.read(limit + 1)
        if len(content) > limit:
            raise ValueError("file size budget exceeded")
        return content


def _verify_windows_handle(descriptor: int, root: Path) -> None:
    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel = getattr(ctypes, "WinDLL")("kernel32", use_last_error=True)
    kernel.GetFinalPathNameByHandleW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    kernel.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    buffer = ctypes.create_unicode_buffer(32768)
    length = kernel.GetFinalPathNameByHandleW(
        getattr(msvcrt, "get_osfhandle")(descriptor), buffer, len(buffer), 0
    )
    if not length or length >= len(buffer):
        raise ValueError("cannot verify opened source location")
    actual = buffer.value
    if actual.startswith("\\\\?\\UNC\\"):
        actual = "\\\\" + actual[8:]
    elif actual.startswith("\\\\?\\"):
        actual = actual[4:]
    if not Path(actual).is_relative_to(root):
        raise ValueError("opened source escaped the scan root")


def scan(path: str | os.PathLike[str], config: ScanConfig | None = None) -> ScanReport:
    """Scan a local directory or .py file without importing or executing its code.

    Omitting config reads a root rce-path.toml; it cannot opt into AI or remote code
    transmission. Operational/configuration failures are returned as error reports.
    """
    started = time.monotonic()
    target = Path(path).absolute()
    root = target if target.is_dir() else target.parent
    findings: list[Finding] = []
    diagnostics: list[Diagnostic] = []
    hashes: dict[str, str] = {}
    analyzed = skipped = 0

    def diagnostic(
        code: str, message: str, file: str | None = None, incomplete: bool = True
    ) -> None:
        diagnostics.append(
            Diagnostic(code=code, message=message, file=file, affects_completion=incomplete)
        )

    try:
        if not target.exists() or _reparse(target):
            raise ValueError("scan target does not exist or is a symlink/reparse point")
        target = target.resolve()
        root = root.resolve()
        if not target.is_dir() and target.suffix != ".py":
            raise ValueError("scan target must be a directory or Python source file")
        if config is None:
            candidate = root / "rce-path.toml"
            if candidate.exists():
                config = load_config(candidate)
            else:
                config = ScanConfig()
    except (OSError, ValueError, TypeError) as error:
        return ScanReport(
            root=str(root),
            status="error",
            target_syntax=f"Python {sys.version_info.major}.{sys.version_info.minor}",
            diagnostics=(
                Diagnostic(
                    code="configuration_error", message=str(error)[:500], affects_completion=True
                ),
            ),
        )
    assert config is not None
    deadline = started + config.scan_timeout_seconds
    limits = {
        key: value
        for key, value in config.model_dump().items()
        if key.startswith(("max_", "parser_", "scan_timeout", "loop_"))
    }

    def excluded(relative: str, name: str) -> bool:
        return name.endswith(".egg-info") or any(
            name == item or fnmatch.fnmatch(relative, item) or fnmatch.fnmatch(relative + "/", item)
            for item in config.excludes
        )

    def inventory():
        nonlocal skipped
        if target.is_file():
            yield target
            return
        stack = [target]
        entries_seen = 0
        while stack:
            if time.monotonic() >= deadline:
                diagnostic("scan_timeout", "Total scan time budget exhausted during inventory.")
                return
            directory = stack.pop()
            try:
                if _reparse(directory) or not directory.resolve().is_relative_to(root):
                    skipped += 1
                    diagnostic(
                        "symlink_skipped",
                        "Directory symlink/reparse point skipped.",
                        directory.relative_to(root).as_posix(),
                    )
                    continue
                # Incremental traversal avoids an unbounded list of directory entries.
                with os.scandir(directory) as entries:
                    for entry in entries:
                        entries_seen += 1
                        if entries_seen > config.max_inventory_entries:
                            diagnostic("inventory_limit", "Inventory entry budget exhausted.")
                            return
                        if time.monotonic() >= deadline:
                            diagnostic(
                                "scan_timeout", "Total scan time budget exhausted during inventory."
                            )
                            return
                        source_path = Path(entry.path)
                        relative = source_path.relative_to(root).as_posix()
                        if excluded(relative, entry.name):
                            skipped += 1
                            diagnostic(
                                "excluded", "Excluded by scan configuration.", relative, False
                            )
                        elif _reparse(source_path):
                            skipped += 1
                            diagnostic(
                                "symlink_skipped", "Symlink/reparse point skipped.", relative
                            )
                        elif entry.is_dir(follow_symlinks=False):
                            if (source_path / "pyvenv.cfg").is_file():
                                skipped += 1
                                diagnostic(
                                    "excluded",
                                    "Virtual environment detected by pyvenv.cfg.",
                                    relative,
                                    False,
                                )
                            else:
                                stack.append(source_path)
                        elif entry.name.endswith(".py"):
                            yield source_path
            except OSError:
                skipped += 1
                diagnostic(
                    "inventory_error",
                    "Cannot read directory.",
                    directory.relative_to(root).as_posix(),
                )

    worker = Path(__file__).with_name("_worker.py")
    for index, source_path in enumerate(inventory()):
        relative = source_path.relative_to(root).as_posix()
        remaining = deadline - time.monotonic()
        if remaining <= 0 or index >= config.max_files:
            skipped += 1
            diagnostic("scan_limit", "Total scan time or file count budget exhausted.", relative)
            break
        try:
            content = _read(source_path, root, config.max_file_bytes)
            hashes[relative] = hashlib.sha256(content).hexdigest()
            encoding, _ = tokenize.detect_encoding(io.BytesIO(content).readline)
            source = content.decode(encoding)
            payload = json.dumps(
                {"source": source, "file": relative, "config": config.model_dump()}
            )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                skipped += 1
                diagnostic(
                    "scan_timeout", "Total scan time budget exhausted before parsing.", relative
                )
                break
            # Do not inherit target import paths or SDK credentials into a static worker.
            env = {
                key: value
                for key, value in os.environ.items()
                if key.upper() in {"SYSTEMROOT", "WINDIR", "PATH", "TEMP", "TMP", "LANG", "LC_ALL"}
            }
            result = subprocess.run(
                [sys.executable, "-I", str(worker)],
                input=payload.encode(),
                capture_output=True,
                env=env,
                cwd=worker.parent,
                timeout=min(remaining, config.parser_timeout_seconds),
                check=False,
            )
            if result.returncode != 0:
                raise ValueError("parser worker failed or exceeded its memory budget")
            if len(result.stdout) > 16_000_000:
                raise ValueError("worker evidence response exceeded its size budget")
            data = json.loads(result.stdout)
            findings.extend(Finding.model_validate(f) for f in data["findings"])
            file_diagnostics = [Diagnostic.model_validate(d) for d in data["diagnostics"]]
            diagnostics.extend(file_diagnostics)
            if any(d.code == "parse_error" for d in file_diagnostics):
                skipped += 1
            else:
                analyzed += 1
        except subprocess.TimeoutExpired:
            skipped += 1
            diagnostic("parser_timeout", "Isolated parser/analysis worker timed out.", relative)
        except (OSError, ValueError, UnicodeError, SyntaxError):
            skipped += 1
            diagnostic(
                "source_skipped",
                "Source could not be safely read/parsed within configured limits.",
                relative,
            )
    if time.monotonic() > deadline:
        diagnostic("scan_timeout", "Total scan time budget exhausted.")
    if not config.rules == ScanConfig().rules:
        diagnostic("rule_selection", "Only selected sink rules were analyzed.", incomplete=False)
    if not hashes and analyzed == 0 and not any(d.affects_completion for d in diagnostics):
        diagnostic("no_sources", "No Python files were available for analysis.")
    # Content hashes provide reproducible provenance without invoking git in an untrusted tree.
    report = ScanReport(
        root=str(root),
        status="incomplete" if any(d.affects_completion for d in diagnostics) else "completed",
        findings=tuple(
            sorted(findings, key=lambda f: (f.location.file, f.location.line, f.fingerprint))
        ),
        diagnostics=tuple(diagnostics),
        analyzed_files=analyzed,
        skipped_files=skipped,
        content_hashes=hashes,
        limits=limits,
        enabled_rules=config.rules,
        exclusions=config.excludes,
        target_syntax=f"Python {sys.version_info.major}.{sys.version_info.minor}",
    )
    if config.ai_enabled:
        from .llm import annotate

        report = annotate(report, config, deadline=deadline)
    return report
