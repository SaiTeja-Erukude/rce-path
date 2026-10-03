"""Trusted isolated worker entry point. Never import anything from the target tree."""

from __future__ import annotations

import ast
import ctypes
import json
import os
import sys
from pathlib import Path

# -I removes cwd/PYTHONPATH; only the installed package's source root is reintroduced.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

_job_handle = None


def memory_limit(megabytes: int) -> None:
    global _job_handle
    amount = megabytes * 1024 * 1024
    if os.name != "nt":
        import resource

        getattr(resource, "setrlimit")(getattr(resource, "RLIMIT_AS"), (amount, amount))
        return
    from ctypes import wintypes

    class Basic(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class IO(ctypes.Structure):
        _fields_ = [
            (name, ctypes.c_uint64)
            for name in (
                "ReadOperationCount",
                "WriteOperationCount",
                "OtherOperationCount",
                "ReadTransferCount",
                "WriteTransferCount",
                "OtherTransferCount",
            )
        ]

    class Extended(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", Basic),
            ("IoInfo", IO),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel = getattr(ctypes, "WinDLL")("kernel32", use_last_error=True)
    kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    handle = kernel.CreateJobObjectW(None, None)
    limits = Extended()
    limits.BasicLimitInformation.LimitFlags = 0x100  # JOB_OBJECT_LIMIT_PROCESS_MEMORY
    limits.ProcessMemoryLimit = amount
    if not handle or not kernel.SetInformationJobObject(
        handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)
    ):
        raise OSError("Could not enforce parser-worker memory limit")
    if not kernel.AssignProcessToJobObject(handle, kernel.GetCurrentProcess()):
        raise OSError("Could not assign parser-worker memory limit")
    _job_handle = handle  # retain until process exit


def main() -> None:
    from rce_path.config import ScanConfig
    from rce_path.flow import Analyzer

    request = json.loads(sys.stdin.buffer.read(25_000_000))
    config = ScanConfig.model_validate_json(json.dumps(request["config"]))
    memory_limit(config.parser_memory_mb)
    source = request["source"]
    file = request["file"]
    try:
        tree = ast.parse(source, filename=file)
        count = 0
        for _ in ast.walk(tree):
            count += 1
            if count > config.max_ast_nodes:
                raise ValueError("AST node budget exhausted")
        findings, diagnostics = Analyzer(source, file, config).analyze(tree)
        payload = {
            "findings": [f.model_dump() for f in findings],
            "diagnostics": [d.model_dump() for d in diagnostics],
        }
    except (SyntaxError, UnicodeError, ValueError, RecursionError, MemoryError) as error:
        payload = {
            "findings": [],
            "diagnostics": [
                {
                    "code": "parse_error",
                    "file": file,
                    "line": getattr(error, "lineno", None),
                    "affects_completion": True,
                    "message": f"{type(error).__name__}: {str(error)[:200]}",
                }
            ],
        }
    # Bound serialized evidence before it enters the parent's capture buffer.
    chunks = []
    size = 0
    for chunk in json.JSONEncoder().iterencode(payload):
        size += len(chunk.encode())
        if size > 16_000_000:
            chunks = [
                json.dumps(
                    {
                        "findings": [],
                        "diagnostics": [
                            {
                                "code": "evidence_response_limit",
                                "file": file,
                                "message": "Worker evidence response exceeded size budget.",
                                "affects_completion": True,
                            }
                        ],
                    }
                )
            ]
            break
        chunks.append(chunk)
    sys.stdout.write("".join(chunks))


if __name__ == "__main__":
    main()
