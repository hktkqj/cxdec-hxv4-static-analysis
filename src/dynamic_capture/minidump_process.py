#!/usr/bin/env python3
"""Create a full-memory minidump for a running Windows process.

This is a lightweight fallback when ProcDump/cdb/x32dbg are not installed. For
the packed executable, use it after the game has passed the .bind unpack loader
or while paused near the suspected OEP. The output is a process minidump, not a
rebuilt PE; use it as input for IDA/manual reconstruction or for extracting the
unpacked image bytes.
"""

from __future__ import annotations

import argparse
import ctypes
import sys
from ctypes import wintypes
from pathlib import Path


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
dbghelp = ctypes.WinDLL("Dbghelp", use_last_error=True)

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_DUP_HANDLE = 0x0040
PROCESS_ALL_FOR_DUMP = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE

CREATE_ALWAYS = 2
GENERIC_WRITE = 0x40000000
FILE_ATTRIBUTE_NORMAL = 0x80
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

TH32CS_SNAPPROCESS = 0x00000002
MAX_PATH = 260

MiniDumpWithFullMemory = 0x00000002
MiniDumpWithHandleData = 0x00000004
MiniDumpWithUnloadedModules = 0x00000020
MiniDumpWithFullMemoryInfo = 0x00000800
MiniDumpWithThreadInfo = 0x00001000
MiniDumpWithFullAuxiliaryState = 0x00008000
MINIDUMP_TYPE = (
    MiniDumpWithFullMemory
    | MiniDumpWithHandleData
    | MiniDumpWithUnloadedModules
    | MiniDumpWithFullMemoryInfo
    | MiniDumpWithThreadInfo
    | MiniDumpWithFullAuxiliaryState
)


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(wintypes.ULONG)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * MAX_PATH),
    ]


kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.CreateFileW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.HANDLE,
]
kernel32.CreateFileW.restype = wintypes.HANDLE
kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Process32FirstW.restype = wintypes.BOOL
kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Process32NextW.restype = wintypes.BOOL
dbghelp.MiniDumpWriteDump.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.LPVOID,
    wintypes.LPVOID,
]
dbghelp.MiniDumpWriteDump.restype = wintypes.BOOL


def win_error(prefix: str) -> OSError:
    return OSError(ctypes.get_last_error(), prefix)


def iter_processes() -> list[tuple[int, str]]:
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE_VALUE:
        raise win_error("CreateToolhelp32Snapshot failed")
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        processes: list[tuple[int, str]] = []
        ok = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            processes.append((int(entry.th32ProcessID), entry.szExeFile))
            ok = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
        return processes
    finally:
        kernel32.CloseHandle(snapshot)


def resolve_pid(pid: int | None, name: str | None) -> int:
    if pid is not None:
        return pid
    assert name is not None
    wanted = name.casefold()
    matches = [(p, n) for p, n in iter_processes() if n.casefold() == wanted]
    if not matches:
        raise RuntimeError(f"process {name!r} not found")
    if len(matches) > 1:
        joined = ", ".join(f"{pid}:{exe}" for pid, exe in matches)
        raise RuntimeError(f"process name is ambiguous: {joined}")
    return matches[0][0]


def create_dump(pid: int, output: Path) -> None:
    process = kernel32.OpenProcess(PROCESS_ALL_FOR_DUMP, False, pid)
    if not process:
        raise win_error("OpenProcess failed")
    try:
        out = kernel32.CreateFileW(
            str(output),
            GENERIC_WRITE,
            0,
            None,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        if out == INVALID_HANDLE_VALUE:
            raise win_error("CreateFileW failed")
        try:
            ok = dbghelp.MiniDumpWriteDump(process, pid, out, MINIDUMP_TYPE, None, None, None)
            if not ok:
                raise win_error("MiniDumpWriteDump failed")
        finally:
            kernel32.CloseHandle(out)
    finally:
        kernel32.CloseHandle(process)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--pid", type=int)
    target.add_argument("--name", help="exact process image name, e.g. SabbatOfTheWitch.exe")
    parser.add_argument("output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    if sys.platform != "win32":
        print("error: this script requires Windows", file=sys.stderr)
        return 2
    args = build_parser().parse_args(argv)
    try:
        pid = resolve_pid(args.pid, args.name)
        create_dump(pid, args.output)
        print(f"dumped pid {pid} to {args.output}")
        return 0
    except (OSError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
