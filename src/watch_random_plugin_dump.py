#!/usr/bin/env python3
"""Launch/attach to SabbatOfTheWitch and dump when the random plugin manager is ready.

The game loads a protected TVP plugin from a random path like:

    %TEMP%\\krkr_<hex>_<tick>_<pid>\\<hex>.dll

This helper polls the target process modules, finds that random DLL, reads a
caller-provided manager slot RVA relative to the random DLL base, and writes a
full-memory minidump once the slot becomes nonzero.
"""

from __future__ import annotations

import argparse
import ctypes
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from ctypes import wintypes


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
dbghelp = ctypes.WinDLL("Dbghelp", use_last_error=True)

MAX_PATH = 260
MAX_MODULE_NAME32 = 255
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
STILL_ACTIVE = 259

CREATE_ALWAYS = 2
GENERIC_WRITE = 0x40000000
FILE_ATTRIBUTE_NORMAL = 0x80

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_DUP_HANDLE = 0x0040
PROCESS_ALL_FOR_DUMP = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE

TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010

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

RANDOM_DLL_RE = re.compile(r"^[0-9a-f]{12}\.dll$", re.IGNORECASE)


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


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


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.POINTER(ctypes.c_ubyte)),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", wintypes.HMODULE),
        ("szModule", wintypes.WCHAR * (MAX_MODULE_NAME32 + 1)),
        ("szExePath", wintypes.WCHAR * MAX_PATH),
    ]


@dataclass(frozen=True)
class ModuleInfo:
    base: int
    size: int
    name: str
    path: str


kernel32.CreateProcessW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.LPWSTR,
    wintypes.LPVOID,
    wintypes.LPVOID,
    wintypes.BOOL,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.LPCWSTR,
    ctypes.POINTER(STARTUPINFOW),
    ctypes.POINTER(PROCESS_INFORMATION),
]
kernel32.CreateProcessW.restype = wintypes.BOOL
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
kernel32.GetExitCodeProcess.restype = wintypes.BOOL
kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    wintypes.LPVOID,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
kernel32.ReadProcessMemory.restype = wintypes.BOOL
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
kernel32.Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
kernel32.Module32FirstW.restype = wintypes.BOOL
kernel32.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
kernel32.Module32NextW.restype = wintypes.BOOL
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


def parse_int(text: str) -> int:
    return int(text, 0)


def is_random_plugin(module: ModuleInfo) -> bool:
    path = module.path.replace("/", "\\").casefold()
    name = module.name.casefold()
    return "\\temp\\krkr_" in path and RANDOM_DLL_RE.match(name) is not None


def close_handle(handle: int) -> None:
    if handle and handle != INVALID_HANDLE_VALUE:
        kernel32.CloseHandle(handle)


def launch_process(exe: Path, extra_args: list[str]) -> tuple[int, int]:
    cmdline = subprocess.list2cmdline([str(exe), *extra_args])
    mutable_cmdline = ctypes.create_unicode_buffer(cmdline)
    startup = STARTUPINFOW()
    startup.cb = ctypes.sizeof(startup)
    info = PROCESS_INFORMATION()
    ok = kernel32.CreateProcessW(
        None,
        mutable_cmdline,
        None,
        None,
        False,
        0,
        None,
        str(exe.parent),
        ctypes.byref(startup),
        ctypes.byref(info),
    )
    if not ok:
        raise win_error("CreateProcessW failed")
    close_handle(info.hThread)
    return int(info.dwProcessId), int(info.hProcess)


def iter_processes() -> list[tuple[int, str]]:
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE_VALUE:
        raise win_error("CreateToolhelp32Snapshot(process) failed")
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        result: list[tuple[int, str]] = []
        ok = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            result.append((int(entry.th32ProcessID), entry.szExeFile))
            ok = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
        return result
    finally:
        close_handle(snapshot)


def resolve_pid_by_name(name: str) -> int:
    wanted = name.casefold()
    matches = [(pid, exe) for pid, exe in iter_processes() if exe.casefold() == wanted]
    if not matches:
        raise RuntimeError(f"process {name!r} not found")
    if len(matches) > 1:
        raise RuntimeError("ambiguous process name: " + ", ".join(f"{p}:{e}" for p, e in matches))
    return matches[0][0]


def list_modules(pid: int) -> list[ModuleInfo]:
    flags = TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32
    snapshot = kernel32.CreateToolhelp32Snapshot(flags, pid)
    if snapshot == INVALID_HANDLE_VALUE:
        raise win_error("CreateToolhelp32Snapshot(module) failed")
    try:
        entry = MODULEENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        modules: list[ModuleInfo] = []
        ok = kernel32.Module32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            modules.append(
                ModuleInfo(
                    base=ctypes.cast(entry.modBaseAddr, ctypes.c_void_p).value or 0,
                    size=int(entry.modBaseSize),
                    name=entry.szModule,
                    path=entry.szExePath,
                )
            )
            ok = kernel32.Module32NextW(snapshot, ctypes.byref(entry))
        return modules
    finally:
        close_handle(snapshot)


def open_process(pid: int) -> int:
    handle = kernel32.OpenProcess(PROCESS_ALL_FOR_DUMP, False, pid)
    if not handle:
        raise win_error("OpenProcess failed")
    return int(handle)


def read_memory(process: int, address: int, size: int) -> bytes:
    buf = (ctypes.c_ubyte * size)()
    got = ctypes.c_size_t()
    ok = kernel32.ReadProcessMemory(
        process,
        ctypes.c_void_p(address),
        buf,
        size,
        ctypes.byref(got),
    )
    if not ok or got.value != size:
        raise win_error(f"ReadProcessMemory failed at {address:#x}")
    return bytes(buf)


def read_pointer(process: int, address: int, ptr_size: int) -> int:
    raw = read_memory(process, address, ptr_size)
    return int.from_bytes(raw, "little")


def is_process_alive(process: int) -> bool:
    code = wintypes.DWORD()
    if not kernel32.GetExitCodeProcess(process, ctypes.byref(code)):
        raise win_error("GetExitCodeProcess failed")
    return int(code.value) == STILL_ACTIVE


def write_full_dump(process: int, pid: int, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
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
        raise win_error("CreateFileW(dump) failed")
    try:
        ok = dbghelp.MiniDumpWriteDump(process, pid, out, MINIDUMP_TYPE, None, None, None)
        if not ok:
            raise win_error("MiniDumpWriteDump failed")
    finally:
        close_handle(out)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--exe", type=Path, help="launch this executable")
    target.add_argument("--attach-name", help="attach to an already-running process image name")
    target.add_argument("--pid", type=int, help="attach to an already-running PID")
    parser.add_argument("--manager-slot-rva", type=parse_int, help="RVA in random DLL that stores manager pointer")
    parser.add_argument("--manager-slot-va", type=parse_int, help="absolute VA that stores manager pointer")
    parser.add_argument("--deref-manager0", action="store_true", help="require *(manager_pointer) to be nonzero")
    parser.add_argument("--ptr-size", type=int, choices=(4, 8), default=4)
    parser.add_argument("--poll-ms", type=int, default=100)
    parser.add_argument("--settle-ms", type=int, default=250, help="wait this long after condition is met before dumping")
    parser.add_argument("--timeout-sec", type=float, default=60.0)
    parser.add_argument("--output", type=Path, default=Path("analysis/manager_ready.full.dmp"))
    parser.add_argument("--peek-bytes", type=parse_int, default=0x80)
    parser.add_argument("--dump-on-module-load", action="store_true", help="dump as soon as random DLL is loaded")
    parser.add_argument("exe_args", nargs=argparse.REMAINDER, help="extra arguments after -- when using --exe")
    return parser


def main(argv: list[str] | None = None) -> int:
    if sys.platform != "win32":
        print("error: this script requires Windows", file=sys.stderr)
        return 2

    args = build_parser().parse_args(argv)
    if not args.dump_on_module_load and args.manager_slot_rva is None and args.manager_slot_va is None:
        print("error: provide --manager-slot-rva/--manager-slot-va or --dump-on-module-load", file=sys.stderr)
        return 2

    process = 0
    launched_handle = 0
    try:
        if args.exe is not None:
            pid, launched_handle = launch_process(args.exe, args.exe_args)
            process = launched_handle
            print(f"launched pid={pid} exe={args.exe}")
        elif args.attach_name:
            pid = resolve_pid_by_name(args.attach_name)
            process = open_process(pid)
            print(f"attached pid={pid} name={args.attach_name}")
        else:
            pid = args.pid
            process = open_process(pid)
            print(f"attached pid={pid}")

        deadline = time.monotonic() + args.timeout_sec
        seen_base: int | None = None
        while time.monotonic() < deadline:
            if not is_process_alive(process):
                raise RuntimeError("target process exited before dump condition was met")

            random_modules = [m for m in list_modules(pid) if is_random_plugin(m)]
            if random_modules:
                module = random_modules[-1]
                if module.base != seen_base:
                    seen_base = module.base
                    print(f"random dll: base={module.base:#x} size={module.size:#x} path={module.path}")

                if args.dump_on_module_load:
                    print("dump condition met: random DLL loaded")
                    write_full_dump(process, pid, args.output)
                    print(f"dumped pid {pid} to {args.output}")
                    return 0

                slot_va = args.manager_slot_va
                if slot_va is None:
                    slot_va = module.base + args.manager_slot_rva
                manager_ptr = read_pointer(process, slot_va, args.ptr_size)
                if manager_ptr:
                    print(f"manager slot {slot_va:#x} -> {manager_ptr:#x}")
                    if args.peek_bytes:
                        try:
                            print(f"manager bytes: {read_memory(process, manager_ptr, args.peek_bytes).hex()}")
                        except OSError as exc:
                            print(f"warning: could not peek manager bytes: {exc}")

                    if args.deref_manager0:
                        manager0 = read_pointer(process, manager_ptr, args.ptr_size)
                        print(f"manager[0] -> {manager0:#x}")
                        if not manager0:
                            time.sleep(args.poll_ms / 1000.0)
                            continue
                        if args.peek_bytes:
                            try:
                                print(f"manager[0] bytes: {read_memory(process, manager0, args.peek_bytes).hex()}")
                            except OSError as exc:
                                print(f"warning: could not peek manager[0] bytes: {exc}")

                    if args.settle_ms:
                        time.sleep(args.settle_ms / 1000.0)
                    write_full_dump(process, pid, args.output)
                    print(f"dumped pid {pid} to {args.output}")
                    return 0

            time.sleep(args.poll_ms / 1000.0)

        raise RuntimeError("timeout waiting for random DLL/manager slot")
    except (OSError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    finally:
        close_handle(process)


if __name__ == "__main__":
    raise SystemExit(main())
