#!/usr/bin/env python3
"""Capture the final System.bootStrap string passed into the random DLL.

By default this script launches the game normally, waits for the protected
random DLL, attaches as a debugger only after that DLL is visible, patches an
INT3 breakpoint at the low-level sub_10015630 call site, and reads the 32-bit
stack arguments:

    [esp]     UTF-16LE bootstrap string pointer
    [esp+4]   bootstrap byte length
    [esp+8]   PARAMS pointer
    [esp+0xc] PARAMS byte length

Default RVA is for 1ae7153ed25d.dll / compatible random plugin builds:

    System_bootStrap_callback + call sub_10015630 = module_base + 0xF269
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import re
import struct
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from ctypes import wintypes


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

MAX_PATH = 260
MAX_MODULE_NAME32 = 255
INFINITE = 0xFFFFFFFF
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

DEBUG_PROCESS = 0x00000001
DEBUG_ONLY_THIS_PROCESS = 0x00000002
CREATE_NEW_CONSOLE = 0x00000010

DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001

EXCEPTION_DEBUG_EVENT = 1
CREATE_THREAD_DEBUG_EVENT = 2
CREATE_PROCESS_DEBUG_EVENT = 3
EXIT_THREAD_DEBUG_EVENT = 4
EXIT_PROCESS_DEBUG_EVENT = 5
LOAD_DLL_DEBUG_EVENT = 6
UNLOAD_DLL_DEBUG_EVENT = 7
OUTPUT_DEBUG_STRING_EVENT = 8
RIP_EVENT = 9

EXCEPTION_BREAKPOINT = 0x80000003

PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_ALL_FOR_DEBUG = (
    PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION
)
STILL_ACTIVE = 259

TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010

THREAD_GET_CONTEXT = 0x0008
THREAD_SET_CONTEXT = 0x0010
THREAD_QUERY_INFORMATION = 0x0040
THREAD_ALL_FOR_CONTEXT = THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION

WOW64_CONTEXT_i386 = 0x00010000
WOW64_CONTEXT_CONTROL = WOW64_CONTEXT_i386 | 0x00000001

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


class EXCEPTION_RECORD32(ctypes.Structure):
    _fields_ = [
        ("ExceptionCode", wintypes.DWORD),
        ("ExceptionFlags", wintypes.DWORD),
        ("ExceptionRecord", ctypes.c_void_p),
        ("ExceptionAddress", ctypes.c_void_p),
        ("NumberParameters", wintypes.DWORD),
        ("ExceptionInformation", ctypes.c_void_p * 15),
    ]


class EXCEPTION_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("ExceptionRecord", EXCEPTION_RECORD32),
        ("dwFirstChance", wintypes.DWORD),
    ]


class CREATE_THREAD_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("hThread", wintypes.HANDLE),
        ("lpThreadLocalBase", ctypes.c_void_p),
        ("lpStartAddress", ctypes.c_void_p),
    ]


class CREATE_PROCESS_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("hFile", wintypes.HANDLE),
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("lpBaseOfImage", ctypes.c_void_p),
        ("dwDebugInfoFileOffset", wintypes.DWORD),
        ("nDebugInfoSize", wintypes.DWORD),
        ("lpThreadLocalBase", ctypes.c_void_p),
        ("lpStartAddress", ctypes.c_void_p),
        ("lpImageName", ctypes.c_void_p),
        ("fUnicode", wintypes.WORD),
    ]


class EXIT_THREAD_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("dwExitCode", wintypes.DWORD)]


class EXIT_PROCESS_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("dwExitCode", wintypes.DWORD)]


class LOAD_DLL_DEBUG_INFO(ctypes.Structure):
    _fields_ = [
        ("hFile", wintypes.HANDLE),
        ("lpBaseOfDll", ctypes.c_void_p),
        ("dwDebugInfoFileOffset", wintypes.DWORD),
        ("nDebugInfoSize", wintypes.DWORD),
        ("lpImageName", ctypes.c_void_p),
        ("fUnicode", wintypes.WORD),
    ]


class UNLOAD_DLL_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("lpBaseOfDll", ctypes.c_void_p)]


class OUTPUT_DEBUG_STRING_INFO(ctypes.Structure):
    _fields_ = [
        ("lpDebugStringData", ctypes.c_void_p),
        ("fUnicode", wintypes.WORD),
        ("nDebugStringLength", wintypes.WORD),
    ]


class RIP_INFO(ctypes.Structure):
    _fields_ = [("dwError", wintypes.DWORD), ("dwType", wintypes.DWORD)]


class DEBUG_EVENT_UNION(ctypes.Union):
    _fields_ = [
        ("Exception", EXCEPTION_DEBUG_INFO),
        ("CreateThread", CREATE_THREAD_DEBUG_INFO),
        ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
        ("ExitThread", EXIT_THREAD_DEBUG_INFO),
        ("ExitProcess", EXIT_PROCESS_DEBUG_INFO),
        ("LoadDll", LOAD_DLL_DEBUG_INFO),
        ("UnloadDll", UNLOAD_DLL_DEBUG_INFO),
        ("DebugString", OUTPUT_DEBUG_STRING_INFO),
        ("RipInfo", RIP_INFO),
    ]


class DEBUG_EVENT(ctypes.Structure):
    _fields_ = [
        ("dwDebugEventCode", wintypes.DWORD),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
        ("u", DEBUG_EVENT_UNION),
    ]


class WOW64_FLOATING_SAVE_AREA(ctypes.Structure):
    _fields_ = [
        ("ControlWord", wintypes.DWORD),
        ("StatusWord", wintypes.DWORD),
        ("TagWord", wintypes.DWORD),
        ("ErrorOffset", wintypes.DWORD),
        ("ErrorSelector", wintypes.DWORD),
        ("DataOffset", wintypes.DWORD),
        ("DataSelector", wintypes.DWORD),
        ("RegisterArea", ctypes.c_byte * 80),
        ("Cr0NpxState", wintypes.DWORD),
    ]


class WOW64_CONTEXT(ctypes.Structure):
    _fields_ = [
        ("ContextFlags", wintypes.DWORD),
        ("Dr0", wintypes.DWORD),
        ("Dr1", wintypes.DWORD),
        ("Dr2", wintypes.DWORD),
        ("Dr3", wintypes.DWORD),
        ("Dr6", wintypes.DWORD),
        ("Dr7", wintypes.DWORD),
        ("FloatSave", WOW64_FLOATING_SAVE_AREA),
        ("SegGs", wintypes.DWORD),
        ("SegFs", wintypes.DWORD),
        ("SegEs", wintypes.DWORD),
        ("SegDs", wintypes.DWORD),
        ("Edi", wintypes.DWORD),
        ("Esi", wintypes.DWORD),
        ("Ebx", wintypes.DWORD),
        ("Edx", wintypes.DWORD),
        ("Ecx", wintypes.DWORD),
        ("Eax", wintypes.DWORD),
        ("Ebp", wintypes.DWORD),
        ("Eip", wintypes.DWORD),
        ("SegCs", wintypes.DWORD),
        ("EFlags", wintypes.DWORD),
        ("Esp", wintypes.DWORD),
        ("SegSs", wintypes.DWORD),
        ("ExtendedRegisters", ctypes.c_byte * 512),
    ]


@dataclass
class Breakpoint:
    addr: int
    original_byte: bytes
    module_base: int
    module_path: str


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
kernel32.DebugActiveProcess.argtypes = [wintypes.DWORD]
kernel32.DebugActiveProcess.restype = wintypes.BOOL
kernel32.DebugActiveProcessStop.argtypes = [wintypes.DWORD]
kernel32.DebugActiveProcessStop.restype = wintypes.BOOL
kernel32.WaitForDebugEvent.argtypes = [ctypes.POINTER(DEBUG_EVENT), wintypes.DWORD]
kernel32.WaitForDebugEvent.restype = wintypes.BOOL
kernel32.ContinueDebugEvent.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.DWORD]
kernel32.ContinueDebugEvent.restype = wintypes.BOOL
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenThread.restype = wintypes.HANDLE
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
kernel32.GetExitCodeProcess.restype = wintypes.BOOL
kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
kernel32.Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
kernel32.Module32FirstW.restype = wintypes.BOOL
kernel32.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
kernel32.Module32NextW.restype = wintypes.BOOL
kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    wintypes.LPVOID,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
kernel32.ReadProcessMemory.restype = wintypes.BOOL
kernel32.WriteProcessMemory.argtypes = [
    wintypes.HANDLE,
    wintypes.LPVOID,
    wintypes.LPCVOID,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
kernel32.WriteProcessMemory.restype = wintypes.BOOL
kernel32.FlushInstructionCache.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, ctypes.c_size_t]
kernel32.FlushInstructionCache.restype = wintypes.BOOL
kernel32.GetFinalPathNameByHandleW.argtypes = [
    wintypes.HANDLE,
    wintypes.LPWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
]
kernel32.GetFinalPathNameByHandleW.restype = wintypes.DWORD
kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
kernel32.TerminateProcess.restype = wintypes.BOOL
kernel32.Wow64GetThreadContext.argtypes = [wintypes.HANDLE, ctypes.POINTER(WOW64_CONTEXT)]
kernel32.Wow64GetThreadContext.restype = wintypes.BOOL
kernel32.Wow64SetThreadContext.argtypes = [wintypes.HANDLE, ctypes.POINTER(WOW64_CONTEXT)]
kernel32.Wow64SetThreadContext.restype = wintypes.BOOL


def win_error(prefix: str) -> OSError:
    return OSError(ctypes.get_last_error(), prefix)


def close_handle(handle: int | None) -> None:
    if handle and handle != INVALID_HANDLE_VALUE:
        kernel32.CloseHandle(handle)


def parse_int(text: str) -> int:
    return int(text, 0)


def read_process(handle: int, address: int, size: int) -> bytes:
    buf = (ctypes.c_ubyte * size)()
    got = ctypes.c_size_t()
    ok = kernel32.ReadProcessMemory(
        handle, ctypes.c_void_p(address), buf, size, ctypes.byref(got)
    )
    if not ok:
        raise win_error(f"ReadProcessMemory failed at {address:#x}")
    return bytes(buf[: got.value])


def write_process(handle: int, address: int, data: bytes) -> None:
    buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    written = ctypes.c_size_t()
    ok = kernel32.WriteProcessMemory(
        handle, ctypes.c_void_p(address), buf, len(data), ctypes.byref(written)
    )
    if not ok or written.value != len(data):
        raise win_error(f"WriteProcessMemory failed at {address:#x}")
    kernel32.FlushInstructionCache(handle, ctypes.c_void_p(address), len(data))


def u32(data: bytes, offset: int = 0) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def launch_debuggee(exe: Path, extra_args: list[str], new_console: bool) -> tuple[int, int]:
    cmdline = subprocess.list2cmdline([str(exe), *extra_args])
    mutable_cmdline = ctypes.create_unicode_buffer(cmdline)
    startup = STARTUPINFOW()
    startup.cb = ctypes.sizeof(startup)
    info = PROCESS_INFORMATION()
    flags = DEBUG_ONLY_THIS_PROCESS | (CREATE_NEW_CONSOLE if new_console else 0)
    ok = kernel32.CreateProcessW(
        None,
        mutable_cmdline,
        None,
        None,
        False,
        flags,
        None,
        str(exe.parent),
        ctypes.byref(startup),
        ctypes.byref(info),
    )
    if not ok:
        raise win_error("CreateProcessW failed")
    close_handle(info.hThread)
    return int(info.dwProcessId), int(info.hProcess)


def launch_process(exe: Path, extra_args: list[str], new_console: bool) -> tuple[int, int]:
    cmdline = subprocess.list2cmdline([str(exe), *extra_args])
    mutable_cmdline = ctypes.create_unicode_buffer(cmdline)
    startup = STARTUPINFOW()
    startup.cb = ctypes.sizeof(startup)
    info = PROCESS_INFORMATION()
    flags = CREATE_NEW_CONSOLE if new_console else 0
    ok = kernel32.CreateProcessW(
        None,
        mutable_cmdline,
        None,
        None,
        False,
        flags,
        None,
        str(exe.parent),
        ctypes.byref(startup),
        ctypes.byref(info),
    )
    if not ok:
        raise win_error("CreateProcessW failed")
    close_handle(info.hThread)
    return int(info.dwProcessId), int(info.hProcess)


def attach_debuggee(pid: int) -> tuple[int, int]:
    handle = kernel32.OpenProcess(PROCESS_ALL_FOR_DEBUG, False, pid)
    if not handle:
        raise win_error("OpenProcess failed")
    if not kernel32.DebugActiveProcess(pid):
        close_handle(handle)
        raise win_error("DebugActiveProcess failed")
    return pid, int(handle)


def attach_debuggee_with_handle(pid: int, process: int) -> int:
    if not kernel32.DebugActiveProcess(pid):
        raise win_error("DebugActiveProcess failed")
    return process


def is_process_alive(process: int) -> bool:
    code = wintypes.DWORD()
    if not kernel32.GetExitCodeProcess(process, ctypes.byref(code)):
        raise win_error("GetExitCodeProcess failed")
    return int(code.value) == STILL_ACTIVE


def list_modules(pid: int) -> list[ModuleInfo]:
    # From a 64-bit host, TH32CS_SNAPMODULE alone fails with ERROR_PARTIAL_COPY (299)
    # when targeting a 32-bit (WOW64) process; use TH32CS_SNAPMODULE32 only.
    # ERROR_PARTIAL_COPY (299) can occur transiently; retry a few times.
    flags = TH32CS_SNAPMODULE32 if struct.calcsize("P") == 8 else (TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32)
    snapshot = wintypes.HANDLE(INVALID_HANDLE_VALUE)
    for _ in range(5):
        snapshot = kernel32.CreateToolhelp32Snapshot(flags, pid)
        if snapshot != INVALID_HANDLE_VALUE:
            break
        err = ctypes.get_last_error()
        if err != 299:  # ERROR_PARTIAL_COPY
            raise win_error("CreateToolhelp32Snapshot(module) failed")
        time.sleep(0.05)
    if snapshot == INVALID_HANDLE_VALUE:
        return []  # process may not have any modules yet
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


def wait_for_target_module(pid: int, process: int, args: argparse.Namespace) -> ModuleInfo:
    deadline = time.monotonic() + args.timeout_sec
    seen_base: int | None = None
    while time.monotonic() < deadline:
        if not is_process_alive(process):
            raise RuntimeError("target process exited before random DLL was observed")
        matches = [
            module
            for module in list_modules(pid)
            if is_target_module(module.path, module.base, args)
        ]
        if matches:
            module = matches[-1]
            print(f"[*] target module observed {module.base:#010x} {module.path}")
            return module
        if args.verbose:
            randomish = [m for m in list_modules(pid) if RANDOM_DLL_RE.match(m.name)]
            for module in randomish:
                if module.base != seen_base:
                    seen_base = module.base
                    print(f"[*] random-looking module {module.base:#010x} {module.path}")
        time.sleep(max(args.poll_ms, 1) / 1000.0)
    raise TimeoutError(f"target module was not loaded within {args.timeout_sec:g}s")


def path_from_file_handle(handle: int | None) -> str:
    if not handle:
        return ""
    buf = ctypes.create_unicode_buffer(32768)
    n = kernel32.GetFinalPathNameByHandleW(handle, buf, len(buf), 0)
    if not n:
        return ""
    text = buf.value
    return text.removeprefix("\\\\?\\")


def is_target_module(path: str, base: int, args: argparse.Namespace) -> bool:
    name = Path(path).name if path else ""
    if args.module_name and name.casefold() == args.module_name.casefold():
        return True
    if args.module_regex and re.search(args.module_regex, path, re.IGNORECASE):
        return True
    if args.module_base is not None and base == args.module_base:
        return True
    norm = path.replace("/", "\\").casefold()
    return "\\temp\\krkr_" in norm and RANDOM_DLL_RE.match(name) is not None


def set_breakpoint(process: int, module_base: int, path: str, rva: int) -> Breakpoint:
    addr = module_base + rva
    original = read_process(process, addr, 1)
    write_process(process, addr, b"\xCC")
    print(f"[+] breakpoint set at {addr:#010x} ({path or 'unknown module'} + {rva:#x})")
    return Breakpoint(addr=addr, original_byte=original, module_base=module_base, module_path=path)


def open_thread(thread_id: int) -> int:
    thread = kernel32.OpenThread(THREAD_ALL_FOR_CONTEXT, False, thread_id)
    if not thread:
        raise win_error(f"OpenThread({thread_id}) failed")
    return int(thread)


def get_wow64_context(thread: int) -> WOW64_CONTEXT:
    ctx = WOW64_CONTEXT()
    ctx.ContextFlags = WOW64_CONTEXT_CONTROL
    if not kernel32.Wow64GetThreadContext(thread, ctypes.byref(ctx)):
        raise win_error("Wow64GetThreadContext failed")
    return ctx


def set_wow64_context(thread: int, ctx: WOW64_CONTEXT) -> None:
    if not kernel32.Wow64SetThreadContext(thread, ctypes.byref(ctx)):
        raise win_error("Wow64SetThreadContext failed")


def capture_stack_args(process: int, esp: int, max_string_bytes: int) -> dict[str, object]:
    stack = read_process(process, esp, 16)
    string_ptr = u32(stack, 0)
    string_len = u32(stack, 4)
    params_ptr = u32(stack, 8)
    params_len = u32(stack, 12)

    if string_len > max_string_bytes:
        raise RuntimeError(f"bootstrap string length looks wrong: {string_len:#x}")
    if params_len > 0x10000:
        raise RuntimeError(f"PARAMS length looks wrong: {params_len:#x}")

    string_bytes = read_process(process, string_ptr, string_len) if string_len else b""
    params = read_process(process, params_ptr, params_len) if params_len else b""
    bootstrap_text = string_bytes.decode("utf-16le", errors="replace")
    return {
        "esp": esp,
        "bootstrap_ptr": string_ptr,
        "bootstrap_byte_len": string_len,
        "bootstrap_text": bootstrap_text,
        "bootstrap_utf16le_hex": string_bytes.hex(),
        "params_ptr": params_ptr,
        "params_len": params_len,
        "params_hex": params.hex(),
    }


def handle_breakpoint(
    process: int,
    thread_id: int,
    bp: Breakpoint,
    args: argparse.Namespace,
) -> dict[str, object]:
    thread = open_thread(thread_id)
    try:
        ctx = get_wow64_context(thread)
        eip = int(ctx.Eip)
        if eip == bp.addr + 1:
            ctx.Eip = bp.addr
            set_wow64_context(thread, ctx)
            eip = bp.addr
        if eip != bp.addr:
            raise RuntimeError(f"breakpoint thread stopped at unexpected EIP {eip:#x}")

        result = capture_stack_args(process, int(ctx.Esp), args.max_string_bytes)
        result.update(
            {
                "module_base": bp.module_base,
                "module_path": bp.module_path,
                "breakpoint_addr": bp.addr,
                "breakpoint_rva": args.break_rva,
                "thread_id": thread_id,
                "eip": eip,
            }
        )

        write_process(process, bp.addr, bp.original_byte)
        return result
    finally:
        close_handle(thread)


def debug_loop(
    pid: int,
    process: int,
    args: argparse.Namespace,
    initial_bp: Breakpoint | None = None,
) -> dict[str, object]:
    bp: Breakpoint | None = initial_bp
    captured: dict[str, object] | None = None

    while True:
        event = DEBUG_EVENT()
        if not kernel32.WaitForDebugEvent(ctypes.byref(event), INFINITE):
            raise win_error("WaitForDebugEvent failed")

        code = int(event.dwDebugEventCode)
        event_pid = int(event.dwProcessId)
        thread_id = int(event.dwThreadId)
        continue_status = DBG_CONTINUE

        try:
            if event_pid != pid:
                continue

            if code == CREATE_PROCESS_DEBUG_EVENT:
                info = event.u.CreateProcessInfo
                path = path_from_file_handle(info.hFile)
                base = int(info.lpBaseOfImage or 0)
                print(f"[*] process image {base:#010x} {path}")
                if is_target_module(path, base, args) and bp is None:
                    bp = set_breakpoint(process, base, path, args.break_rva)
                close_handle(info.hFile)

            elif code == LOAD_DLL_DEBUG_EVENT:
                info = event.u.LoadDll
                path = path_from_file_handle(info.hFile)
                base = int(info.lpBaseOfDll or 0)
                name = Path(path).name if path else ""
                if args.verbose or is_target_module(path, base, args):
                    print(f"[*] load dll {base:#010x} {path or name or '<unknown>'}")
                if is_target_module(path, base, args) and bp is None:
                    bp = set_breakpoint(process, base, path, args.break_rva)
                close_handle(info.hFile)

            elif code == EXCEPTION_DEBUG_EVENT:
                ex = event.u.Exception
                ex_code = int(ex.ExceptionRecord.ExceptionCode)
                ex_addr = int(ex.ExceptionRecord.ExceptionAddress or 0)
                first = int(ex.dwFirstChance)
                if (
                    bp is not None
                    and ex_code == EXCEPTION_BREAKPOINT
                    and ex_addr in (bp.addr, bp.addr + 1)
                ):
                    print(f"[+] hit bootstrap breakpoint at {ex_addr:#010x}")
                    captured = handle_breakpoint(process, thread_id, bp, args)
                    break

                if ex_code == EXCEPTION_BREAKPOINT:
                    continue_status = DBG_CONTINUE
                else:
                    continue_status = DBG_EXCEPTION_NOT_HANDLED if first else DBG_CONTINUE

            elif code == EXIT_PROCESS_DEBUG_EVENT:
                exit_code = int(event.u.ExitProcess.dwExitCode)
                raise RuntimeError(f"process exited before capture, exit_code={exit_code:#x}")

        finally:
            if captured is None:
                kernel32.ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continue_status)

    assert captured is not None
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(captured, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[+] wrote {out}")
    else:
        print(json.dumps(captured, ensure_ascii=False, indent=2))

    if args.keep_running:
        kernel32.ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE)
        kernel32.DebugActiveProcessStop(pid)
        print("[+] restored original byte and detached; process continues")
    else:
        kernel32.TerminateProcess(process, 0)
        kernel32.ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE)
        print("[+] restored original byte and terminated debuggee")

    return captured


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Launch/attach and capture final System.bootStrap arguments."
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--exe", type=Path, help="game executable to launch")
    target.add_argument("--pid", type=parse_int, help="existing process id to attach to")
    parser.add_argument("game_args", nargs=argparse.REMAINDER, help="arguments after -- are passed to --exe")
    parser.add_argument(
        "--launch-mode",
        choices=("late-attach", "debug"),
        default="late-attach",
        help="late-attach launches normally first to avoid startup anti-debug checks",
    )
    parser.add_argument("--out", type=Path, help="write capture JSON here")
    parser.add_argument("--break-rva", type=parse_int, default=0xF269)
    parser.add_argument("--module-name", help="exact DLL file name to break in")
    parser.add_argument("--module-regex", help="regex matched against loaded DLL path")
    parser.add_argument("--module-base", type=parse_int, help="known loaded module base")
    parser.add_argument("--max-string-bytes", type=parse_int, default=0x4000)
    parser.add_argument("--poll-ms", type=int, default=5)
    parser.add_argument("--timeout-sec", type=float, default=60.0)
    parser.add_argument("--new-console", action="store_true", help="launch target in a new console")
    parser.add_argument("--keep-running", action="store_true", help="detach after capture instead of terminating")
    parser.add_argument("--verbose", action="store_true", help="print every DLL load event")
    return parser


def main() -> int:
    if os.name != "nt":
        print("This script requires Windows debugging APIs.", file=sys.stderr)
        return 2

    parser = build_parser()
    args = parser.parse_args()
    if args.game_args and args.game_args[0] == "--":
        args.game_args = args.game_args[1:]

    process = 0
    try:
        initial_bp: Breakpoint | None = None
        if args.exe:
            exe = args.exe.resolve()
            if args.launch_mode == "debug":
                pid, process = launch_debuggee(exe, args.game_args, args.new_console)
                print(f"[*] launched under debugger pid={pid} exe={exe}")
            else:
                pid, process = launch_process(exe, args.game_args, args.new_console)
                print(f"[*] launched normally pid={pid} exe={exe}")
                module = wait_for_target_module(pid, process, args)
                attach_debuggee_with_handle(pid, process)
                print(f"[*] debugger attached after target module load")
                initial_bp = set_breakpoint(process, module.base, module.path, args.break_rva)
        else:
            pid, process = attach_debuggee(args.pid)
            print(f"[*] attached pid={pid}")

        debug_loop(pid, process, args, initial_bp)
        return 0
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        close_handle(process)


if __name__ == "__main__":
    raise SystemExit(main())
