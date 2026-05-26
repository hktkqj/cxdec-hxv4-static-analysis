#!/usr/bin/env python3
"""Inspect the random plugin FilterManager state in a full-memory minidump."""

from __future__ import annotations

import argparse
import json
import re
import struct
from dataclasses import dataclass
from pathlib import Path


RANDOM_DLL_RE = re.compile(r"^[0-9a-f]{12}\.dll$", re.IGNORECASE)


@dataclass(frozen=True)
class ModuleInfo:
    base: int
    size: int
    path: str

    @property
    def name(self) -> str:
        return Path(self.path).name


@dataclass(frozen=True)
class Region:
    start: int
    end: int
    file_start: int
    file_end: int


class MiniDump:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.data = path.read_bytes()
        if self.data[:4] != b"MDMP":
            raise ValueError(f"{path} is not a minidump")
        self.streams = self._read_stream_dir()
        self.modules = self._read_modules()
        self.regions = self._read_memory64()

    def _read_stream_dir(self) -> dict[int, tuple[int, int]]:
        count = struct.unpack_from("<I", self.data, 8)[0]
        rva = struct.unpack_from("<I", self.data, 12)[0]
        streams: dict[int, tuple[int, int]] = {}
        for index in range(count):
            stype, size, srva = struct.unpack_from("<III", self.data, rva + index * 12)
            streams[stype] = (size, srva)
        return streams

    def _read_modules(self) -> list[ModuleInfo]:
        if 4 not in self.streams:
            return []
        _, rva = self.streams[4]
        count = struct.unpack_from("<I", self.data, rva)[0]
        modules: list[ModuleInfo] = []
        off = rva + 4
        for _ in range(count):
            base, size, _checksum, _timestamp, name_rva = struct.unpack_from("<QIIII", self.data, off)
            name_len = struct.unpack_from("<I", self.data, name_rva)[0]
            path = self.data[name_rva + 4 : name_rva + 4 + name_len].decode("utf-16le", "replace")
            modules.append(ModuleInfo(base, size, path))
            off += 108
        return modules

    def _read_memory64(self) -> list[Region]:
        if 9 not in self.streams:
            return []
        _, rva = self.streams[9]
        count = struct.unpack_from("<Q", self.data, rva)[0]
        file_off = struct.unpack_from("<Q", self.data, rva + 8)[0]
        regions: list[Region] = []
        for index in range(count):
            start, size = struct.unpack_from("<QQ", self.data, rva + 16 + index * 16)
            regions.append(Region(start, start + size, file_off, file_off + size))
            file_off += size
        return regions

    def va_to_offset(self, va: int) -> int | None:
        for region in self.regions:
            if region.start <= va < region.end:
                return region.file_start + va - region.start
        return None

    def read(self, va: int, size: int) -> bytes:
        off = self.va_to_offset(va)
        if off is None:
            raise ValueError(f"VA {va:#x} is not present in dump")
        return self.data[off : off + size]

    def u32(self, va: int) -> int:
        return struct.unpack("<I", self.read(va, 4))[0]

    def module_for(self, va: int) -> str:
        for module in self.modules:
            if module.base <= va < module.base + module.size:
                return f"{module.name}+0x{va - module.base:x}"
        return ""


def is_random_plugin(module: ModuleInfo) -> bool:
    path = module.path.replace("/", "\\").casefold()
    return "\\temp\\krkr_" in path and RANDOM_DLL_RE.match(module.name) is not None


def fmt_ptr(mdmp: MiniDump, value: int) -> str:
    suffix = mdmp.module_for(value)
    if suffix:
        return f"{value:#010x} ({suffix})"
    if mdmp.va_to_offset(value) is not None:
        return f"{value:#010x} (mapped)"
    return f"{value:#010x}"


def write_blob(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    print(f"wrote {path} ({len(data):#x} bytes)")


def _u32_list(data: bytes) -> list[int]:
    limit = len(data) & ~3
    return [struct.unpack_from("<I", data, offset)[0] for offset in range(0, limit, 4)]


def write_drip_program(
    mdmp: MiniDump,
    module: ModuleInfo,
    manager: int,
    drip_impl: int,
    path: Path,
) -> None:
    holder = manager + 8
    holder_words = [mdmp.u32(holder + index * 4) for index in range(6)]
    lanes: list[dict[str, object]] = []
    ctx_ptrs: set[int] = set()

    for lane_index in range(128):
        lane_va = drip_impl + 4 + lane_index * 0x10
        begin = mdmp.u32(lane_va)
        end = mdmp.u32(lane_va + 4)
        current = mdmp.u32(lane_va + 8)
        ctx = mdmp.u32(lane_va + 0xC)
        ctx_ptrs.add(ctx)

        if end < begin or (end - begin) % 8:
            raise ValueError(f"lane {lane_index} has invalid record range {begin:#x}..{end:#x}")

        records: list[list[int]] = []
        for record_va in range(begin, end, 8):
            param = mdmp.u32(record_va)
            callback = mdmp.u32(record_va + 4)
            callback_rva = (
                callback - module.base
                if module.base <= callback < module.base + module.size
                else callback
            )
            records.append([param, callback_rva])

        lanes.append(
            {
                "index": lane_index,
                "begin_va": begin,
                "end_va": end,
                "current_va": current,
                "ctx_va": ctx,
                "records": records,
            }
        )

    if len(ctx_ptrs) != 1:
        raise ValueError(f"expected one Drip context pointer, got {sorted(ctx_ptrs)!r}")
    ctx = next(iter(ctx_ptrs))
    if not (manager <= ctx < manager + 0x30B0):
        raise ValueError(f"Drip context pointer {ctx:#x} is outside FilterManager")
    context = mdmp.read(ctx, manager + 0x30B0 - ctx)

    payload = {
        "version": 1,
        "source_module": module.name,
        "source_module_base": module.base,
        "manager_va": manager,
        "drip_impl_va": drip_impl,
        "holder_words": holder_words,
        "context_va": ctx,
        "context_u32": _u32_list(context),
        "callback_rva_base": module.base,
        "lanes": lanes,
    }

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"wrote {path} ({len(lanes)} lanes, {len(payload['context_u32'])} context dwords)")


def inspect(path: Path, manager_slot_rva: int, out_prefix: Path | None) -> None:
    mdmp = MiniDump(path)
    random_modules = [module for module in mdmp.modules if is_random_plugin(module)]
    print(f"{path}: modules={len(mdmp.modules)} random_plugins={len(random_modules)}")
    for module in random_modules:
        print(f"random plugin: base={module.base:#010x} size={module.size:#x} path={module.path}")
        slot = module.base + manager_slot_rva
        manager = mdmp.u32(slot)
        print(f"  g_FilterManager slot {slot:#010x} -> {fmt_ptr(mdmp, manager)}")
        if not manager:
            continue

        manager0 = mdmp.u32(manager)
        manager1 = mdmp.u32(manager + 4)
        drip_holder = manager + 8
        drip_impl = mdmp.u32(drip_holder)
        drip_vtable = mdmp.u32(drip_impl) if drip_impl else 0
        print(f"  manager[0] wrapper -> {fmt_ptr(mdmp, manager0)}")
        print(f"  manager[1]         -> {fmt_ptr(mdmp, manager1)}")
        print(f"  drip holder field  -> {fmt_ptr(mdmp, drip_holder)}")
        print(f"  drip impl          -> {fmt_ptr(mdmp, drip_impl)}")
        print(f"  drip impl vtable   -> {fmt_ptr(mdmp, drip_vtable)}")

        if manager0:
            closure_obj = mdmp.u32(manager0)
            closure_this = mdmp.u32(manager0 + 4)
            print(f"  manager[0][0] closure object -> {fmt_ptr(mdmp, closure_obj)}")
            print(f"  manager[0][1] closure this   -> {fmt_ptr(mdmp, closure_this)}")
            if closure_obj:
                print(f"    closure object vtable      -> {fmt_ptr(mdmp, mdmp.u32(closure_obj))}")
            if closure_this:
                print(f"    closure this vtable        -> {fmt_ptr(mdmp, mdmp.u32(closure_this))}")

        if out_prefix is not None:
            stem = out_prefix.with_suffix("")
            write_blob(stem.with_suffix(".filter_manager.bin"), mdmp.read(manager, 0x30B0))
            if drip_impl:
                write_blob(stem.with_suffix(".drip_impl.bin"), mdmp.read(drip_impl, 0x804))
                write_drip_program(
                    mdmp,
                    module,
                    manager,
                    drip_impl,
                    stem.with_suffix(".drip_program.json"),
                )
            if manager0:
                write_blob(stem.with_suffix(".manager0_wrapper.bin"), mdmp.read(manager0, 8))
                closure_obj = mdmp.u32(manager0)
                closure_this = mdmp.u32(manager0 + 4)
                if closure_obj:
                    write_blob(stem.with_suffix(".closure_obj_head.bin"), mdmp.read(closure_obj, 0x400))
                if closure_this:
                    write_blob(stem.with_suffix(".closure_this_head.bin"), mdmp.read(closure_this, 0x400))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dump", type=Path)
    parser.add_argument("--manager-slot-rva", type=lambda s: int(s, 0), default=0xAC9AC)
    parser.add_argument("--out-prefix", type=Path)
    args = parser.parse_args()
    inspect(args.dump, args.manager_slot_rva, args.out_prefix)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
