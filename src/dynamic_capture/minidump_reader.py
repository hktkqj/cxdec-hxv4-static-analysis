from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path


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
