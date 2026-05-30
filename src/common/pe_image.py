from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path


def u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


@dataclass(frozen=True)
class Section:
    name: str
    va: int
    size: int
    raw: int
    raw_size: int


class PeImage:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.data = path.read_bytes()
        pe = u32(self.data, 0x3C)
        if self.data[pe : pe + 4] != b"PE\0\0":
            raise ValueError(f"{path} is not a PE file")

        coff = pe + 4
        section_count = u16(self.data, coff + 2)
        optional_size = u16(self.data, coff + 16)
        optional = coff + 20
        magic = u16(self.data, optional)
        data_dir = optional + (96 if magic == 0x10B else 112)
        self.resource_rva = u32(self.data, data_dir + 2 * 8)
        self.resource_size = u32(self.data, data_dir + 2 * 8 + 4)

        self.sections: list[Section] = []
        section_table = optional + optional_size
        for index in range(section_count):
            off = section_table + index * 40
            name = self.data[off : off + 8].split(b"\0", 1)[0].decode(errors="replace")
            virtual_size = u32(self.data, off + 8)
            va = u32(self.data, off + 12)
            raw_size = u32(self.data, off + 16)
            raw = u32(self.data, off + 20)
            self.sections.append(Section(name, va, max(virtual_size, raw_size), raw, raw_size))

    def rva_to_offset(self, rva: int) -> int:
        for section in self.sections:
            if section.va <= rva < section.va + section.size:
                return section.raw + (rva - section.va)
        raise ValueError(f"RVA 0x{rva:x} is not mapped in {self.path}")

    def read_rva(self, rva: int, size: int) -> bytes:
        off = self.rva_to_offset(rva)
        return self.data[off : off + size]

    def resources(self) -> dict[tuple[object, object, object], bytes]:
        if not self.resource_rva:
            return {}
        resource_off = self.rva_to_offset(self.resource_rva)

        def read_name(name_off: int) -> str:
            length = u16(self.data, resource_off + name_off)
            raw = self.data[resource_off + name_off + 2 : resource_off + name_off + 2 + length * 2]
            return raw.decode("utf-16le", errors="replace")

        def walk(directory_rel: int, path: tuple[object, ...]) -> dict[tuple[object, object, object], bytes]:
            base = resource_off + directory_rel
            named = u16(self.data, base + 12)
            ids = u16(self.data, base + 14)
            found: dict[tuple[object, object, object], bytes] = {}
            for index in range(named + ids):
                entry = base + 16 + index * 8
                name_raw = u32(self.data, entry)
                child = u32(self.data, entry + 4)
                name: object = read_name(name_raw & 0x7FFFFFFF) if name_raw & 0x80000000 else name_raw
                if child & 0x80000000:
                    found.update(walk(child & 0x7FFFFFFF, path + (name,)))
                else:
                    data_entry = resource_off + child
                    rva = u32(self.data, data_entry)
                    size = u32(self.data, data_entry + 4)
                    found[path + (name,)] = self.read_rva(rva, size)
            return found

        return walk(0, ())


def read_file_offset(path: Path, offset: int, size: int) -> bytes:
    if offset < 0:
        raise ValueError(f"negative file offset: 0x{offset:x}")
    with path.open("rb") as f:
        f.seek(offset)
        data = f.read(size)
    if len(data) != size:
        raise ValueError(f"{path}: offset 0x{offset:x} has {len(data)} bytes; expected {size}")
    return data


def format_resource_key(key: tuple[object, object, object]) -> str:
    return "/".join(str(part) for part in key)


def find_resource(resources: dict[tuple[object, object, object], bytes], res_type: object, name: object) -> bytes:
    for (current_type, current_name, _language), data in resources.items():
        if current_type == res_type and current_name == name:
            return data
    sample = ", ".join(format_resource_key(key) for key in sorted(resources, key=format_resource_key)[:12])
    suffix = f"; available resources include: {sample}" if sample else "; PE has no parsed resources"
    raise KeyError(f"resource {res_type!r}/{name!r} was not found{suffix}")


def find_optional_resource(
    resources: dict[tuple[object, object, object], bytes], res_type: object, name: object
) -> bytes | None:
    try:
        return find_resource(resources, res_type, name)
    except KeyError:
        return None
