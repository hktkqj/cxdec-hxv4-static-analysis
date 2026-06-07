#!/usr/bin/env python3
"""PSB (M2/Kirikiri pimg) File Parser and Extractor.

Parses Kirikiri engine PSB container files (magic: "PSB\\x00", version 3).
These files contain serialized TJS2 script objects with embedded resources
(typically TLG images). The format uses a tagged binary encoding with
variable-length integers (prefix bytes 0x0D-0x10 for 1-4 byte widths)
and supports zlib-compressed sections.

Based on reverse engineering of psbfile.dll and binary sample analysis.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import struct
import subprocess
import sys
import uuid
import zlib
from dataclasses import dataclass, field
from enum import IntEnum, auto
from io import BytesIO
from pathlib import Path
from typing import Any, BinaryIO, Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PSB_MAGIC = b"PSB\0"
PSB_HEADER_SIZE = 40  # PSBHDR: magic + version/encrypt + 8 offsets

# Variable-length integer prefix bytes
VARINT_U8 = 0x0D   # 1-byte unsigned
VARINT_U16 = 0x0E  # 2-byte unsigned LE
VARINT_U24 = 0x0F  # 3-byte unsigned LE
VARINT_U32 = 0x10  # 4-byte unsigned LE

VARINT_PREFIXES = {VARINT_U8: 1, VARINT_U16: 2, VARINT_U24: 3, VARINT_U32: 4}

# Inline value markers (distinct from length-prefixed varints)
INLINE_U8 = 0x11
INLINE_U16 = 0x12
INLINE_U24 = 0x13
INLINE_U32 = 0x14

# PSB data type constants (from psbfile.dll type classification)
TYPE_NULL = 0x00       # Not in switch, treated as null
TYPE_U8 = 0x01         # 0-byte? (case 1 → returns 0)
TYPE_U8_2 = 0x02       # 1-byte (case 2-3 → returns 1)
TYPE_U8_3 = 0x03       # 1-byte
TYPE_U16_BASE = 0x04   # 2-byte (case 4-12 → returns 2)
TYPE_U16_END = 0x0C
TYPE_FLOAT32_BASE = 0x15  # 4-byte (case 0x15-0x18 → returns 4)
TYPE_FLOAT32_END = 0x18
TYPE_FLOAT64_BASE = 0x19  # 5-byte (case 0x19-0x1C → returns 5)
TYPE_FLOAT64_END = 0x1C
TYPE_U24_BASE = 0x1D      # 3-byte (case 0x1D-0x1F → returns 3)
TYPE_U24_END = 0x1F
TYPE_RES7 = 0x20          # 6-byte (returns 6)
TYPE_RES8 = 0x21          # 7-byte (returns 7)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class PSBError(Exception):
    """Base exception for PSB parsing errors."""


class PSBMagicError(PSBError):
    """Invalid PSB magic bytes."""


class PSBVersionError(PSBError):
    """Unsupported PSB version."""


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

class PSBTypeWidth(IntEnum):
    """Byte width for PSB data types.

    Based on sub_1000B3B0 in psbfile.dll.
    """
    NULL_OR_SINGLE = 0
    U8 = 1
    U16 = 2
    U24 = 3
    F32 = 4
    F64 = 5
    RES7 = 6
    RES8 = 7


@dataclass
class PSBHeader:
    """PSB file header (40 bytes), matching krkrpsb PSBHDR."""
    magic: bytes                    # "PSB\0"
    version: int                    # 3
    encrypt: int                    # 0 for plain section tables
    offset_encrypt: int             # Usually 0 or offset_names
    offset_names: int               # Name b-tree arrays
    offset_strings: int             # String offset table
    offset_strings_data: int        # String pool
    offset_chunk_offsets: int       # Resource offsets array
    offset_chunk_lengths: int       # Resource lengths array
    offset_chunk_data: int          # Resource data base
    offset_entries: int             # Root object/value stream

    @property
    def resources_offset(self) -> int:
        return self.offset_chunk_data


@dataclass
class PSBTagInfo:
    """Information about a PSB data type tag."""
    type_byte: int
    name: str
    width: int
    is_primitive: bool = False
    is_varint_prefix: bool = False
    is_inline_value: bool = False


@dataclass
class TLGHeader:
    """TLG image header."""
    magic: str          # "TLG5.0" or "TLG0.0"
    raw_format: str     # Usually "raw"
    colors: int         # Color type (1, 2 3, or 4)
    width: int
    height: int
    block_size: int     # Maximum block size for compression


@dataclass
class PSBArray:
    """Packed integer array used by M2 PSB."""
    offset: int
    end: int
    count_type: int
    count: int
    entry_type: int
    entry_width: int
    values: list[int]


@dataclass
class PSBResource:
    """Embedded resource chunk."""
    index: int
    name: str
    file_offset: int
    relative_offset: int
    length: int
    resource_type: str = "unknown"
    extension: str = ".bin"
    tlg_header: Optional[TLGHeader] = None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable resource summary."""
        item: dict[str, Any] = {
            "index": self.index,
            "name": self.name,
            "file_offset": self.file_offset,
            "relative_offset": self.relative_offset,
            "length": self.length,
            "resource_type": self.resource_type,
            "extension": self.extension,
        }
        if self.tlg_header:
            item["tlg"] = {
                "magic": self.tlg_header.magic,
                "raw_format": self.tlg_header.raw_format,
                "colors": self.tlg_header.colors,
                "width": self.tlg_header.width,
                "height": self.tlg_header.height,
                "block_size": self.tlg_header.block_size,
            }
        return item


@dataclass
class PSBFile:
    """Parsed PSB file representation."""
    header: PSBHeader
    type_palette: list[int] = field(default_factory=list)
    names: list[str] = field(default_factory=list)
    tlg_header: Optional[TLGHeader] = None
    raw_data_offset: int = 0
    raw_data_size: int = 0
    sections: dict[str, bytes] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Variable-Length Integer (VarInt) Reader
# ---------------------------------------------------------------------------

def read_varint(stream: BinaryIO) -> int:
    """Read a PSB variable-length unsigned integer from stream.

    PSB varints use explicit prefix bytes instead of continuation bits:
    - 0x0D: 1-byte value follows
    - 0x0E: 2-byte value follows (little-endian)
    - 0x0F: 3-byte value follows (little-endian)
    - 0x10: 4-byte value follows (little-endian)

    Args:
        stream: Binary file-like object positioned at the prefix byte.

    Returns:
        The decoded unsigned integer value.

    Raises:
        PSBError: If an unknown prefix byte is encountered.
    """
    prefix = stream.read(1)
    if not prefix:
        raise PSBError("Unexpected end of stream while reading varint prefix")
    prefix_byte = prefix[0]

    size = VARINT_PREFIXES.get(prefix_byte)
    if size is None:
        raise PSBError(
            f"Unknown varint prefix: 0x{prefix_byte:02X} "
            f"at offset 0x{stream.tell() - 1:08X}"
        )

    data = stream.read(size)
    if len(data) < size:
        raise PSBError(
            f"Unexpected end of stream while reading varint data "
            f"(expected {size} bytes, got {len(data)})"
        )

    return int.from_bytes(data, 'little')


def write_varint(value: int) -> bytes:
    """Encode an integer as a PSB variable-length integer.

    Args:
        value: Unsigned integer to encode.

    Returns:
        Bytes of the encoded varint (prefix + data).
    """
    if value <= 0xFF:
        return bytes([VARINT_U8, value])
    elif value <= 0xFFFF:
        return bytes([VARINT_U16]) + value.to_bytes(2, 'little')
    elif value <= 0xFFFFFF:
        return bytes([VARINT_U24]) + value.to_bytes(3, 'little')
    else:
        return bytes([VARINT_U32]) + value.to_bytes(4, 'little')


def peek_varint_prefix(stream: BinaryIO) -> tuple[int, int]:
    """Peek at the next varint without consuming the prefix byte.

    Args:
        stream: Binary file-like object.

    Returns:
        Tuple of (prefix_byte, data_byte_count).
    """
    pos = stream.tell()
    prefix = stream.read(1)
    stream.seek(pos)
    if not prefix:
        raise PSBError("Unexpected end of stream")
    prefix_byte = prefix[0]
    size = VARINT_PREFIXES.get(prefix_byte, 0)
    return prefix_byte, size


# ---------------------------------------------------------------------------
# Type Classification (based on psbfile.dll sub_1000B3B0)
# ---------------------------------------------------------------------------

def classify_type_tag(type_byte: int) -> PSBTagInfo:
    """Classify a PSB type tag byte.

    Args:
        type_byte: The type tag byte value.

    Returns:
        PSBTagInfo with classification details.
    """
    if type_byte == 1:
        return PSBTagInfo(type_byte, "null_or_single", 0, is_primitive=True)
    elif 2 <= type_byte <= 3:
        return PSBTagInfo(type_byte, "u8", 1, is_primitive=True)
    elif 4 <= type_byte <= 0x0C:
        return PSBTagInfo(type_byte, "u16", 2, is_primitive=True)
    elif type_byte == VARINT_U8:
        return PSBTagInfo(type_byte, "varint_u8_prefix", 1, is_varint_prefix=True)
    elif type_byte == VARINT_U16:
        return PSBTagInfo(type_byte, "varint_u16_prefix", 2, is_varint_prefix=True)
    elif type_byte == VARINT_U24:
        return PSBTagInfo(type_byte, "varint_u24_prefix", 3, is_varint_prefix=True)
    elif type_byte == VARINT_U32:
        return PSBTagInfo(type_byte, "varint_u32_prefix", 4, is_varint_prefix=True)
    elif INLINE_U8 <= type_byte <= INLINE_U32:
        width = type_byte - 0x10
        return PSBTagInfo(type_byte, f"inline_u{width*8}", width, is_inline_value=True)
    elif 0x15 <= type_byte <= 0x18:
        return PSBTagInfo(type_byte, "float32", 4, is_primitive=True)
    elif 0x19 <= type_byte <= 0x1C:
        return PSBTagInfo(type_byte, "float64", 5, is_primitive=True)
    elif 0x1D <= type_byte <= 0x1F:
        return PSBTagInfo(type_byte, "u24", 3, is_primitive=True)
    elif type_byte == 0x20:
        return PSBTagInfo(type_byte, "res7", 6, is_primitive=True)
    elif type_byte == 0x21:
        return PSBTagInfo(type_byte, "res8", 7, is_primitive=True)
    else:
        return PSBTagInfo(type_byte, f"unknown_0x{type_byte:02X}", 0)


# ---------------------------------------------------------------------------
# Header Parser
# ---------------------------------------------------------------------------

def parse_header(data: bytes) -> PSBHeader:
    """Parse the 40-byte PSB file header.

    Args:
        data: First 40+ bytes of the PSB file.

    Returns:
        PSBHeader dataclass instance.

    Raises:
        PSBMagicError: If magic bytes don't match.
    """
    if len(data) < PSB_HEADER_SIZE:
        raise PSBError(
            f"Data too short for PSB header: {len(data)} bytes "
            f"(need {PSB_HEADER_SIZE})"
        )

    magic = data[0:4]
    if magic != PSB_MAGIC:
        raise PSBMagicError(
            f"Invalid PSB magic: {magic.hex(' ')} (expected 50 53 42 00)"
        )

    (
        magic,
        version,
        encrypt,
        offset_encrypt,
        offset_names,
        offset_strings,
        offset_strings_data,
        offset_chunk_offsets,
        offset_chunk_lengths,
        offset_chunk_data,
        offset_entries,
    ) = struct.unpack_from('<4sHH8I', data, 0)

    return PSBHeader(
        magic=magic,
        version=version,
        encrypt=encrypt,
        offset_encrypt=offset_encrypt,
        offset_names=offset_names,
        offset_strings=offset_strings,
        offset_strings_data=offset_strings_data,
        offset_chunk_offsets=offset_chunk_offsets,
        offset_chunk_lengths=offset_chunk_lengths,
        offset_chunk_data=offset_chunk_data,
        offset_entries=offset_entries,
    )


# ---------------------------------------------------------------------------
# PSB File Reader
# ---------------------------------------------------------------------------

class PSBReader:
    """Reads and parses PSB files."""

    def __init__(self, filepath: str):
        """Initialize reader from file path.

        Args:
            filepath: Path to the PSB file.
        """
        self.filepath = filepath
        self._data: bytes = b""
        self.header: Optional[PSBHeader] = None
        self._name_arrays: Optional[tuple[PSBArray, PSBArray, PSBArray]] = None
        self._names: Optional[list[str]] = None
        self._string_offsets: Optional[PSBArray] = None
        self._strings: Optional[list[str]] = None
        self._chunk_offsets: Optional[PSBArray] = None
        self._chunk_lengths: Optional[PSBArray] = None
        self._parse()

    def _parse(self) -> None:
        """Read and parse the PSB file."""
        with open(self.filepath, 'rb') as f:
            self._data = f.read()

        if len(self._data) < PSB_HEADER_SIZE:
            raise PSBError(
                f"File too small to be a valid PSB: {len(self._data)} bytes"
            )

        self.header = parse_header(self._data)

    @property
    def data(self) -> bytes:
        """Get the raw file data."""
        return self._data

    def _read_uint_n(self, offset: int, size: int) -> int:
        """Read a little-endian integer with an explicit byte width."""
        if size < 0 or size > 8:
            raise PSBError(f"Unsupported integer width {size} at 0x{offset:08X}")
        if offset + size > len(self._data):
            raise PSBError(f"Integer at 0x{offset:08X} exceeds file size")
        return int.from_bytes(self._data[offset:offset + size], "little")

    def read_psb_array(self, offset: int) -> PSBArray:
        """Read a krkrpsb psb_array_t packed integer array."""
        if offset >= len(self._data):
            raise PSBError(f"Array offset 0x{offset:08X} exceeds file size")

        cursor = offset
        count_type = self._data[cursor]
        cursor += 1
        count_width = count_type - 0x0C
        if count_width < 1 or count_width > 8:
            raise PSBError(
                f"Invalid PSB array count type 0x{count_type:02X} at 0x{offset:08X}"
            )

        count = self._read_uint_n(cursor, count_width)
        cursor += count_width

        entry_type = self._data[cursor]
        cursor += 1
        entry_width = entry_type - 0x0C
        if entry_width < 1 or entry_width > 8:
            raise PSBError(
                f"Invalid PSB array entry type 0x{entry_type:02X} at 0x{cursor - 1:08X}"
            )

        values: list[int] = []
        for _ in range(count):
            values.append(self._read_uint_n(cursor, entry_width))
            cursor += entry_width

        return PSBArray(
            offset=offset,
            end=cursor,
            count_type=count_type,
            count=count,
            entry_type=entry_type,
            entry_width=entry_width,
            values=values,
        )

    def read_name_arrays(self) -> tuple[PSBArray, PSBArray, PSBArray]:
        """Read the three arrays used by PSB's compact name b-tree."""
        if not self.header:
            raise PSBError("Header not parsed")
        if self._name_arrays is None:
            a1 = self.read_psb_array(self.header.offset_names)
            a2 = self.read_psb_array(a1.end)
            a3 = self.read_psb_array(a2.end)
            self._name_arrays = (a1, a2, a3)
        return self._name_arrays

    def get_name(self, index: int) -> str:
        """Reconstruct a property name from the name b-tree arrays."""
        str1, str2, str3 = self.read_name_arrays()
        if index < 0 or index >= len(str3.values):
            raise PSBError(f"Name index {index} outside table")

        accum: list[int] = []
        a = str3.values[index]
        b = str2.values[a]

        while True:
            c = str2.values[b]
            d = str1.values[c]
            accum.append(b - d)
            b = c
            if b == 0:
                break

        return bytes(reversed(accum)).decode("ascii", errors="replace")

    def read_names(self) -> list[str]:
        """Return all reconstructed property names."""
        if self._names is None:
            _, _, str3 = self.read_name_arrays()
            self._names = [self.get_name(i) for i in range(str3.count)]
        return self._names

    def read_string_offsets(self) -> PSBArray:
        """Read string-pool offset array."""
        if not self.header:
            raise PSBError("Header not parsed")
        if self._string_offsets is None:
            self._string_offsets = self.read_psb_array(self.header.offset_strings)
        return self._string_offsets

    def get_string(self, index: int) -> str:
        """Read a string by index through the string offset table."""
        if not self.header:
            raise PSBError("Header not parsed")
        arr = self.read_string_offsets()
        if index < 0 or index >= len(arr.values):
            raise PSBError(f"String index {index} outside table")
        start = self.header.offset_strings_data + arr.values[index]
        end = self._data.index(0, start)
        return self._data[start:end].decode("ascii", errors="replace")

    def get_section(self, start: int, end: int) -> bytes:
        """Get a section of the file by offset range.

        Args:
            start: Start offset (inclusive).
            end: End offset (exclusive).

        Returns:
            Bytes of the section.
        """
        return self._data[start:end]

    def read_varint_at(self, offset: int) -> tuple[int, int]:
        """Read a variable-length integer at the given offset.

        Args:
            offset: Byte offset in the file.

        Returns:
            Tuple of (value, bytes_consumed).
        """
        stream = BytesIO(self._data)
        stream.seek(offset)
        prefix = stream.read(1)
        if not prefix:
            raise PSBError(f"Unexpected EOF at offset 0x{offset:08X}")
        prefix_byte = prefix[0]

        size = VARINT_PREFIXES.get(prefix_byte)
        if size is None:
            raise PSBError(
                f"Unknown varint prefix 0x{prefix_byte:02X} "
                f"at offset 0x{offset:08X}"
            )

        data = stream.read(size)
        value = int.from_bytes(data, 'little')
        return value, 1 + size

    def read_string_table(self) -> list[str]:
        """Read the string table from the PSB file.

        The string table contains null-terminated ASCII strings
        (entry names like "AA", "AB", etc.).

        Returns:
            List of strings.
        """
        if not self.header:
            raise PSBError("Header not parsed")

        if self._strings is None:
            arr = self.read_string_offsets()
            self._strings = [self.get_string(i) for i in range(arr.count)]
        return self._strings

    def _parse_int_value(self, offset: int) -> tuple[Any, int]:
        """Parse PSB scalar numeric tags following krkrpsb behavior."""
        tag = self._data[offset]
        cursor = offset + 1

        if tag == 0x01:
            return None, cursor
        if tag == 0x02:
            return False, cursor
        if tag == 0x03:
            return True, cursor

        if 0x04 <= tag <= 0x0C:
            size = tag - 0x04
            if size == 0:
                return 0, cursor
            raw = self._read_uint_n(cursor, size)
            cursor += size
            sign = 1 << (size * 8 - 1)
            if raw & sign:
                raw -= 1 << (size * 8)
            return raw, cursor

        if tag == 0x1D:
            return 0.0, cursor
        if tag == 0x1E:
            return struct.unpack_from("<f", self._data, cursor)[0], cursor + 4
        if tag == 0x1F:
            return struct.unpack_from("<d", self._data, cursor)[0], cursor + 8

        raise PSBError(f"Unsupported numeric tag 0x{tag:02X} at 0x{offset:08X}")

    def _parse_string_ref(self, offset: int) -> tuple[str, int]:
        tag = self._data[offset]
        size = tag - 0x14
        index = self._read_uint_n(offset + 1, size)
        return self.get_string(index), offset + 1 + size

    def _parse_resource_ref(self, offset: int) -> tuple[dict[str, Any], int]:
        tag = self._data[offset]
        size = tag - 0x18
        index = self._read_uint_n(offset + 1, size)
        strings = self.read_string_table()
        name = strings[index] if 0 <= index < len(strings) else None
        return {"$res": index, "name": name}, offset + 1 + size

    def parse_value(self, offset: int) -> tuple[Any, int]:
        """Parse a PSB value at offset."""
        tag = self._data[offset]

        if tag in (0x01, 0x02, 0x03) or 0x04 <= tag <= 0x0C or tag in (0x1D, 0x1E, 0x1F):
            return self._parse_int_value(offset)
        if 0x0D <= tag <= 0x14:
            arr = self.read_psb_array(offset)
            return arr.values, arr.end
        if 0x15 <= tag <= 0x18:
            return self._parse_string_ref(offset)
        if 0x19 <= tag <= 0x1C:
            return self._parse_resource_ref(offset)
        if tag == 0x20:
            return self._parse_collection(offset)
        if tag == 0x21:
            return self._parse_object(offset)

        raise PSBError(f"Unknown PSB value tag 0x{tag:02X} at 0x{offset:08X}")

    def _parse_collection(self, offset: int) -> tuple[list[Any], int]:
        cursor = offset + 1
        offsets = self.read_psb_array(cursor)
        base = offsets.end
        values: list[Any] = []
        end = base
        for rel in offsets.values:
            value, value_end = self.parse_value(base + rel)
            values.append(value)
            end = max(end, value_end)
        return values, end

    def _parse_object(self, offset: int) -> tuple[dict[str, Any], int]:
        cursor = offset + 1
        names = self.read_psb_array(cursor)
        offsets = self.read_psb_array(names.end)
        base = offsets.end
        obj: dict[str, Any] = {}
        end = base
        for name_index, rel in zip(names.values, offsets.values):
            key = self.get_name(name_index)
            value, value_end = self.parse_value(base + rel)
            obj[key] = value
            end = max(end, value_end)
        return obj, end

    def read_object_tree(self) -> dict[str, Any]:
        """Parse and return the root PSB object tree."""
        if not self.header:
            raise PSBError("Header not parsed")
        value, _ = self.parse_value(self.header.offset_entries)
        if not isinstance(value, dict):
            raise PSBError(f"Root value is {type(value).__name__}, expected object")
        return value

    def _resource_names_from_root(self) -> dict[int, str]:
        """Return resource index -> object-key filename mappings when present."""
        names: dict[int, str] = {}
        try:
            root = self.read_object_tree()
        except PSBError:
            return names
        for key, value in root.items():
            if not isinstance(key, str) or not isinstance(value, dict):
                continue
            index = value.get("$res")
            if isinstance(index, int):
                names.setdefault(index, key)
        return names

    def _detect_resource_type_at(self, offset: int) -> tuple[str, str, Optional[TLGHeader]]:
        """Classify an embedded resource by magic bytes."""
        head = self._data[offset:offset + 16]
        if head.startswith(b"TLG"):
            return "tlg", ".tlg", self._parse_tlg_header_at(offset)
        if head.startswith(b"\x89PNG\r\n\x1a\n"):
            return "png", ".png", None
        if head.startswith(b"RIFF") and head[8:12] == b"WEBP":
            return "webp", ".webp", None
        if head.startswith(b"BM"):
            return "bmp", ".bmp", None
        return "unknown", ".bin", None

    def read_resource_table(self) -> list[PSBResource]:
        """Read embedded resource offsets, lengths, names, and magic types."""
        if not self.header:
            raise PSBError("Header not parsed")
        if self._chunk_offsets is None:
            self._chunk_offsets = self.read_psb_array(self.header.offset_chunk_offsets)
        if self._chunk_lengths is None:
            self._chunk_lengths = self.read_psb_array(self.header.offset_chunk_lengths)

        strings = self.read_string_table()
        root_names = self._resource_names_from_root()
        resources: list[PSBResource] = []
        for index, (rel, length) in enumerate(zip(self._chunk_offsets.values, self._chunk_lengths.values)):
            file_offset = self.header.offset_chunk_data + rel
            resource_type, extension, tlg = self._detect_resource_type_at(file_offset)
            name = strings[index] if index < len(strings) else root_names.get(index)
            if not name:
                name = f"resource_{index}{extension}"
            resources.append(
                PSBResource(
                    index=index,
                    name=name,
                    file_offset=file_offset,
                    relative_offset=rel,
                    length=length,
                    resource_type=resource_type,
                    extension=extension,
                    tlg_header=tlg,
                )
            )
        return resources

    def get_resource_by_index(self, index: int) -> PSBResource:
        """Return an embedded resource by numeric PSB resource index."""
        for res in self.read_resource_table():
            if res.index == index:
                return res
        raise PSBError(f"Resource index {index} not found")

    def get_resource_by_name(self, name: str) -> PSBResource:
        """Return an embedded resource by string-table resource name."""
        for res in self.read_resource_table():
            if res.name == name:
                return res
        raise PSBError(f"Resource name {name!r} not found")

    def read_resource_bytes(self, resource: PSBResource | int | str) -> bytes:
        """Return exact bytes for a resource chunk, using chunk length."""
        if isinstance(resource, int):
            resource = self.get_resource_by_index(resource)
        elif isinstance(resource, str):
            resource = self.get_resource_by_name(resource)
        return self._data[resource.file_offset:resource.file_offset + resource.length]

    def write_resource(self, resource: PSBResource | int | str, output_path: str | os.PathLike[str]) -> bytes:
        """Write exact bytes for a resource chunk to disk."""
        data = self.read_resource_bytes(resource)
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(data)
        return data

    def _parse_tlg_header_at(self, offset: int) -> Optional[TLGHeader]:
        """Parse a TLG header at a fixed resource offset."""
        if offset + 24 > len(self._data) or self._data[offset:offset + 3] != b"TLG":
            return None
        tlg, _ = self._parse_tlg_data(offset)
        return tlg

    def read_composition(self) -> dict[str, Any]:
        """Return canvas, layers, and layer-to-resource mapping."""
        root = self.read_object_tree()
        resource_list = self.read_resource_table()
        resources = {r.name: r for r in resource_list}
        resources_by_index = {r.index: r for r in resource_list}
        image_map: dict[int, dict[str, Any]] = {}
        for key, value in root.items():
            if not (isinstance(key, str) and isinstance(value, dict) and "$res" in value):
                continue
            stem, ext = os.path.splitext(key)
            if ext.casefold() not in (".tlg", ".png", ".webp", ".bmp"):
                continue
            if value.get("name") is None:
                value = dict(value)
                value["name"] = key
            try:
                image_map[int(stem)] = value
            except ValueError:
                continue
        layers = root.get("layers", [])
        if not isinstance(layers, list):
            layers = []

        expanded_layers: list[dict[str, Any]] = []
        for order, layer in enumerate(layers):
            if not isinstance(layer, dict):
                continue
            item = dict(layer)
            item["order"] = order
            layer_id = layer.get("layer_id")
            ref = image_map.get(layer_id) if isinstance(layer_id, int) else None
            if ref:
                item["resource_index"] = ref["$res"]
                item["resource_name"] = ref.get("name")
                res = resources_by_index.get(ref["$res"])
                if res is None:
                    res = resources.get(str(ref.get("name")))
                if res:
                    item["resource_name"] = res.name
                    item["resource_offset"] = res.file_offset
                    item["resource_length"] = res.length
                    item["resource_type"] = res.resource_type
                    if res.tlg_header:
                        item["tlg_width"] = res.tlg_header.width
                        item["tlg_height"] = res.tlg_header.height
            expanded_layers.append(item)

        layers_by_id = {
            layer["layer_id"]: layer
            for layer in expanded_layers
            if isinstance(layer.get("layer_id"), int)
        }
        diff_groups: dict[int, list[dict[str, Any]]] = {}
        for layer in expanded_layers:
            diff_id = layer.get("diff_id")
            if isinstance(diff_id, int):
                diff_groups.setdefault(diff_id, []).append(layer)

        for layer in expanded_layers:
            layer_id = layer.get("layer_id")
            if isinstance(layer_id, int) and layer_id in diff_groups:
                layer["base_for"] = [d.get("name") for d in diff_groups[layer_id]]

        return {
            "width": root.get("width"),
            "height": root.get("height"),
            "image_map": image_map,
            "resources": resources,
            "layers_by_id": layers_by_id,
            "diff_groups": diff_groups,
            "layers": expanded_layers,
        }

    def find_layer(self, layer_name: str) -> dict[str, Any]:
        """Find one layer by PSB layer name, case-insensitive fallback included."""
        comp = self.read_composition()
        layers = comp["layers"]
        exact = [layer for layer in layers if layer.get("name") == layer_name]
        if not exact:
            want = layer_name.casefold()
            exact = [
                layer for layer in layers
                if str(layer.get("name", "")).casefold() == want
            ]
        if not exact:
            available = ", ".join(str(layer.get("name")) for layer in layers)
            raise PSBError(f"Layer {layer_name!r} not found. Available: {available}")
        if len(exact) > 1:
            ids = ", ".join(str(layer.get("layer_id")) for layer in exact)
            raise PSBError(f"Layer name {layer_name!r} is ambiguous; matching layer_id: {ids}")
        return exact[0]

    def resolve_diff_layer(self, layer_name: str) -> dict[str, Any]:
        """Resolve a diff layer name to its dependent base layer and resources.

        The PSB pimg convention used by these files stores the dependent base
        layer as ``diff_id``. If the selected layer does not have ``diff_id``,
        it is returned as a standalone full layer.
        """
        comp = self.read_composition()
        layers_by_id = comp["layers_by_id"]
        diff_layer = self.find_layer(layer_name)
        diff_id = diff_layer.get("diff_id")
        base_layer = None
        if isinstance(diff_id, int):
            base_layer = layers_by_id.get(diff_id)
            if base_layer is None:
                raise PSBError(
                    f"Layer {layer_name!r} references missing base layer_id {diff_id}"
                )

        plan_layers = [base_layer, diff_layer] if base_layer else [diff_layer]
        plan_layers = [layer for layer in plan_layers if layer is not None]
        return {
            "width": comp["width"],
            "height": comp["height"],
            "diff_name": diff_layer.get("name"),
            "base_layer": base_layer,
            "diff_layer": diff_layer,
            "layers": plan_layers,
        }

    def extract_diff_tlgs(
        self,
        layer_name: str,
        output_dir: str | os.PathLike[str],
        include_base: bool = True,
    ) -> dict[str, Any]:
        """Extract TLG files needed to compose a selected diff layer."""
        plan = self.resolve_diff_layer(layer_name)
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        exported: list[dict[str, Any]] = []
        for role, layer in (("base", plan.get("base_layer")), ("diff", plan.get("diff_layer"))):
            if layer is None or (role == "base" and not include_base):
                continue
            res_index = layer.get("resource_index")
            if not isinstance(res_index, int):
                raise PSBError(f"Layer {layer.get('name')!r} has no resource_index")
            res = self.get_resource_by_index(res_index)
            stem = self.layer_export_stem(role, layer)
            path = out_dir / f"{stem}{res.extension}"
            self.write_resource(res, path)
            expected_png = out_dir / f"{stem}.png"
            if res.resource_type == "png":
                expected_png = path
            item = {
                "role": role,
                "path": str(path),
                "layer": layer,
                "resource": res.to_dict(),
                "source_format": res.resource_type,
                "expected_png": str(expected_png),
            }
            exported.append(item)

        manifest = {
            "psb": self.filepath,
            "diff_name": layer_name,
            "width": plan["width"],
            "height": plan["height"],
            "exports": exported,
        }
        (out_dir / f"{layer_name}_manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return manifest

    def extract_all_tlgs(self, output_dir: str | os.PathLike[str]) -> dict[str, Any]:
        """Extract every embedded image resource and write a full manifest."""
        comp = self.read_composition()
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        layers_by_resource: dict[int, list[dict[str, Any]]] = {}
        for layer in comp["layers"]:
            res_index = layer.get("resource_index")
            if isinstance(res_index, int):
                layers_by_resource.setdefault(res_index, []).append(layer)

        exported: list[dict[str, Any]] = []
        skipped: list[dict[str, Any]] = []
        for res in self.read_resource_table():
            if res.resource_type == "unknown":
                skipped.append(res.to_dict())
                continue
            stem = self.resource_export_stem(res)
            path = out_dir / f"{stem}{res.extension}"
            self.write_resource(res, path)
            expected_png = out_dir / f"{stem}.png"
            if res.resource_type == "png":
                expected_png = path
            exported.append({
                "path": str(path),
                "expected_png": str(expected_png),
                "resource": res.to_dict(),
                "source_format": res.resource_type,
                "needs_conversion": res.resource_type == "tlg",
                "layers": layers_by_resource.get(res.index, []),
            })

        diffs: dict[str, dict[str, Any]] = {}
        for layer in comp["layers"]:
            layer_name = layer.get("name")
            if not isinstance(layer_name, str):
                continue
            diff_id = layer.get("diff_id")
            base_layer = None
            if isinstance(diff_id, int):
                base_layer = comp["layers_by_id"].get(diff_id)
            plan_layers = [base_layer, layer] if base_layer else [layer]
            diffs[layer_name] = {
                "diff_name": layer_name,
                "base_layer": base_layer,
                "diff_layer": layer,
                "layers": [item for item in plan_layers if item is not None],
            }

        manifest = {
            "psb": self.filepath,
            "mode": "all",
            "width": comp["width"],
            "height": comp["height"],
            "resource_count": len(exported),
            "resource_types": self.resource_type_counts(),
            "exports": exported,
            "diffs": diffs,
            "skipped": skipped,
        }
        manifest_path = out_dir / "all_tlg_manifest.json"
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return manifest

    @staticmethod
    def layer_export_stem(role: str, layer: dict[str, Any]) -> str:
        """Stable filename stem for a layer's exported TLG/converted PNG."""
        return (
            f"{role}_{layer.get('name')}_id{layer.get('layer_id')}"
            f"_res{int(layer.get('resource_index', -1)):02d}_{layer.get('resource_name')}"
        )

    @staticmethod
    def resource_export_stem(resource: PSBResource) -> str:
        """Stable filename stem for a resource-table export."""
        name = Path(resource.name).name
        suffix = Path(name).suffix
        if suffix.casefold() == resource.extension.casefold():
            name = name[:-len(suffix)]
        return f"res{resource.index:02d}_{name}"

    def resource_type_counts(self) -> dict[str, int]:
        """Count embedded resource types detected by magic bytes."""
        counts: dict[str, int] = {}
        for res in self.read_resource_table():
            counts[res.resource_type] = counts.get(res.resource_type, 0) + 1
        return counts

    def extract_tlg(self) -> tuple[Optional[TLGHeader], bytes]:
        """Extract TLG image data from the PSB file.

        Uses the PSB chunk table and per-resource magic detection. This avoids
        false positives from arbitrary ``TLG`` byte sequences inside PNG data.

        Returns:
            Tuple of (TLGHeader or None, raw_tlg_bytes).
        """
        if not self.header:
            raise PSBError("Header not parsed")

        for res in self.read_resource_table():
            if res.resource_type == "tlg" and res.tlg_header is not None:
                return res.tlg_header, self.read_resource_bytes(res)

        return None, b""

    def _parse_tlg_data(self, offset: int) -> tuple[Optional[TLGHeader], bytes]:
        """Parse TLG header at the given offset.

        TLG header structure:
          - Magic: "TLG5.0\\0" or "TLG0.0\\0" (7 bytes with null)
          - Raw format: "raw" (3 bytes, may or may not have null terminator)
          - Extra flag byte: varies (1 byte, 0x00 or 0x1A etc.)
          - Color type: 1 byte (1=gray, 2=gray+alpha, 3=RGB, 4=RGBA)
          - Width: 4 bytes LE
          - Height: 4 bytes LE
          - Block size: 4 bytes LE
        Total header: 24 bytes before image data.

        Args:
            offset: Offset of the TLG magic bytes in the file.

        Returns:
            Tuple of (TLGHeader, tlg_data_bytes).
        """
        data = self._data
        if offset + 7 > len(data):
            return None, data[offset:]

        # Read magic (7 bytes: "TLG5.0\0")
        magic_bytes = data[offset:offset + 7]
        magic_str = magic_bytes.rstrip(b'\0').decode('ascii', errors='replace').rstrip('\0')

        if not magic_str.startswith('TLG'):
            return None, data[offset:]

        # Read format string: starts at offset+7, scan for alphanumeric chars.
        # Format string is typically "raw", "sds", "zlib" — 3 ASCII chars.
        # The byte immediately after the format chars is a format flag:
        #   0x00 = standard (looks like a null terminator from C-string view)
        #   0x1A = some variant
        # After the flag byte: colors(1), width(4), height(4), block_size(4).
        fmt_start = offset + 7
        fmt_end = fmt_start
        while fmt_end < len(data):
            b = data[fmt_end]
            if (0x30 <= b <= 0x39) or (0x41 <= b <= 0x5A) or (0x61 <= b <= 0x7A) or b == 0x5F:
                fmt_end += 1
            else:
                break

        raw_format = data[fmt_start:fmt_end].decode('ascii', errors='replace')

        # Need at least 14 more bytes after format: flag(1) + colors(1) +
        # width(4) + height(4) + block_size(4)
        if fmt_end + 14 > len(data):
            tlg_raw = data[offset:]
            tlg = TLGHeader(magic=magic_str, raw_format=raw_format,
                           colors=0, width=0, height=0, block_size=0)
            return tlg, tlg_raw

        # The byte at fmt_end is the format flag (0x00 or 0x1A, etc.)
        format_flag = data[fmt_end]
        colors = data[fmt_end + 1]
        width = struct.unpack_from('<I', data, fmt_end + 2)[0]
        height = struct.unpack_from('<I', data, fmt_end + 6)[0]
        block_size = struct.unpack_from('<I', data, fmt_end + 10)[0]

        tlg_header_size = (fmt_end + 14) - offset  # 24 bytes (7+3+1+1+4+4+4)

        tlg = TLGHeader(
            magic=magic_str,
            raw_format=raw_format,
            colors=colors,
            width=width,
            height=height,
            block_size=block_size,
        )

        # Return full TLG data (header + raw image data)
        tlg_raw = data[offset:]

        return tlg, tlg_raw

    def get_info(self) -> dict[str, Any]:
        """Get summary information about the PSB file.

        Returns:
            Dictionary with file summary information.
        """
        if not self.header:
            return {"error": "Not parsed"}

        h = self.header
        info = {
            "file": self.filepath,
            "size": len(self._data),
            "version": h.version,
            "encrypt": h.encrypt,
            "offset_names": f"0x{h.offset_names:08X} ({h.offset_names})",
            "offset_entries": f"0x{h.offset_entries:08X} ({h.offset_entries})",
            "offset_strings": f"0x{h.offset_strings:08X} ({h.offset_strings})",
            "offset_strings_data": f"0x{h.offset_strings_data:08X} ({h.offset_strings_data})",
            "offset_chunk_offsets": f"0x{h.offset_chunk_offsets:08X} ({h.offset_chunk_offsets})",
            "offset_chunk_lengths": f"0x{h.offset_chunk_lengths:08X} ({h.offset_chunk_lengths})",
            "offset_chunk_data": f"0x{h.offset_chunk_data:08X} ({h.offset_chunk_data})",
        }

        # Try to read strings
        try:
            strings = self.read_string_table()
            info["string_table_count"] = len(strings)
            info["string_table_sample"] = strings[:20]
        except Exception:
            info["string_table_count"] = "N/A"

        # Try to read TLG
        try:
            tlg_header, tlg_data = self.extract_tlg()
            if tlg_header:
                info["tlg_magic"] = tlg_header.magic
                info["tlg_format"] = tlg_header.raw_format
                info["tlg_colors"] = tlg_header.colors
                info["tlg_width"] = tlg_header.width
                info["tlg_height"] = tlg_header.height
                info["tlg_block_size"] = tlg_header.block_size
                info["tlg_data_size"] = len(tlg_data)
        except Exception:
            pass

        return info

    def dump_structure(self, max_depth: int = 2) -> str:
        """Dump the PSB file structure as a human-readable string.

        Args:
            max_depth: Maximum recursion depth for nested structures.

        Returns:
            Multi-line string describing the file structure.
        """
        if not self.header:
            return "PSB file not parsed."

        h = self.header
        lines = [
            "=" * 70,
            f"PSB File: {self.filepath}",
            f"File Size: {len(self._data):,} bytes",
            "=" * 70,
            "",
            "--- HEADER ---",
            f"  Magic:         {h.magic.hex(' ')} ({h.magic})",
            f"  Version:       {h.version}",
            f"  Encrypt:       {h.encrypt}",
            f"  Offset Encrypt:0x{h.offset_encrypt:08X} ({h.offset_encrypt})",
            f"  Names Offset:  0x{h.offset_names:08X} ({h.offset_names})",
            f"  Entries Off:   0x{h.offset_entries:08X} ({h.offset_entries})",
            f"  Strings Off:   0x{h.offset_strings:08X} ({h.offset_strings})",
            f"  Strings Data:  0x{h.offset_strings_data:08X} ({h.offset_strings_data})",
            f"  Chunk Offsets: 0x{h.offset_chunk_offsets:08X} ({h.offset_chunk_offsets})",
            f"  Chunk Lengths: 0x{h.offset_chunk_lengths:08X} ({h.offset_chunk_lengths})",
            f"  Chunk Data:    0x{h.offset_chunk_data:08X} ({h.offset_chunk_data})",
            "",
        ]

        lines.append("--- NAME TABLE ---")
        try:
            name_arrays = self.read_name_arrays()
            names = self.read_names()
            lines.append(
                "  Arrays: "
                + ", ".join(f"count={arr.count} width={arr.entry_width}" for arr in name_arrays)
            )
            lines.append(f"  Names: {names}")
        except Exception as e:
            lines.append(f"  Error reading names: {e}")

        # String table
        lines.append(f"\n--- STRING TABLE (offset 0x{h.offset_strings:08X}) ---")
        try:
            strings = self.read_string_table()
            lines.append(f"  Count: {len(strings)}")
            lines.append(f"  Sample: {strings[:30]}")
        except Exception as e:
            lines.append(f"  Error reading strings: {e}")

        lines.append(f"\n--- ENTRIES SECTION (offset 0x{h.offset_entries:08X}) ---")
        lines.append(self._dump_hex_section(h.offset_entries, min(128, h.offset_strings - h.offset_entries)))

        lines.append(f"\n--- CHUNK TABLES ---")
        try:
            resources = self.read_resource_table()
            lines.append(f"  Resource count: {len(resources)}")
            for res in resources[:30]:
                dim = ""
                if res.tlg_header:
                    dim = f" {res.tlg_header.width}x{res.tlg_header.height}"
                lines.append(
                    f"  {res.index:02d} {res.name:<3s} off=0x{res.file_offset:08X} "
                    f"len=0x{res.length:X}{dim}"
                )
        except Exception as e:
            lines.append(f"  Error reading resources: {e}")

        lines.append(f"\n--- RESOURCE DATA (offset 0x{h.resources_offset:08X}) ---")
        try:
            resources = self.read_resource_table()
            counts = self.resource_type_counts()
            if counts:
                lines.append(
                    "  Resource Types: "
                    + ", ".join(f"{name}={count}" for name, count in sorted(counts.items()))
                )
            if resources:
                first = resources[0]
                head = self.read_resource_bytes(first)[:8]
                lines.append(
                    f"  First Resource: {first.resource_type} "
                    f"{first.name} len={first.length:,} magic={head.hex(' ')}"
                )
            tlg_header, tlg_data = self.extract_tlg()
            if tlg_header:
                lines.append(f"  TLG Type:    {tlg_header.magic}")
                lines.append(f"  Raw Format:  {tlg_header.raw_format}")
                lines.append(f"  Colors:      {tlg_header.colors}")
                lines.append(f"  Dimensions:  {tlg_header.width} x {tlg_header.height}")
                lines.append(f"  Block Size:  {tlg_header.block_size}")
                lines.append(f"  Data Size:   {len(tlg_data):,} bytes")
            else:
                lines.append("  TLG:          none")
        except Exception as e:
            lines.append(f"  Error reading resource data: {e}")

        return "\n".join(lines)

    def _dump_hex_section(self, offset: int, size: int) -> str:
        """Create a hex dump of a section.

        Args:
            offset: Start offset.
            size: Number of bytes to dump.

        Returns:
            Hex dump string.
        """
        if offset >= len(self._data):
            return f"  [offset 0x{offset:08X} is beyond file end]"

        actual_size = min(size, len(self._data) - offset)
        data = self._data[offset:offset + actual_size]

        lines = [f"  Offset 0x{offset:08X}, {actual_size} bytes:"]
        for i in range(0, actual_size, 16):
            chunk = data[i:i + 16]
            hex_part = ' '.join(f'{b:02X}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            lines.append(f"  {offset + i:08X}: {hex_part:<48s} {ascii_part}")

        if actual_size < size:
            lines.append(f"  ... (truncated, {size - actual_size} more bytes)")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# TLG Data Extraction
# ---------------------------------------------------------------------------

def extract_tlg_from_psb(psb_path: str, output_path: Optional[str] = None) -> bytes:
    """Extract TLG image data from a PSB file.

    Args:
        psb_path: Path to the PSB file.
        output_path: Optional output path for the TLG data.
                     If not provided, derives from PSB path.

    Returns:
        Raw TLG data bytes.
    """
    reader = PSBReader(psb_path)
    tlg_header, tlg_data = reader.extract_tlg()

    if not tlg_data:
        raise PSBError(f"No TLG data found in {psb_path}")

    if output_path is None:
        output_path = psb_path.replace('.bin', '.tlg')

    with open(output_path, 'wb') as f:
        f.write(tlg_data)

    print(f"Extracted TLG data: {len(tlg_data):,} bytes -> {output_path}")
    if tlg_header:
        print(f"  TLG: {tlg_header.magic}, {tlg_header.width}x{tlg_header.height}, "
              f"colors={tlg_header.colors}")

    return tlg_data


IMAGE_EXTENSIONS = (".png", ".webp", ".tif", ".tiff", ".bmp")


def default_tlg2png_path() -> Path:
    """Return the bundled tlg2png.exe path."""
    return Path(__file__).resolve().parent / "tlg2png" / "tlg2png.exe"


def convert_tlg_to_png(
    tlg_path: str | os.PathLike[str],
    png_path: str | os.PathLike[str],
    tlg2png_path: str | os.PathLike[str] | None = None,
) -> None:
    """Convert one TLG file to PNG using tools/tlg2png/tlg2png.exe."""
    exe = Path(tlg2png_path) if tlg2png_path else default_tlg2png_path()
    if not exe.is_file():
        raise PSBError(f"tlg2png executable not found: {exe}")

    src = Path(tlg_path).resolve()
    dst = Path(png_path).resolve()
    dst.parent.mkdir(parents=True, exist_ok=True)

    proc = subprocess.run(
        [str(exe), str(src), str(dst)],
        cwd=str(exe.parent),
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        if detail:
            detail = f": {detail}"
        raise PSBError(f"tlg2png failed for {src}{detail}")
    if not dst.is_file():
        raise PSBError(f"tlg2png did not create output file: {dst}")


def convert_manifest_exports_to_png(
    manifest: dict[str, Any],
    tlg2png_path: str | os.PathLike[str] | None = None,
) -> list[dict[str, str]]:
    """Convert exported TLG paths listed in a manifest; keep PNG exports as-is."""
    converted: list[dict[str, str]] = []
    for item in manifest.get("exports", []):
        if not isinstance(item, dict):
            continue
        src = item.get("path")
        dst = item.get("expected_png")
        if not isinstance(src, str) or not isinstance(dst, str):
            continue
        source_format = item.get("source_format")
        if source_format == "png":
            converted.append({"png": dst, "source": src})
            continue
        if source_format == "tlg" or Path(src).suffix.casefold() == ".tlg":
            convert_tlg_to_png(src, dst, tlg2png_path)
            converted.append({"tlg": src, "png": dst})
    return converted


def layer_tlg_png_paths(
    work_dir: str | os.PathLike[str],
    role: str,
    layer: dict[str, Any],
) -> tuple[Path, Path]:
    """Return stable temporary TLG/PNG paths for a composition layer."""
    stem = PSBReader.layer_export_stem(role, layer)
    directory = Path(work_dir)
    return directory / f"{stem}.tlg", directory / f"{stem}.png"


def find_layer_image(
    image_dir: str | os.PathLike[str],
    role: str,
    layer: dict[str, Any],
) -> Path:
    """Find a decoded image file for a layer.

    Resource extraction writes TLG files with the same stable stem this
    function checks first. After converting those TLG files to PNG, callers
    can find them without extra mapping arguments. It also accepts
    simple resource-name files such as ``EA.png``.
    """
    directory = Path(image_dir)
    res_name = str(layer.get("resource_name", ""))
    res_index = layer.get("resource_index")
    layer_name = str(layer.get("name", ""))

    stems = [
        PSBReader.layer_export_stem(role, layer),
        res_name,
        layer_name,
    ]
    if isinstance(res_index, int):
        stems.extend([
            f"res{res_index:02d}_{res_name}",
            f"res_{res_index:02d}_{res_name}",
            f"{res_index:02d}_{res_name}",
        ])

    candidates: list[Path] = []
    for stem in stems:
        if not stem or stem == "None":
            continue
        for ext in IMAGE_EXTENSIONS:
            candidates.append(directory / f"{stem}{ext}")
            candidates.append(directory / f"{stem}.tlg{ext}")

    for candidate in candidates:
        if candidate.is_file():
            return candidate

    checked = ", ".join(path.name for path in candidates[:12])
    if len(candidates) > 12:
        checked += ", ..."
    raise PSBError(
        f"Decoded image for layer {layer_name!r} resource {res_name!r} not found "
        f"in {directory}. Checked: {checked}"
    )


def load_json_manifest(manifest_path: str | os.PathLike[str]) -> dict[str, Any]:
    """Load a JSON manifest produced by this parser."""
    path = Path(manifest_path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise PSBError(f"Cannot read manifest {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise PSBError(f"Invalid JSON manifest {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise PSBError(f"Manifest {path} is not a JSON object")
    return data


def find_manifest_diff(
    diffs: dict[str, Any],
    layer_name: str,
) -> dict[str, Any]:
    """Find one diff plan in an all-resource manifest."""
    plan = diffs.get(layer_name)
    if isinstance(plan, dict):
        return plan
    folded = layer_name.casefold()
    matches = [
        value for key, value in diffs.items()
        if key.casefold() == folded and isinstance(value, dict)
    ]
    if not matches:
        available = ", ".join(sorted(diffs.keys()))
        raise PSBError(f"Diff layer {layer_name!r} not found in manifest. Available: {available}")
    if len(matches) > 1:
        raise PSBError(f"Diff layer {layer_name!r} is ambiguous in manifest")
    return matches[0]


def resolve_manifest_diff_plan(
    manifest: dict[str, Any],
    layer_name: Optional[str] = None,
) -> dict[str, Any]:
    """Resolve a manifest into the base/diff layer plan needed for composition."""
    if manifest.get("mode") == "all":
        diffs = manifest.get("diffs")
        if not isinstance(diffs, dict):
            raise PSBError("All-resource manifest does not contain a 'diffs' index")
        if layer_name is None:
            raise PSBError("All-resource manifest requires --layer to choose a diff")
        plan = find_manifest_diff(diffs, layer_name)
        return {
            "width": manifest.get("width"),
            "height": manifest.get("height"),
            "diff_name": plan.get("diff_name", layer_name),
            "base_layer": plan.get("base_layer"),
            "diff_layer": plan.get("diff_layer"),
            "layers": plan.get("layers", []),
        }

    diff_name = manifest.get("diff_name")
    if layer_name is not None and diff_name is not None:
        if str(diff_name).casefold() != layer_name.casefold():
            raise PSBError(
                f"Manifest is for diff {diff_name!r}, not requested {layer_name!r}"
            )

    role_layers: dict[str, dict[str, Any]] = {}
    for item in manifest.get("exports", []):
        if not isinstance(item, dict):
            continue
        role = item.get("role")
        layer = item.get("layer")
        if isinstance(role, str) and isinstance(layer, dict):
            role_layers[role] = layer

    if "diff" not in role_layers:
        raise PSBError("Diff-specific manifest does not contain a diff layer export")

    plan_layers = []
    if "base" in role_layers:
        plan_layers.append(role_layers["base"])
    plan_layers.append(role_layers["diff"])

    return {
        "width": manifest.get("width"),
        "height": manifest.get("height"),
        "diff_name": diff_name or role_layers["diff"].get("name"),
        "base_layer": role_layers.get("base"),
        "diff_layer": role_layers["diff"],
        "layers": plan_layers,
    }


def _manifest_file_path(
    value: str | os.PathLike[str],
    manifest_dir: Path,
) -> Path:
    """Resolve a manifest-listed path against the extraction directory."""
    raw = Path(value)
    if raw.is_absolute() and raw.exists():
        return raw
    candidate = manifest_dir / raw.name
    if candidate.exists():
        return candidate
    return raw if raw.is_absolute() else manifest_dir / raw


def _manifest_exports_by_resource(
    manifest: dict[str, Any],
    manifest_dir: Path,
) -> dict[int, dict[str, Any]]:
    """Build resource_index -> export item map with resolved file paths."""
    exports: dict[int, dict[str, Any]] = {}
    for item in manifest.get("exports", []):
        if not isinstance(item, dict):
            continue
        resource = item.get("resource")
        if not isinstance(resource, dict):
            continue
        index = resource.get("index")
        if not isinstance(index, int):
            continue
        resolved = dict(item)
        path = item.get("path")
        expected_png = item.get("expected_png")
        if isinstance(path, str):
            resolved["path"] = str(_manifest_file_path(path, manifest_dir))
        if isinstance(expected_png, str):
            resolved["expected_png"] = str(_manifest_file_path(expected_png, manifest_dir))
        exports[index] = resolved
    return exports


def ensure_export_png(
    export: dict[str, Any],
    tlg2png_path: str | os.PathLike[str] | None = None,
) -> Path:
    """Return an extracted PNG path, converting TLG resources when needed."""
    png_raw = export.get("expected_png")
    source_raw = export.get("path")
    if not isinstance(png_raw, str) or not isinstance(source_raw, str):
        raise PSBError("Manifest export is missing path/expected_png")
    png_path = Path(png_raw)
    source_path = Path(source_raw)
    source_format = export.get("source_format")
    if source_format == "png":
        if not png_path.is_file():
            raise PSBError(f"Missing extracted PNG resource: {png_path}")
        return png_path
    if not png_path.is_file():
        if not source_path.is_file():
            resource = export.get("resource", {})
            raise PSBError(
                f"Missing extracted {source_format or 'resource'} for resource "
                f"{resource.get('index')}:{resource.get('name')}: {source_path}"
            )
        if source_format != "tlg" and source_path.suffix.casefold() != ".tlg":
            raise PSBError(f"Cannot convert resource type {source_format!r} to PNG: {source_path}")
        convert_tlg_to_png(source_path, png_path, tlg2png_path)
    return png_path


def composite_plan_from_exports(
    plan: dict[str, Any],
    exports_by_resource: dict[int, dict[str, Any]],
    output_path: str | os.PathLike[str],
    tlg2png_path: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Composite one diff plan using already extracted resources."""
    try:
        from PIL import Image
    except ImportError as exc:
        raise PSBError("Pillow is required for composition: pip install pillow") from exc

    width = int(plan["width"])
    height = int(plan["height"])
    canvas = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    used: list[dict[str, Any]] = []

    for role, layer in (
        ("base", plan.get("base_layer")),
        ("diff", plan.get("diff_layer")),
    ):
        if layer is None:
            continue
        res_index = layer.get("resource_index")
        if not isinstance(res_index, int):
            raise PSBError(f"Layer {layer.get('name')!r} has no resource_index")
        export = exports_by_resource.get(res_index)
        if export is None:
            raise PSBError(f"Manifest has no export for resource index {res_index}")
        png_path = ensure_export_png(export, tlg2png_path)
        image = Image.open(png_path).convert("RGBA")

        opacity = int(layer.get("opacity", 255))
        opacity = max(0, min(255, opacity))
        if opacity != 255:
            alpha = image.getchannel("A").point(lambda a: a * opacity // 255)
            image.putalpha(alpha)

        left = int(layer.get("left", 0))
        top = int(layer.get("top", 0))
        overlay = Image.new("RGBA", canvas.size, (0, 0, 0, 0))
        overlay.alpha_composite(image, (left, top))
        canvas.alpha_composite(overlay)
        used.append({
            "role": role,
            "layer_name": layer.get("name"),
            "layer_id": layer.get("layer_id"),
            "resource_index": res_index,
            "resource_name": layer.get("resource_name"),
            "left": left,
            "top": top,
            "opacity": opacity,
            "png": str(png_path),
        })

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    canvas.save(out)
    return {
        "diff_name": plan.get("diff_name"),
        "output": str(out),
        "width": width,
        "height": height,
        "layers": used,
    }


def export_flat_images_from_manifest(
    manifest: dict[str, Any],
    output_dir: str | os.PathLike[str],
    manifest_dir: Path,
    tlg2png_path: str | os.PathLike[str] | None = None,
) -> list[dict[str, Any]]:
    """Write one PNG output per exported resource when no layer plan exists."""
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []
    for item in manifest.get("exports", []):
        if not isinstance(item, dict):
            continue
        resolved = dict(item)
        path = item.get("path")
        expected_png = item.get("expected_png")
        if isinstance(path, str):
            resolved["path"] = str(_manifest_file_path(path, manifest_dir))
        if isinstance(expected_png, str):
            resolved["expected_png"] = str(_manifest_file_path(expected_png, manifest_dir))

        png_path = ensure_export_png(resolved, tlg2png_path)
        resource = item.get("resource", {})
        name = str(resource.get("name") or png_path.name)
        filename = Path(name).name
        if Path(filename).suffix.casefold() != ".png":
            filename = f"{Path(filename).stem}.png"
        output_path = out_dir / filename
        if png_path.resolve() != output_path.resolve():
            shutil.copy2(png_path, output_path)
        results.append({
            "diff_name": Path(filename).stem,
            "output": str(output_path),
            "resource_index": resource.get("index"),
            "resource_name": resource.get("name"),
            "source_format": item.get("source_format"),
        })
    return results


def composite_all_from_extracted(
    extract_dir: str | os.PathLike[str],
    output_dir: str | os.PathLike[str],
    manifest_path: str | os.PathLike[str] | None = None,
    tlg2png_path: str | os.PathLike[str] | None = None,
) -> list[dict[str, Any]]:
    """Composite every diff from an extract-all directory and manifest."""
    base_dir = Path(extract_dir)
    manifest_file = Path(manifest_path) if manifest_path else base_dir / "all_tlg_manifest.json"
    manifest = load_json_manifest(manifest_file)
    if manifest.get("mode") != "all":
        raise PSBError(f"Expected an all-resource manifest: {manifest_file}")
    diffs = manifest.get("diffs")
    if not isinstance(diffs, dict):
        raise PSBError(f"Manifest does not contain a diffs index: {manifest_file}")

    manifest_dir = manifest_file.parent
    if not diffs:
        return export_flat_images_from_manifest(
            manifest,
            output_dir,
            manifest_dir,
            tlg2png_path=tlg2png_path,
        )

    exports_by_resource = _manifest_exports_by_resource(manifest, manifest_dir)
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    width = manifest.get("width")
    height = manifest.get("height")
    results: list[dict[str, Any]] = []
    for name, diff_plan in diffs.items():
        if not isinstance(name, str) or not isinstance(diff_plan, dict):
            continue
        plan = {
            "width": width,
            "height": height,
            "diff_name": diff_plan.get("diff_name", name),
            "base_layer": diff_plan.get("base_layer"),
            "diff_layer": diff_plan.get("diff_layer"),
            "layers": diff_plan.get("layers", []),
        }
        result = composite_plan_from_exports(
            plan,
            exports_by_resource,
            out_dir / f"{name}.png",
            tlg2png_path=tlg2png_path,
        )
        results.append(result)
    return results


def composite_all_via_extract(
    psb_path: str | os.PathLike[str],
    output_dir: str | os.PathLike[str],
    work_dir: str | os.PathLike[str] | None = None,
    tlg2png_path: str | os.PathLike[str] | None = None,
    keep_temp: bool = False,
) -> tuple[list[dict[str, Any]], Path]:
    """Extract all resources to a temporary directory, compose, then clean up."""
    temp_parent = Path(work_dir) if work_dir else Path.cwd() / "Temp"
    temp_parent.mkdir(parents=True, exist_ok=True)
    extract_dir = temp_parent / f"psb_extract_{os.getpid()}_{uuid.uuid4().hex[:8]}"
    extract_dir.mkdir(parents=True, exist_ok=False)

    try:
        reader = PSBReader(str(psb_path))
        reader.extract_all_tlgs(extract_dir)
        results = composite_all_from_extracted(
            extract_dir,
            output_dir,
            tlg2png_path=tlg2png_path,
        )
        return results, extract_dir
    finally:
        if not keep_temp:
            shutil.rmtree(extract_dir, ignore_errors=True)


def composite_diff_from_manifest(
    manifest_path: str | os.PathLike[str],
    layer_name: Optional[str],
    image_dir: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
) -> dict[str, Any]:
    """Composite the final CG using only a manifest and decoded layer images."""
    try:
        from PIL import Image
    except ImportError as exc:
        raise PSBError("Pillow is required for composition: pip install pillow") from exc

    manifest = load_json_manifest(manifest_path)
    plan = resolve_manifest_diff_plan(manifest, layer_name)
    width = int(plan["width"])
    height = int(plan["height"])
    canvas = Image.new("RGBA", (width, height), (0, 0, 0, 0))

    used: list[dict[str, Any]] = []
    for role, layer in (
        ("base", plan.get("base_layer")),
        ("diff", plan.get("diff_layer")),
    ):
        if layer is None:
            continue
        path = find_layer_image(image_dir, role, layer)
        image = Image.open(path).convert("RGBA")

        opacity = int(layer.get("opacity", 255))
        opacity = max(0, min(255, opacity))
        if opacity != 255:
            alpha = image.getchannel("A").point(lambda a: a * opacity // 255)
            image.putalpha(alpha)

        left = int(layer.get("left", 0))
        top = int(layer.get("top", 0))
        overlay = Image.new("RGBA", canvas.size, (0, 0, 0, 0))
        overlay.alpha_composite(image, (left, top))
        canvas.alpha_composite(overlay)
        used.append({
            "role": role,
            "layer_name": layer.get("name"),
            "layer_id": layer.get("layer_id"),
            "resource_index": layer.get("resource_index"),
            "resource_name": layer.get("resource_name"),
            "left": left,
            "top": top,
            "opacity": opacity,
            "image": str(path),
        })

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    canvas.save(out)
    return {
        "manifest": str(manifest_path),
        "diff_name": plan.get("diff_name"),
        "output": str(out),
        "width": width,
        "height": height,
        "layers": used,
    }


def composite_diff_direct(
    psb_path: str,
    layer_name: str,
    output_path: str | os.PathLike[str],
    work_dir: str | os.PathLike[str] | None = None,
    tlg2png_path: str | os.PathLike[str] | None = None,
    keep_temp: bool = False,
) -> dict[str, Any]:
    """Resolve, convert, and composite one diff directly from a PSB file."""
    try:
        from PIL import Image
    except ImportError as exc:
        raise PSBError("Pillow is required for composition: pip install pillow") from exc

    reader = PSBReader(psb_path)
    plan = reader.resolve_diff_layer(layer_name)
    width = int(plan["width"])
    height = int(plan["height"])

    auto_work_dir = False
    if work_dir is None:
        temp_base = Path.cwd() / "Temp"
        temp_base.mkdir(parents=True, exist_ok=True)
        actual_work_dir = temp_base / f"psb_compose_{os.getpid()}_{uuid.uuid4().hex[:8]}"
        actual_work_dir.mkdir(parents=True, exist_ok=False)
        auto_work_dir = True
    else:
        actual_work_dir = Path(work_dir)
        actual_work_dir.mkdir(parents=True, exist_ok=True)

    try:
        canvas = Image.new("RGBA", (width, height), (0, 0, 0, 0))
        used: list[dict[str, Any]] = []

        for role, layer in (
            ("base", plan.get("base_layer")),
            ("diff", plan.get("diff_layer")),
        ):
            if layer is None:
                continue
            res_index = layer.get("resource_index")
            if not isinstance(res_index, int):
                raise PSBError(f"Layer {layer.get('name')!r} has no resource_index")
            res = reader.get_resource_by_index(res_index)
            if res.resource_type not in ("tlg", "png"):
                raise PSBError(
                    f"Layer {layer.get('name')!r} resource {res.index}:{res.name} "
                    f"is unsupported type {res.resource_type!r}"
                )

            tlg_path, png_path = layer_tlg_png_paths(actual_work_dir, role, layer)
            if res.resource_type == "tlg":
                reader.write_resource(res, tlg_path)
                convert_tlg_to_png(tlg_path, png_path, tlg2png_path)
                source_path = tlg_path
            else:
                reader.write_resource(res, png_path)
                source_path = png_path

            image = Image.open(png_path).convert("RGBA")
            opacity = int(layer.get("opacity", 255))
            opacity = max(0, min(255, opacity))
            if opacity != 255:
                alpha = image.getchannel("A").point(lambda a: a * opacity // 255)
                image.putalpha(alpha)

            left = int(layer.get("left", 0))
            top = int(layer.get("top", 0))
            overlay = Image.new("RGBA", canvas.size, (0, 0, 0, 0))
            overlay.alpha_composite(image, (left, top))
            canvas.alpha_composite(overlay)
            used.append({
                "role": role,
                "layer_name": layer.get("name"),
                "layer_id": layer.get("layer_id"),
                "resource_index": layer.get("resource_index"),
                "resource_name": layer.get("resource_name"),
                "left": left,
                "top": top,
                "opacity": opacity,
                "source": str(source_path),
                "source_format": res.resource_type,
                "png": str(png_path),
            })

        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        canvas.save(out)
        return {
            "psb": psb_path,
            "diff_name": plan.get("diff_name"),
            "output": str(out),
            "width": width,
            "height": height,
            "work_dir": str(actual_work_dir),
            "layers": used,
        }
    finally:
        if auto_work_dir and not keep_temp:
            shutil.rmtree(actual_work_dir, ignore_errors=True)


def composite_all_diffs_direct(
    psb_path: str,
    output_dir: str | os.PathLike[str],
    work_dir: str | os.PathLike[str] | None = None,
    tlg2png_path: str | os.PathLike[str] | None = None,
    keep_temp: bool = False,
) -> list[dict[str, Any]]:
    """Composite every named layer/diff from a PSB file."""
    reader = PSBReader(psb_path)
    comp = reader.read_composition()
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    results: list[dict[str, Any]] = []
    for layer in comp["layers"]:
        name = layer.get("name")
        if not isinstance(name, str):
            continue
        layer_work_dir = None
        if work_dir is not None:
            layer_work_dir = Path(work_dir) / name
        result = composite_diff_direct(
            psb_path,
            name,
            out_dir / f"{name}.png",
            work_dir=layer_work_dir,
            tlg2png_path=tlg2png_path,
            keep_temp=keep_temp,
        )
        results.append(result)
    return results


def composite_diff_image(
    psb_path: str,
    layer_name: str,
    image_dir: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
) -> dict[str, Any]:
    """Composite the final CG for a selected diff layer from decoded images.

    The PSB stores TLG resources, but this function expects those resources to
    have already been decoded to normal images. Export the needed TLG files,
    convert them to PNG with a TLG-capable tool, then call this function.
    """
    try:
        from PIL import Image
    except ImportError as exc:
        raise PSBError("Pillow is required for composition: pip install pillow") from exc

    reader = PSBReader(psb_path)
    plan = reader.resolve_diff_layer(layer_name)
    width = int(plan["width"])
    height = int(plan["height"])
    canvas = Image.new("RGBA", (width, height), (0, 0, 0, 0))

    used: list[dict[str, Any]] = []
    for role, layer in (
        ("base", plan.get("base_layer")),
        ("diff", plan.get("diff_layer")),
    ):
        if layer is None:
            continue
        path = find_layer_image(image_dir, role, layer)
        image = Image.open(path).convert("RGBA")

        opacity = int(layer.get("opacity", 255))
        opacity = max(0, min(255, opacity))
        if opacity != 255:
            alpha = image.getchannel("A").point(lambda a: a * opacity // 255)
            image.putalpha(alpha)

        left = int(layer.get("left", 0))
        top = int(layer.get("top", 0))
        overlay = Image.new("RGBA", canvas.size, (0, 0, 0, 0))
        overlay.alpha_composite(image, (left, top))
        canvas.alpha_composite(overlay)
        used.append({
            "role": role,
            "layer_name": layer.get("name"),
            "layer_id": layer.get("layer_id"),
            "resource_index": layer.get("resource_index"),
            "resource_name": layer.get("resource_name"),
            "left": left,
            "top": top,
            "opacity": opacity,
            "image": str(path),
        })

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    canvas.save(out)
    return {
        "psb": psb_path,
        "diff_name": layer_name,
        "output": str(out),
        "width": width,
        "height": height,
        "layers": used,
    }


# ---------------------------------------------------------------------------
# CLI Interface
# ---------------------------------------------------------------------------

def print_composition(reader: PSBReader, json_path: Optional[str] = None) -> None:
    """Print CG layer composition and optionally write JSON."""
    comp = reader.read_composition()

    print(f"Canvas: {comp['width']} x {comp['height']}")
    print(f"Layers: {len(comp['layers'])}")
    print()
    print(
        "ord  id  name res file  visible opacity  left   top   width height  "
        "tlg_w tlg_h"
    )
    print("-" * 91)
    for layer in comp["layers"]:
        print(
            f"{layer.get('order', 0):3d} "
            f"{layer.get('layer_id', '')!s:>3s} "
            f"{layer.get('name', '')!s:<4s} "
            f"{layer.get('resource_index', '')!s:>3s} "
            f"{str(layer.get('resource_name', '')):<4s} "
            f"{layer.get('visible', '')!s:>7s} "
            f"{layer.get('opacity', '')!s:>7s} "
            f"{layer.get('left', '')!s:>5s} "
            f"{layer.get('top', '')!s:>5s} "
            f"{layer.get('width', '')!s:>7s} "
            f"{layer.get('height', '')!s:>6s} "
            f"{layer.get('tlg_width', '')!s:>6s} "
            f"{layer.get('tlg_height', '')!s:>5s}"
        )

    if json_path:
        serializable = {
            "width": comp["width"],
            "height": comp["height"],
            "layers": comp["layers"],
        }
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(serializable, f, ensure_ascii=False, indent=2)
        print(f"\nWrote JSON: {json_path}")

def print_strings(reader: PSBReader) -> None:
    """Print PSB string table."""
    strings = reader.read_string_table()
    for i, s in enumerate(strings):
        print(f"{i:4d}: {s}")
    print(f"\nTotal: {len(strings)} strings")


def cmd_inspect(args: argparse.Namespace) -> int:
    """Inspect PSB structure, strings, or composition."""
    reader = PSBReader(args.input)
    if args.strings:
        print_strings(reader)
    elif args.composition:
        print_composition(reader, args.json)
    else:
        print(reader.dump_structure(max_depth=args.depth))
    return 0


def cmd_extract_all(args: argparse.Namespace) -> int:
    """Extract all embedded image resources and generate manifest."""
    try:
        reader = PSBReader(args.input)
        manifest = reader.extract_all_tlgs(args.output_dir)
        for item in manifest["exports"]:
            res = item["resource"]
            layer_names = ", ".join(
                str(layer.get("name")) for layer in item.get("layers", [])
            )
            print(
                f"res={res['index']:02d}:{res['name']} "
                f"layers=[{layer_names}] -> {item['path']}"
            )
        if args.png:
            converted = convert_manifest_exports_to_png(manifest, args.tlg2png)
            for item in converted:
                print(f"png -> {item['png']}")
        print(f"Manifest: {Path(args.output_dir) / 'all_tlg_manifest.json'}")
        return 0
    except PSBError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_compose_all(args: argparse.Namespace) -> int:
    """Extract all resources, composite every named layer/diff, and clean up."""
    try:
        results, extract_dir = composite_all_via_extract(
            args.input,
            args.output_dir,
            work_dir=args.work_dir,
            tlg2png_path=args.tlg2png,
            keep_temp=args.keep_temp,
        )
    except PSBError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    print(f"Wrote {len(results)} CG images to: {args.output_dir}")
    if args.keep_temp:
        print(f"Intermediate files: {extract_dir}")
    for result in results:
        print(f"  {result['diff_name']} -> {result['output']}")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="PSB (Painter Scribble / pimg) File Parser",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s inspect file.bin
      Show file structure and metadata
  %(prog)s inspect file.bin --strings
      List PSB string table
  %(prog)s inspect file.bin --composition
      Show layer/resource composition
  %(prog)s extract-all file.bin -o out_tlg --png
      Extract every embedded TLG, convert to PNG, and write manifest
  %(prog)s compose-all file.bin -o out_cg
      Extract all resources, composite every named layer/diff, then clean up
        """,
    )

    sub = parser.add_subparsers(dest="command", help="Subcommands")

    # inspect
    p_inspect = sub.add_parser("inspect", help="Inspect PSB metadata and tables")
    p_inspect.add_argument("input", help="Path to PSB file (.bin)")
    p_inspect.add_argument("-d", "--depth", type=int, default=2,
                           help="Maximum structure dump depth (default: 2)")
    p_inspect.add_argument("--strings", action="store_true",
                           help="List strings from PSB string table")
    p_inspect.add_argument("--composition", action="store_true",
                           help="Display layer/resource composition")
    p_inspect.add_argument("--json",
                           help="With --composition, write composition JSON")

    # extract-all
    p_extract_all = sub.add_parser(
        "extract-all",
        help="Extract every embedded image resource and generate manifest",
    )
    p_extract_all.add_argument("input", help="Path to PSB file (.bin)")
    p_extract_all.add_argument("-o", "--output-dir", required=True,
                               help="Directory for extracted TLG files")
    p_extract_all.add_argument("--png", action="store_true",
                               help="Convert extracted TLG files to PNG; embedded PNG files are kept as-is")
    p_extract_all.add_argument("--tlg2png",
                               help="Path to tlg2png.exe (default: tools/tlg2png/tlg2png.exe)")

    # compose-all
    p_compose_all = sub.add_parser(
        "compose-all",
        help="Extract resources, composite every named layer/diff, and clean up",
    )
    p_compose_all.add_argument("input", help="Path to PSB file (.bin)")
    p_compose_all.add_argument("-o", "--output-dir", required=True,
                               help="Output directory for composited PNG files")
    p_compose_all.add_argument("--work-dir",
                               help="Parent directory for temporary extracted files")
    p_compose_all.add_argument("--keep-temp", action="store_true",
                               help="Keep temporary extracted TLG/PNG/manifest files")
    p_compose_all.add_argument("--tlg2png",
                               help="Path to tlg2png.exe (default: tools/tlg2png/tlg2png.exe)")

    args = parser.parse_args()

    if args.command == "inspect":
        return cmd_inspect(args)
    elif args.command == "extract-all":
        return cmd_extract_all(args)
    elif args.command == "compose-all":
        return cmd_compose_all(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
