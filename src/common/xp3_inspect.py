#!/usr/bin/env python3
"""Inspect Kirikiri/TVP XP3 archives used by this game.

Default mode is read-only: it parses XP3 headers, the compressed index, and
prints package/entry metadata. Optional single-file extraction is available for
researching a known entry such as startup.tjs.

The unpacked program's XP3 stream path is:

    segment read -> zlib inflate when compressed -> recovered filter transform
    -> caller buffer

IDA names for the relevant dump:

    tTVPXP3ArchiveStream_Read_impl     0xC972E0
    TVPSetXP3ArchiveExtractionFilter   0xC7D2F0
    dword_FDA6B0                       0xFDA6B0

The callback receives a 0x18-byte tTVPXP3ExtractionFilterInfo-like structure:
SizeOfSelf, Offset, Buffer, BufferSize, FileHash.  This script models that
boundary and validates the result with the XP3 adlr chunk.  The runtime filter
has been fully recovered (see xp3_static_recovery_summary.md) and is integrated
via the --filter recovered / --drip-program flags.
"""

from __future__ import annotations

import argparse
import json
import re
import struct
import sys
import zlib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable


XP3_MAGIC = b"XP3\r\n \n\x1a\x8bg\x01"
# Recovered from 1ae7153ed25d.dll's initialized FilterManager state.  The Hxv4
# table decryptor uses XChaCha20-Poly1305 with key block 0 and nonce block 1 or
# 2 depending on the Hxv4 flag bit.
HXV4_KEY = bytes.fromhex(
    "e4dc1d99d9d9fb1ae5f7529ee70f841b"
    "fadb13d12f4d22b99170d6cc6a62bc54"
)
HXV4_NONCES = {
    0: bytes.fromhex(
        "d99230e02623f4a0c4f2857682b4de6d"
        "fefe820b57060e50b7cc2580db04d993"
    )[:24],
    1: bytes.fromhex(
        "b96f89630850dd23a13810c7718ad003"
        "936d1d4a3ae008909be93eee7ac8fc3e"
    )[:24],
}


@dataclass(frozen=True)
class Segment:
    flags: int
    offset: int
    original_size: int
    archived_size: int

    @property
    def compressed(self) -> bool:
        return bool(self.flags & 1)


@dataclass(frozen=True)
class Entry:
    name: str
    flags: int
    original_size: int
    archived_size: int
    adler32: int | None
    segments: tuple[Segment, ...]

    @property
    def encrypted_or_protected(self) -> bool:
        return bool(self.flags & 0x80000000)


@dataclass(frozen=True)
class ArchiveInfo:
    path: str
    size: int
    header_index_offset: int
    resolved_index_offset: int
    index_compressed_size: int
    index_original_size: int
    entry_count: int


@dataclass(frozen=True)
class ExtractedEntry:
    data: bytes
    adler32: int
    adler_ok: bool | None
    filter_needed: bool
    filter_applied: bool


class XP3Error(RuntimeError):
    pass


class XP3FilterRequired(XP3Error):
    pass


@dataclass(frozen=True)
class Hxv4Descriptor:
    offset: int
    size: int
    flags: int


@dataclass(frozen=True)
class Hxv4Record:
    domain_hash: str
    file_hash: str
    record_index: int
    packed: int
    archive_slot: int
    filter_flag: int
    key: int
    xp3_entry_index: int | None
    xp3_name: str | None


U32_MASK = 0xFFFFFFFF
U64_MASK = 0xFFFFFFFFFFFFFFFF

DRIP_OP_ADD_IMM = 0x17C50
DRIP_OP_RECURSE = 0x17C60
DRIP_OP_ADD_SCRATCH = 0x17CB0
DRIP_OP_MUL_SCRATCH = 0x17CD0
DRIP_OP_SCRATCH_MINUS_RESULT = 0x17CF0
DRIP_OP_SHL_SCRATCH = 0x17D10
DRIP_OP_SHR_SCRATCH = 0x17D30
DRIP_OP_SUB_SCRATCH = 0x17D50
DRIP_OP_BIT_SHUFFLE = 0x17D70
DRIP_OP_SET_IMM = 0x17DA0
DRIP_OP_SET_SEED = 0x17DB0
DRIP_OP_DEC = 0x17DD0
DRIP_OP_INC = 0x17DE0
DRIP_OP_NEG = 0x17DF0
DRIP_OP_NOT = 0x17E00
DRIP_OP_TABLE_IMM = 0x17E10
DRIP_OP_TABLE_MASKED = 0x17E30
DRIP_OP_SUB_IMM = 0x17E50
DRIP_OP_STORE_SCRATCH = 0x17E60
DRIP_OP_XOR_IMM = 0x17E80
DRIP_OP_STOP = 0x51D90


def _u32(value: int) -> int:
    return value & U32_MASK


def _u64(value: int) -> int:
    return value & U64_MASK


@dataclass(frozen=True)
class DripEvalState:
    seed: int
    scratch: int = 0


class DripProgram:
    """Interpreter for DripValueImpl_get64_from_u32 / DripValueLane_eval."""

    def __init__(
        self,
        *,
        holder_words: list[int],
        context_u32: list[int],
        lanes: list[list[tuple[int, int]]],
        hxv4_key: bytes | None = None,
        hxv4_nonces: dict[int, bytes] | None = None,
    ) -> None:
        if len(lanes) != 128:
            raise XP3Error(f"Drip program must contain 128 lanes, got {len(lanes)}")
        if len(holder_words) < 6:
            raise XP3Error("Drip program holder_words is truncated")
        self.holder_words = tuple(_u32(value) for value in holder_words)
        self.context_u32 = tuple(_u32(value) for value in context_u32)
        self.lanes = tuple(tuple((_u32(param), op) for param, op in lane) for lane in lanes)
        self.hxv4_key = hxv4_key
        self.hxv4_nonces = hxv4_nonces or {}

    @classmethod
    def load(cls, path: Path) -> "DripProgram":
        payload = json.loads(path.read_text(encoding="utf-8"))
        lanes_blob = payload.get("lanes")
        if not isinstance(lanes_blob, list):
            raise XP3Error("Drip program JSON has no lanes list")

        lanes: list[list[tuple[int, int]]] = []
        for lane in lanes_blob:
            records = lane.get("records") if isinstance(lane, dict) else None
            if not isinstance(records, list):
                raise XP3Error("Drip program lane has no records list")
            lane_records: list[tuple[int, int]] = []
            for record in records:
                if not isinstance(record, list) or len(record) != 2:
                    raise XP3Error("Drip program record must be [param, callback_rva]")
                lane_records.append((int(record[0]), int(record[1])))
            lanes.append(lane_records)

        return cls(
            holder_words=[int(value) for value in payload["holder_words"]],
            context_u32=[int(value) for value in payload["context_u32"]],
            lanes=lanes,
            hxv4_key=bytes.fromhex(payload["hxv4_key"]) if payload.get("hxv4_key") else None,
            hxv4_nonces={
                0: bytes.fromhex(payload["hxv4_nonce0"]),
                1: bytes.fromhex(payload["hxv4_nonce1"]),
            }
            if payload.get("hxv4_nonce0") and payload.get("hxv4_nonce1")
            else None,
        )

    def _context_value(self, index: int) -> int:
        if index < 0 or index >= len(self.context_u32):
            raise XP3Error(f"Drip context index out of range: {index:#x}")
        return self.context_u32[index]

    def _eval_records(
        self,
        records: tuple[tuple[int, int], ...],
        pc: int,
        result: int,
        state: DripEvalState,
    ) -> tuple[int, int, DripEvalState]:
        result = _u32(result)
        scratch = _u32(state.scratch)
        seed = _u32(state.seed)

        while pc < len(records):
            param, op = records[pc]
            pc += 1

            if op == DRIP_OP_STOP:
                break
            if op == DRIP_OP_RECURSE:
                nested_state = DripEvalState(seed=seed, scratch=scratch)
                result, pc, _ = self._eval_records(records, pc, result, nested_state)
                continue
            if op == DRIP_OP_ADD_IMM:
                result = result + param
            elif op == DRIP_OP_ADD_SCRATCH:
                result = result + scratch
            elif op == DRIP_OP_MUL_SCRATCH:
                result = result * scratch
            elif op == DRIP_OP_SCRATCH_MINUS_RESULT:
                result = scratch - result
            elif op == DRIP_OP_SHL_SCRATCH:
                result = result << (scratch & 0xF)
            elif op == DRIP_OP_SHR_SCRATCH:
                result = _u32(result) >> (scratch & 0xF)
            elif op == DRIP_OP_SUB_SCRATCH:
                result = result - scratch
            elif op == DRIP_OP_BIT_SHUFFLE:
                result = (2 * (_u32(result) & _u32(~param))) | ((param >> 1) & (_u32(result) >> 1))
            elif op == DRIP_OP_SET_IMM:
                result = param
            elif op == DRIP_OP_SET_SEED:
                result = seed
            elif op == DRIP_OP_DEC:
                result = result - 1
            elif op == DRIP_OP_INC:
                result = result + 1
            elif op == DRIP_OP_NEG:
                result = -result
            elif op == DRIP_OP_NOT:
                result = ~result
            elif op == DRIP_OP_TABLE_IMM:
                result = self._context_value(param)
            elif op == DRIP_OP_TABLE_MASKED:
                result = self._context_value(param & _u32(result))
            elif op == DRIP_OP_SUB_IMM:
                result = result - param
            elif op == DRIP_OP_STORE_SCRATCH:
                scratch = _u32(result)
                result = scratch
            elif op == DRIP_OP_XOR_IMM:
                result = _u32(result) ^ param
            else:
                raise XP3Error(f"unknown Drip op callback RVA: 0x{op:x}")

            result = _u32(result)

        return result, pc, DripEvalState(seed=seed, scratch=scratch)

    def eval_lane(self, lane_index: int, seed: int) -> int:
        if lane_index < 0 or lane_index >= len(self.lanes):
            raise XP3Error(f"Drip lane out of range: {lane_index}")
        result, _, _ = self._eval_records(
            self.lanes[lane_index],
            0,
            0,
            DripEvalState(seed=_u32(seed)),
        )
        return result

    def get64_from_u32(self, value: int) -> int:
        value = _u32(value)
        lane_index = value & 0x7F
        seed = value >> 7
        lo = self.eval_lane(lane_index, seed)
        hi = self.eval_lane(lane_index, _u32(~seed))
        return lo | (hi << 32)

    def build_filter_state(self, key: int, open_flag: int) -> bytes:
        key = _u64(key)
        key_lo = key & U32_MASK
        key_hi = key >> 32
        if not (open_flag & 1):
            key_lo ^= self.holder_words[2]
            key_hi ^= self.holder_words[3]
        key64 = key_lo | (key_hi << 32)

        state = bytearray(48)
        struct.pack_into("<Q", state, 0, self.get64_from_u32(key_lo))
        struct.pack_into("<Q", state, 8, self.get64_from_u32(key_hi))
        bulk_offset = self.holder_words[5] + (self.holder_words[4] & (key64 >> 16))
        struct.pack_into("<I", state, 16, _u32(bulk_offset))
        struct.pack_into("<I", state, 20, 0)

        cur = _u64(~key64)
        bitpos = -1
        out = 24
        while out < 40:
            if bitpos < 0:
                cur = _u64(~self.get64_from_u32(cur & U32_MASK))
                bitpos = 64
            else:
                state[out] = (cur >> bitpos) & 0xFF
                out += 1
            bitpos -= 8

        state[44] = 1
        state[45] = 0
        return bytes(state)


@dataclass(frozen=True)
class FilterBoundary:
    pos0: int
    pos1: int
    key: int
    byte0: int
    byte1: int


class FilterRuntimeState:
    """Runtime equivalent of FilterImpl_InitState plus FilterImpl_Apply."""

    def __init__(self, seed_state: bytes) -> None:
        if len(seed_state) != 48:
            raise XP3Error(f"filter seed state must be 48 bytes, got {len(seed_state)}")
        null_mode = bool(seed_state[45])
        self.boundary0 = self._init_boundary(struct.unpack_from("<Q", seed_state, 0)[0], null_mode)
        self.boundary1 = self._init_boundary(struct.unpack_from("<Q", seed_state, 8)[0], null_mode)
        self.split_offset = struct.unpack_from("<Q", seed_state, 16)[0]
        has_bulk = bool(seed_state[44])
        self.bulk_key = seed_state[24:40] if has_bulk else b""

    @staticmethod
    def _init_boundary(value: int, null_mode: bool) -> FilterBoundary:
        pos0 = (value >> 48) & 0xFFFF
        pos1 = (value >> 32) & 0xFFFF
        if pos0 == pos1:
            pos1 += 1

        key_byte = value & 0xFF
        byte0 = (value >> 8) & 0xFF
        byte1 = (value >> 16) & 0xFF
        if key_byte == 0:
            key_byte = 0 if null_mode else 0xA5
        key = (key_byte * 0x01010101) & U32_MASK
        if null_mode:
            byte0 = 0
            byte1 = 0
        return FilterBoundary(pos0=pos0, pos1=pos1, key=key, byte0=byte0, byte1=byte1)

    @staticmethod
    def _xor_rotated_dword_key(
        data: bytearray,
        *,
        logical_start: int,
        buffer_start: int,
        size: int,
        key: int,
    ) -> None:
        for index in range(size):
            shift = ((logical_start + index) & 3) * 8
            data[buffer_start + index] ^= (key >> shift) & 0xFF

    @staticmethod
    def _xor_boundary_byte(
        data: bytearray,
        *,
        chunk_start: int,
        buffer_start: int,
        size: int,
        position: int,
        value: int,
    ) -> None:
        if value and chunk_start <= position < chunk_start + size:
            data[buffer_start + position - chunk_start] ^= value

    def _apply_boundary(
        self,
        data: bytearray,
        boundary: FilterBoundary,
        *,
        chunk_start: int,
        buffer_start: int,
        size: int,
    ) -> None:
        if size <= 0:
            return
        self._xor_rotated_dword_key(
            data,
            logical_start=chunk_start,
            buffer_start=buffer_start,
            size=size,
            key=boundary.key,
        )
        self._xor_boundary_byte(
            data,
            chunk_start=chunk_start,
            buffer_start=buffer_start,
            size=size,
            position=boundary.pos0,
            value=boundary.byte0,
        )
        self._xor_boundary_byte(
            data,
            chunk_start=chunk_start,
            buffer_start=buffer_start,
            size=size,
            position=boundary.pos1,
            value=boundary.byte1,
        )

    def apply(self, data: bytearray, offset: int) -> bool:
        if not data:
            return False
        size = len(data)
        end = offset + size

        if self.bulk_key and offset < len(self.bulk_key):
            overlap_start = max(offset, 0)
            overlap_end = min(end, len(self.bulk_key))
            for logical in range(overlap_start, overlap_end):
                data[logical - offset] ^= self.bulk_key[logical]

        split = self.split_offset
        if split <= offset:
            self._apply_boundary(
                data,
                self.boundary1,
                chunk_start=offset,
                buffer_start=0,
                size=size,
            )
        elif split < end:
            first_size = split - offset
            self._apply_boundary(
                data,
                self.boundary0,
                chunk_start=offset,
                buffer_start=0,
                size=first_size,
            )
            self._apply_boundary(
                data,
                self.boundary1,
                chunk_start=split,
                buffer_start=first_size,
                size=end - split,
            )
        else:
            self._apply_boundary(
                data,
                self.boundary0,
                chunk_start=offset,
                buffer_start=0,
                size=size,
            )
        return True


def _read_u64(data: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def calc_adler32(data: bytes | bytearray) -> int:
    return zlib.adler32(data) & 0xFFFFFFFF


def format_adler(value: int | None) -> str:
    return "None" if value is None else f"0x{value:08x}"


def resolve_index_offset(blob: bytes) -> int:
    """Return the actual tail index offset.

    These archives put 0x17 in the normal XP3 index-offset field. At 0x17 there
    is an extra pointer block whose qword at 0x20 points at the real zlib index.
    This matches the local packages and keeps support for ordinary XP3 files.
    """
    if not blob.startswith(XP3_MAGIC):
        raise XP3Error("not an XP3 archive")

    header_offset = _read_u64(blob, 11)
    if header_offset >= len(blob):
        raise XP3Error(f"index offset outside file: 0x{header_offset:x}")

    if header_offset == 0x17 and len(blob) >= 0x28:
        candidate = _read_u64(blob, 0x20)
        if 0 < candidate < len(blob):
            return candidate

    return header_offset


def load_index(blob: bytes) -> tuple[int, int, int, bytes]:
    index_offset = resolve_index_offset(blob)
    flag = blob[index_offset]
    cursor = index_offset + 1

    if flag == 0:
        index_size = _read_u64(blob, cursor)
        cursor += 8
        return index_offset, index_size, index_size, blob[cursor : cursor + index_size]

    if flag == 1:
        compressed_size = _read_u64(blob, cursor)
        original_size = _read_u64(blob, cursor + 8)
        cursor += 16
        raw = blob[cursor : cursor + compressed_size]
        index = zlib.decompress(raw)
        if len(index) != original_size:
            raise XP3Error(
                f"index size mismatch: got {len(index)}, expected {original_size}"
            )
        return index_offset, compressed_size, original_size, index

    raise XP3Error(f"unsupported XP3 index flag 0x{flag:02x} at 0x{index_offset:x}")


def find_hxv4_descriptor(index: bytes) -> Hxv4Descriptor | None:
    cursor = 0
    while cursor + 12 <= len(index):
        tag = index[cursor : cursor + 4]
        chunk_size = _read_u64(index, cursor + 4)
        cursor += 12
        chunk = index[cursor : cursor + chunk_size]
        cursor += chunk_size
        if tag == b"Hxv4":
            if len(chunk) < 14:
                raise XP3Error("truncated Hxv4 descriptor")
            offset = struct.unpack_from("<Q", chunk, 0)[0]
            size = struct.unpack_from("<I", chunk, 8)[0]
            flags = struct.unpack_from("<H", chunk, 12)[0]
            return Hxv4Descriptor(offset=offset, size=size, flags=flags)
    return None


def decrypt_hxv4_payload(payload: bytes, flags: int, drip_program: DripProgram | None = None) -> bytes:
    try:
        from Crypto.Cipher import ChaCha20_Poly1305
    except ImportError as exc:
        raise XP3Error(
            "Hxv4 decryption needs PyCryptodome (Crypto.Cipher.ChaCha20_Poly1305)"
        ) from exc

    if len(payload) < 21:
        raise XP3Error("truncated Hxv4 encrypted payload")

    key = drip_program.hxv4_key if drip_program and drip_program.hxv4_key else HXV4_KEY
    nonces = drip_program.hxv4_nonces if drip_program and drip_program.hxv4_nonces else HXV4_NONCES
    nonce = nonces[flags & 1]
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    return cipher.decrypt_and_verify(payload[16:], payload[:16])


class TJSBinaryReader:
    """Reader for the big-endian TJS Variant blob inside Hxv4 tables."""

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def read(self, size: int) -> bytes:
        if self.pos + size > len(self.data):
            raise XP3Error("truncated TJS binary payload")
        value = self.data[self.pos : self.pos + size]
        self.pos += size
        return value

    def read_u8(self) -> int:
        return self.read(1)[0]

    def read_i32(self) -> int:
        return struct.unpack(">i", self.read(4))[0]

    def read_i64(self) -> int:
        return struct.unpack(">q", self.read(8))[0]

    def read_f64(self) -> float:
        return struct.unpack(">d", self.read(8))[0]

    def read_string(self) -> str:
        chars = self.read_i32()
        if chars < 0:
            raise XP3Error("negative TJS string length")
        return self.read(chars * 2).decode("utf-16be", errors="replace")

    def read_value(self) -> Any:
        tag = self.read_u8()
        signed_tag = tag if tag < 0x80 else tag - 0x100

        if signed_tag in (0, 1):
            return None
        if signed_tag == 2:
            return self.read_string()
        if signed_tag == 3:
            size = self.read_i32()
            if size < 0:
                raise XP3Error("negative TJS octet length")
            return self.read(size)
        if signed_tag == 4:
            return self.read_i64()
        if signed_tag == 5:
            return self.read_f64()
        if signed_tag == -127:
            count = self.read_i32()
            if count < 0:
                raise XP3Error("negative TJS array length")
            return [self.read_value() for _ in range(count)]
        if signed_tag == -63:
            count = self.read_i32()
            if count < 0:
                raise XP3Error("negative TJS dictionary length")
            return {self.read_string(): self.read_value() for _ in range(count)}

        raise XP3Error(f"unsupported TJS binary tag {signed_tag} at 0x{self.pos - 1:x}")


def parse_hxv4_table(
    blob: bytes,
    index: bytes,
    entries: list[Entry],
    drip_program: DripProgram | None = None,
) -> tuple[Hxv4Descriptor, list[Hxv4Record]]:
    descriptor = find_hxv4_descriptor(index)
    if descriptor is None:
        raise XP3Error("archive has no Hxv4 table")
    end = descriptor.offset + descriptor.size
    if descriptor.offset < 0 or end > len(blob):
        raise XP3Error("Hxv4 payload points outside archive")

    decrypted = decrypt_hxv4_payload(blob[descriptor.offset:end], descriptor.flags, drip_program)
    if len(decrypted) < 4:
        raise XP3Error("truncated decrypted Hxv4 payload")
    uncompressed_size = struct.unpack_from("<I", decrypted, 0)[0]
    table_blob = zlib.decompress(decrypted[4:])
    if len(table_blob) != uncompressed_size:
        raise XP3Error(
            f"Hxv4 table size mismatch: got {len(table_blob)}, expected {uncompressed_size}"
        )

    value = TJSBinaryReader(table_blob).read_value()
    if not isinstance(value, list) or len(value) % 2:
        raise XP3Error("unexpected Hxv4 table shape")

    entry_base = 1 if len(entries) > 1 and entries[1].name == "startup.tjs" else 0
    records: list[Hxv4Record] = []
    for group_index in range(0, len(value), 2):
        domain_hash = value[group_index]
        group = value[group_index + 1]
        if not isinstance(domain_hash, bytes) or not isinstance(group, list) or len(group) % 2:
            raise XP3Error("unexpected Hxv4 group shape")
        for item_index in range(0, len(group), 2):
            file_hash = group[item_index]
            pair = group[item_index + 1]
            if (
                not isinstance(file_hash, bytes)
                or not isinstance(pair, list)
                or len(pair) != 2
                or not isinstance(pair[0], int)
                or not isinstance(pair[1], int)
            ):
                raise XP3Error("unexpected Hxv4 record shape")
            packed = pair[0]
            archive_slot = (packed >> 16) & 0xFFFF
            filter_flag = packed & 0xFFFF
            xp3_entry_index = filter_flag + entry_base if archive_slot == 0 else None
            xp3_name = (
                entries[xp3_entry_index].name
                if xp3_entry_index is not None and xp3_entry_index < len(entries)
                else None
            )
            records.append(
                Hxv4Record(
                    domain_hash=domain_hash.hex(),
                    file_hash=file_hash.hex(),
                    record_index=len(records),
                    packed=packed,
                    archive_slot=archive_slot,
                    filter_flag=filter_flag,
                    key=pair[1],
                    xp3_entry_index=xp3_entry_index,
                    xp3_name=xp3_name,
                )
            )

    return descriptor, records


def build_filter_state_map(
    blob: bytes,
    index: bytes,
    entries: list[Entry],
    drip_program: DripProgram,
    *,
    force_open_flag: int | None = None,
) -> dict[int, FilterRuntimeState]:
    descriptor, records = parse_hxv4_table(blob, index, entries, drip_program)
    states: dict[int, FilterRuntimeState] = {}
    for record in records:
        if record.archive_slot != 0 or record.xp3_entry_index is None:
            continue
        if record.xp3_entry_index < 0 or record.xp3_entry_index >= len(entries):
            continue
        open_flag = force_open_flag if force_open_flag is not None else (descriptor.flags & 1)
        seed_state = drip_program.build_filter_state(record.key, open_flag)
        states[record.xp3_entry_index] = FilterRuntimeState(seed_state)
    return states


def parse_entries(index: bytes) -> list[Entry]:
    entries: list[Entry] = []
    cursor = 0

    while cursor + 12 <= len(index):
        tag = index[cursor : cursor + 4]
        chunk_size = _read_u64(index, cursor + 4)
        cursor += 12
        chunk = index[cursor : cursor + chunk_size]
        cursor += chunk_size

        if tag != b"File":
            continue

        name = ""
        flags = 0
        original_size = 0
        archived_size = 0
        adler32: int | None = None
        segments: list[Segment] = []
        sub = 0

        while sub + 12 <= len(chunk):
            sub_tag = chunk[sub : sub + 4]
            sub_size = _read_u64(chunk, sub + 4)
            sub += 12
            body = chunk[sub : sub + sub_size]
            sub += sub_size

            if sub_tag == b"info":
                flags, original_size, archived_size, name_len = struct.unpack_from(
                    "<IQQH", body, 0
                )
                raw_name = body[22 : 22 + name_len * 2]
                name = raw_name.decode("utf-16le", errors="replace")
            elif sub_tag == b"segm":
                for seg_off in range(0, len(body), 28):
                    if seg_off + 28 > len(body):
                        raise XP3Error("truncated segment chunk")
                    seg_flags, offset, org, arc = struct.unpack_from(
                        "<IQQQ", body, seg_off
                    )
                    segments.append(Segment(seg_flags, offset, org, arc))
            elif sub_tag == b"adlr" and len(body) >= 4:
                adler32 = struct.unpack_from("<I", body, 0)[0]

        entries.append(
            Entry(
                name=name,
                flags=flags,
                original_size=original_size,
                archived_size=archived_size,
                adler32=adler32,
                segments=tuple(segments),
            )
        )

    return entries


def read_archive(path: Path) -> tuple[ArchiveInfo, list[Entry], bytes]:
    blob = path.read_bytes()
    header_index_offset = _read_u64(blob, 11)
    index_offset, compressed_size, original_size, index = load_index(blob)
    entries = parse_entries(index)
    info = ArchiveInfo(
        path=str(path),
        size=len(blob),
        header_index_offset=header_index_offset,
        resolved_index_offset=index_offset,
        index_compressed_size=compressed_size,
        index_original_size=original_size,
        entry_count=len(entries),
    )
    return info, entries, blob


def iter_entry_chunks(blob: bytes, entry: Entry) -> Iterable[tuple[int, bytes]]:
    """Yield decompressed XP3 entry chunks as the runtime stream would see them.

    tTVPXP3ArchiveStream_Read_impl calls the extraction filter after bytes have
    been copied into the caller's buffer.  The callback offset is the logical
    entry offset, not the physical archive offset.  Yielding logical offsets
    here keeps any recovered filter easy to plug in later.
    """
    logical_offset = 0
    for seg in entry.segments:
        raw = blob[seg.offset : seg.offset + seg.archived_size]
        if len(raw) != seg.archived_size:
            raise XP3Error(f"segment outside archive for {entry.name!r}")
        if seg.compressed:
            raw = zlib.decompress(raw)
            if len(raw) != seg.original_size:
                raise XP3Error(
                    f"segment size mismatch for {entry.name!r}: "
                    f"{len(raw)} != {seg.original_size}"
                )
        yield logical_offset, raw
        logical_offset += len(raw)


def apply_recovered_filter(
    data: bytearray,
    *,
    entry: Entry,
    offset: int,
    filter_name: str,
    filter_state: FilterRuntimeState | None = None,
) -> bool:
    """Apply a recovered game-specific XP3 extraction filter.

    The current EXE dump proves where the callback is invoked, but dword_FDA6B0
    is still zero in that dump and the callback body has not been recovered.
    Keep this function as the single integration point for the real algorithm:
    it should mutate data in place using the runtime fields
    (offset, buffer, size, entry.adler32).
    """
    if filter_name == "none":
        return False
    if filter_name == "recovered":
        if filter_state is None:
            raise XP3FilterRequired(f"no recovered filter state for {entry.name!r}")
        return filter_state.apply(data, offset)
    raise XP3Error(f"unknown filter mode: {filter_name}")


def extract_entry(
    blob: bytes,
    entry: Entry,
    *,
    filter_name: str = "auto",
    filter_state: FilterRuntimeState | None = None,
) -> ExtractedEntry:
    raw_chunks = list(iter_entry_chunks(blob, entry))
    if filter_name == "recovered" and entry.adler32 is not None:
        raw_data = b"".join(chunk for _, chunk in raw_chunks)
        if calc_adler32(raw_data) == entry.adler32:
            filter_name = "none"

    parts: list[bytes] = []
    filter_applied = False
    for offset, chunk in raw_chunks:
        buf = bytearray(chunk)
        if filter_name == "recovered":
            filter_applied |= apply_recovered_filter(
                buf,
                entry=entry,
                offset=offset,
                filter_name=filter_name,
                filter_state=filter_state,
            )
        parts.append(bytes(buf))

    data = b"".join(parts)
    if len(data) != entry.original_size:
        raise XP3Error(
            f"entry size mismatch for {entry.name!r}: {len(data)} != {entry.original_size}"
        )

    actual = calc_adler32(data)
    adler_ok = None if entry.adler32 is None else actual == entry.adler32
    filter_needed = (
        entry.encrypted_or_protected
        and entry.adler32 is not None
        and not adler_ok
        and not filter_applied
    )
    if filter_name == "auto" and filter_needed:
        raise XP3FilterRequired(
            f"{entry.name!r} needs the runtime XP3 extraction filter: "
            f"raw adler=0x{actual:08x}, expected=0x{entry.adler32:08x}"
        )

    return ExtractedEntry(
        data=data,
        adler32=actual,
        adler_ok=adler_ok,
        filter_needed=filter_needed,
        filter_applied=filter_applied,
    )


def iter_archives(paths: Iterable[Path]) -> Iterable[Path]:
    for path in paths:
        if path.is_dir():
            yield from sorted(path.glob("*.xp3"))
        else:
            yield path


def is_warning_entry(index: int, entry: Entry) -> bool:
    return (
        index == 0
        and entry.flags == 0
        and len(entry.segments) == 1
        and entry.segments[0].original_size < entry.original_size
    )


def safe_output_name(index: int, entry: Entry) -> str:
    name = entry.name.strip().replace("\\", "/")
    name = name.split("/")[-1]
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]+', "_", name)
    name = name.strip(" ._")
    if not name:
        name = f"entry_{index:05d}"
    if "." not in name:
        codepoints = "_".join(f"{ord(ch):04x}" for ch in entry.name[:4]) or "unnamed"
        name = f"entry_{index:05d}_{codepoints}.bin"
    return name


def unique_path(root: Path, name: str) -> Path:
    candidate = root / name
    if not candidate.exists():
        return candidate
    stem = candidate.stem
    suffix = candidate.suffix
    for idx in range(1, 100000):
        candidate = root / f"{stem}.{idx}{suffix}"
        if not candidate.exists():
            return candidate
    raise XP3Error(f"could not find a unique output name for {name!r}")


def load_filter_states_for_archive(
    blob: bytes,
    entries: list[Entry],
    args: argparse.Namespace,
) -> dict[int, FilterRuntimeState]:
    drip_path = getattr(args, "drip_program", None)
    if getattr(args, "filter", "none") != "recovered" or drip_path is None:
        return {}
    drip_program = DripProgram.load(drip_path)
    _, _, _, index = load_index(blob)
    return build_filter_state_map(
        blob,
        index,
        entries,
        drip_program,
        force_open_flag=getattr(args, "force_open_flag", None),
    )


def command_summary(args: argparse.Namespace) -> int:
    for path in iter_archives(args.paths):
        info, entries, _ = read_archive(path)
        protected = sum(1 for e in entries if e.encrypted_or_protected)
        compressed_entries = sum(1 for e in entries if any(s.compressed for s in e.segments))
        visible = [e.name for e in entries if e.name and (e.name.isascii() or "." in e.name)]
        print(
            f"{Path(info.path).name}: entries={info.entry_count} "
            f"index=0x{info.resolved_index_offset:x} "
            f"index_c/u={info.index_compressed_size}/{info.index_original_size} "
            f"protected_flag={protected} compressed={compressed_entries}"
        )
        if visible:
            print("  visible:", ", ".join(visible[: args.visible_limit]))
        if args.samples:
            for entry in entries[: args.samples]:
                print(
                    f"  {entry.name!r} flags=0x{entry.flags:08x} "
                    f"size={entry.original_size}/{entry.archived_size} "
                    f"segments={len(entry.segments)}"
                )
    return 0


def command_find(args: argparse.Namespace) -> int:
    needle = args.name.casefold()
    found = False
    for path in iter_archives(args.paths):
        _, entries, _ = read_archive(path)
        for entry in entries:
            if needle in entry.name.casefold():
                found = True
                print(
                    f"{path.name}: {entry.name!r} flags=0x{entry.flags:08x} "
                    f"size={entry.original_size}/{entry.archived_size} "
                    f"adler={format_adler(entry.adler32)}"
                )
                for seg in entry.segments:
                    print(
                        f"  seg flags=0x{seg.flags:x} off=0x{seg.offset:x} "
                        f"size={seg.original_size}/{seg.archived_size}"
                    )
    return 0 if found else 1


def command_extract(args: argparse.Namespace) -> int:
    info, entries, blob = read_archive(args.archive)
    matches = [(index, entry) for index, entry in enumerate(entries) if entry.name == args.name]
    if not matches:
        raise XP3Error(f"{args.name!r} not found in {info.path}")
    if len(matches) > 1:
        raise XP3Error(f"{args.name!r} is ambiguous in {info.path}")
    entry_index, entry = matches[0]
    filter_states = load_filter_states_for_archive(blob, entries, args)

    result = extract_entry(
        blob,
        entry,
        filter_name=args.filter,
        filter_state=filter_states.get(entry_index),
    )
    args.output.write_bytes(result.data)
    status = "unchecked" if result.adler_ok is None else ("ok" if result.adler_ok else "mismatch")
    print(
        f"wrote {len(result.data)} bytes to {args.output} "
        f"adler={status} raw=0x{result.adler32:08x} "
        f"expected={format_adler(entry.adler32)}"
    )
    if result.filter_needed:
        print("warning: output is raw post-zlib data; runtime XP3 filter was not applied")
    return 0


def command_verify(args: argparse.Namespace) -> int:
    failed = 0
    unresolved = 0
    checked = 0
    max_entries = getattr(args, "max_entries", None)
    for path in iter_archives(args.paths):
        archive_failed = 0
        archive_unresolved = 0
        archive_checked = 0
        archive_seen = 0
        _, entries, blob = read_archive(path)
        filter_states = load_filter_states_for_archive(blob, entries, args)
        for index, entry in enumerate(entries):
            if is_warning_entry(index, entry) and not args.include_warning:
                continue
            if max_entries is not None and archive_seen >= max_entries:
                break
            archive_seen += 1
            try:
                result = extract_entry(
                    blob,
                    entry,
                    filter_name=args.filter,
                    filter_state=filter_states.get(index),
                )
            except XP3FilterRequired as exc:
                unresolved += 1
                archive_unresolved += 1
                if args.verbose:
                    print(f"{path.name}:{index}:{entry.name!r}: unresolved: {exc}")
                continue
            except XP3Error as exc:
                failed += 1
                archive_failed += 1
                if args.verbose:
                    print(f"{path.name}:{index}:{entry.name!r}: error: {exc}")
                continue
            checked += 1
            archive_checked += 1
            if result.adler_ok is False:
                failed += 1
                archive_failed += 1
                if args.verbose:
                    print(
                        f"{path.name}:{index}:{entry.name!r}: mismatch "
                        f"raw=0x{result.adler32:08x} expected={format_adler(entry.adler32)}"
                    )
        print(
            f"{path.name}: checked={archive_checked} failed={archive_failed} "
            f"unresolved_filter={archive_unresolved}"
            + (f" limited_to={max_entries}" if max_entries is not None else "")
        )
    return 1 if failed or unresolved else 0


def _load_hxv4_hashes_for_entries(
    blob: bytes,
    entries: list[Entry],
    args: argparse.Namespace,
) -> dict[int, dict[str, object]]:
    """Build a mapping from xp3_entry_index to Hxv4 hash fields.

    Returns an empty dict if the archive has no Hxv4 table or parsing fails.
    """
    try:
        _, _, _, index = load_index(blob)
        drip_path = getattr(args, "drip_program", None)
        drip_program = DripProgram.load(drip_path) if drip_path else None
        _, records = parse_hxv4_table(blob, index, entries, drip_program)
    except XP3Error:
        return {}

    hashes: dict[int, dict[str, object]] = {}
    for rec in records:
        if rec.xp3_entry_index is None:
            continue
        hashes[rec.xp3_entry_index] = {
            "pathname_hash": rec.domain_hash,
            "filename_hash": rec.file_hash,
            "hxv4_key": rec.key,
        }
    return hashes


def command_extract_all(args: argparse.Namespace) -> int:
    args.output.mkdir(parents=True, exist_ok=True)
    manifest_path = args.output / "manifest.jsonl"
    total = 0
    written = 0
    unresolved = 0
    failed = 0
    with manifest_path.open("w", encoding="utf-8") as manifest:
        for path in iter_archives(args.paths):
            _, entries, blob = read_archive(path)
            filter_states = load_filter_states_for_archive(blob, entries, args)
            hxv4_hashes = _load_hxv4_hashes_for_entries(blob, entries, args)
            archive_dir = args.output / path.stem
            archive_dir.mkdir(parents=True, exist_ok=True)
            for index, entry in enumerate(entries):
                if is_warning_entry(index, entry) and not args.include_warning:
                    continue
                total += 1
                record: dict[str, object] = {
                    "archive": path.name,
                    "index": index,
                    "name": entry.name,
                    "flags": entry.flags,
                    "expected_adler32": entry.adler32,
                    "original_size": entry.original_size,
                    "archived_size": entry.archived_size,
                }
                if index in hxv4_hashes:
                    record.update(hxv4_hashes[index])
                try:
                    result = extract_entry(
                        blob,
                        entry,
                        filter_name=args.filter,
                        filter_state=filter_states.get(index),
                    )
                    out_path = unique_path(archive_dir, safe_output_name(index, entry))
                    out_path.write_bytes(result.data)
                    written += 1
                    record.update(
                        {
                            "status": "written",
                            "output": str(out_path.relative_to(args.output)),
                            "actual_adler32": result.adler32,
                            "adler_ok": result.adler_ok,
                            "filter_applied": result.filter_applied,
                        }
                    )
                    if result.filter_needed:
                        record["status"] = "written_unfiltered"
                except XP3FilterRequired as exc:
                    unresolved += 1
                    record.update({"status": "unresolved_filter", "error": str(exc)})
                except (OSError, XP3Error, zlib.error, struct.error) as exc:
                    failed += 1
                    record.update({"status": "error", "error": str(exc)})
                manifest.write(json.dumps(record, ensure_ascii=False) + "\n")
    print(
        f"processed={total} written={written} unresolved_filter={unresolved} "
        f"failed={failed} manifest={manifest_path}"
    )
    return 1 if unresolved or failed else 0


def command_json(args: argparse.Namespace) -> int:
    info, entries, _ = read_archive(args.archive)
    payload = {
        "archive": asdict(info),
        "entries": [
            {
                **asdict(entry),
                "segments": [asdict(seg) for seg in entry.segments],
            }
            for entry in entries
        ],
    }
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"wrote {len(entries)} entries to {args.output}")
    return 0


def command_hxv4(args: argparse.Namespace) -> int:
    total = 0
    payloads = []
    state_payloads = []
    drip_program = DripProgram.load(args.drip_program) if args.drip_program else None
    for path in args.paths:
        info, entries, blob = read_archive(path)
        _, _, _, index = load_index(blob)
        descriptor, records = parse_hxv4_table(blob, index, entries, drip_program)
        total += len(records)
        record_payloads: list[dict[str, Any]] = []
        state_records: list[dict[str, Any]] = []
        for record in records:
            record_payload = asdict(record)
            if drip_program is not None:
                open_flag = (
                    args.force_open_flag
                    if args.force_open_flag is not None
                    else (descriptor.flags & 1)
                )
                state = drip_program.build_filter_state(record.key, open_flag)
                state_dwords = list(struct.unpack("<12I", state))
                state_payload = {
                    "record_index": record.record_index,
                    "archive_slot": record.archive_slot,
                    "filter_flag": record.filter_flag,
                    "filter_open_flag": open_flag,
                    "key": record.key,
                    "key_hex": f"0x{record.key & U64_MASK:016x}",
                    "xp3_entry_index": record.xp3_entry_index,
                    "xp3_name": record.xp3_name,
                    "state_hex": state.hex(),
                    "state_dwords": state_dwords,
                }
                record_payload["filter_open_flag"] = open_flag
                record_payload["filter_state_hex"] = state.hex()
                record_payload["filter_state_dwords"] = state_dwords
                state_records.append(state_payload)
            record_payloads.append(record_payload)

        archive_payload = {
            "archive": asdict(info),
            "hxv4": asdict(descriptor),
            "record_count": len(records),
            "records": record_payloads,
        }
        payloads.append(archive_payload)
        if drip_program is not None:
            state_payloads.append(
                {
                    "archive": path.name,
                    "path": str(path),
                    "record_count": len(state_records),
                    "records": state_records,
                }
            )

        sample = records[: args.samples]
        print(
            f"{path.name}: hxv4_offset=0x{descriptor.offset:x} "
            f"size=0x{descriptor.size:x} flags=0x{descriptor.flags:x} "
            f"records={len(records)}"
        )
        for record in sample:
            suffix = ""
            if drip_program is not None:
                open_flag = (
                    args.force_open_flag
                    if args.force_open_flag is not None
                    else (descriptor.flags & 1)
                )
                state = drip_program.build_filter_state(record.key, open_flag)
                suffix = f" open_flag={open_flag} state={state[:16].hex()}..."
            print(
                f"  #{record.record_index}: xp3_index={record.xp3_entry_index} "
                f"name={record.xp3_name!r} packed=0x{record.packed:x} "
                f"key=0x{record.key & U64_MASK:016x}{suffix}"
            )

    if args.output:
        output = payloads[0] if len(payloads) == 1 else payloads
        args.output.write_text(
            json.dumps(output, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"wrote Hxv4 metadata to {args.output}")

    if args.states_output:
        output = state_payloads[0] if len(state_payloads) == 1 else state_payloads
        args.states_output.write_text(
            json.dumps(output, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"wrote filter states to {args.states_output}")

    if len(args.paths) > 1:
        print(f"total_hxv4_records={total}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    summary = sub.add_parser("summary", help="summarize XP3 archives")
    summary.add_argument("paths", nargs="+", type=Path)
    summary.add_argument("--samples", type=int, default=0)
    summary.add_argument("--visible-limit", type=int, default=12)
    summary.set_defaults(func=command_summary)

    find = sub.add_parser("find", help="find entries by case-insensitive substring")
    find.add_argument("name")
    find.add_argument("paths", nargs="+", type=Path)
    find.set_defaults(func=command_find)

    extract = sub.add_parser("extract", help="extract one named entry")
    extract.add_argument("archive", type=Path)
    extract.add_argument("name")
    extract.add_argument("output", type=Path)
    extract.add_argument(
        "--filter",
        choices=("auto", "none", "recovered"),
        default="auto",
        help="auto rejects entries that need the unrecovered runtime filter; none writes raw post-zlib bytes",
    )
    extract.add_argument("--drip-program", type=Path)
    extract.add_argument("--force-open-flag", type=int, choices=(0, 1))
    extract.set_defaults(func=command_extract)

    verify = sub.add_parser("verify", help="verify extracted payloads against XP3 adlr")
    verify.add_argument("paths", nargs="+", type=Path)
    verify.add_argument(
        "--filter",
        choices=("auto", "none", "recovered"),
        default="auto",
        help="auto reports entries that need the unrecovered runtime filter",
    )
    verify.add_argument("--include-warning", action="store_true")
    verify.add_argument("--verbose", action="store_true")
    verify.add_argument("--drip-program", type=Path)
    verify.add_argument("--force-open-flag", type=int, choices=(0, 1))
    verify.add_argument(
        "--max-entries",
        type=int,
        help="verify at most this many non-warning entries per archive",
    )
    verify.set_defaults(func=command_verify)

    extract_all = sub.add_parser("extract-all", help="extract all directly recoverable entries")
    extract_all.add_argument("output", type=Path)
    extract_all.add_argument("paths", nargs="+", type=Path)
    extract_all.add_argument(
        "--filter",
        choices=("auto", "none", "recovered"),
        default="auto",
        help="auto skips entries that need the unrecovered runtime filter; none writes raw post-zlib bytes",
    )
    extract_all.add_argument("--include-warning", action="store_true")
    extract_all.add_argument("--drip-program", type=Path)
    extract_all.add_argument("--force-open-flag", type=int, choices=(0, 1))
    extract_all.set_defaults(func=command_extract_all)

    dump_json = sub.add_parser("json", help="write archive index metadata as JSON")
    dump_json.add_argument("archive", type=Path)
    dump_json.add_argument("output", type=Path)
    dump_json.set_defaults(func=command_json)

    hxv4 = sub.add_parser(
        "hxv4",
        help="decrypt and parse the game-specific Hxv4 archive mapping table",
    )
    hxv4.add_argument("paths", nargs="+", type=Path)
    hxv4.add_argument("--samples", type=int, default=5)
    hxv4.add_argument("--output", type=Path)
    hxv4.add_argument(
        "--drip-program",
        type=Path,
        help="JSON exported by inspect_manager_dump.py with DripValue lane programs",
    )
    hxv4.add_argument(
        "--states-output",
        type=Path,
        help="write compact per-resource filter state JSON",
    )
    hxv4.add_argument(
        "--force-open-flag",
        type=int,
        choices=(0, 1),
        help="override the low-bit open flag used before BuildFilterStateFromUniqueKey",
    )
    hxv4.set_defaults(func=command_hxv4)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (OSError, XP3Error, zlib.error, struct.error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
