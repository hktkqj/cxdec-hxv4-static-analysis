from __future__ import annotations

import hashlib
import struct


def _rotl64(value: int, count: int) -> int:
    return ((value << count) | (value >> (64 - count))) & 0xFFFFFFFFFFFFFFFF


def _sip_round(v0: int, v1: int, v2: int, v3: int) -> tuple[int, int, int, int]:
    v0 = (v0 + v1) & 0xFFFFFFFFFFFFFFFF
    v1 = _rotl64(v1, 13)
    v1 ^= v0
    v0 = _rotl64(v0, 32)
    v2 = (v2 + v3) & 0xFFFFFFFFFFFFFFFF
    v3 = _rotl64(v3, 16)
    v3 ^= v2
    v0 = (v0 + v3) & 0xFFFFFFFFFFFFFFFF
    v3 = _rotl64(v3, 21)
    v3 ^= v0
    v2 = (v2 + v1) & 0xFFFFFFFFFFFFFFFF
    v1 = _rotl64(v1, 17)
    v1 ^= v2
    v2 = _rotl64(v2, 32)
    return v0, v1, v2, v3


def siphash24(data: bytes, key: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError(f"SipHash key must be 16 bytes, got {len(key)}")

    k0, k1 = struct.unpack_from("<QQ", key)
    v0 = k0 ^ 0x736F6D6570736575
    v1 = k1 ^ 0x646F72616E646F6D
    v2 = k0 ^ 0x6C7967656E657261
    v3 = k1 ^ 0x7465646279746573

    end = len(data) - (len(data) % 8)
    for offset in range(0, end, 8):
        message = struct.unpack_from("<Q", data, offset)[0]
        v3 ^= message
        v0, v1, v2, v3 = _sip_round(v0, v1, v2, v3)
        v0, v1, v2, v3 = _sip_round(v0, v1, v2, v3)
        v0 ^= message

    tail = data[end:]
    final = len(data) << 56
    for index, value in enumerate(tail):
        final |= value << (8 * index)

    v3 ^= final
    v0, v1, v2, v3 = _sip_round(v0, v1, v2, v3)
    v0, v1, v2, v3 = _sip_round(v0, v1, v2, v3)
    v0 ^= final
    v2 ^= 0xFF
    for _ in range(4):
        v0, v1, v2, v3 = _sip_round(v0, v1, v2, v3)

    return struct.pack("<Q", (v0 ^ v1 ^ v2 ^ v3) & 0xFFFFFFFFFFFFFFFF)


def tjs_string_bytes(value: str) -> bytes:
    return value.encode("utf-16le")


def path_hash(pathname: str, hash_key: bytes = b"", extra: str | None = None, *, keyed: bool = False) -> bytes:
    data = tjs_string_bytes(pathname)
    if extra:
        data += tjs_string_bytes(extra)
    key = hash_key[:16] if keyed else bytes(16)
    return siphash24(data, key)


def file_hash(filename: str, hash_key: bytes = b"", extra: str | None = None, *, keyed: bool = False) -> bytes:
    data = tjs_string_bytes(filename)
    if extra:
        data += tjs_string_bytes(extra)
    if keyed:
        return hashlib.blake2s(data, digest_size=32, key=hash_key[:32]).digest()
    return hashlib.blake2s(data, digest_size=32).digest()
