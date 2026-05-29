#!/usr/bin/env python3
from __future__ import annotations

import argparse
import struct
from dataclasses import dataclass
from pathlib import Path


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def i32(data: bytes, off: int) -> int:
    return struct.unpack_from("<i", data, off)[0]


def align4(value: int) -> int:
    return (value + 3) & ~3


@dataclass
class Chunk:
    tag: str
    offset: int
    size: int
    body: bytes


def parse_chunks(data: bytes) -> list[Chunk]:
    if len(data) < 12 or data[:8] != b"TJS2100\x00":
        raise ValueError("not a TJS2100 bytecode file")
    declared = u32(data, 8)
    if declared != len(data):
        print(f"warning: declared size {declared:#x} != file size {len(data):#x}")

    chunks: list[Chunk] = []
    off = 12
    while off + 8 <= len(data):
        tag = data[off : off + 4].decode("ascii", errors="replace")
        size = u32(data, off + 4)
        body_off = off + 8
        chunk_end = off + size
        if size < 8 or chunk_end > len(data):
            raise ValueError(f"chunk {tag} at {off:#x} exceeds file size")
        chunks.append(Chunk(tag, off, size, data[body_off:chunk_end]))
        off = chunk_end
    return chunks


def parse_data_chunk(chunk: Chunk) -> dict[str, object]:
    data = chunk.body
    p = 0

    def take_count(name: str, unit: int) -> list[int] | bytes:
        nonlocal p
        count = u32(data, p)
        p += 4
        size = count * unit
        raw = data[p : p + size]
        p += align4(size)
        if unit == 1:
            return raw
        if unit == 2:
            return list(struct.unpack_from(f"<{count}H", raw, 0)) if count else []
        if unit == 4:
            return list(struct.unpack_from(f"<{count}I", raw, 0)) if count else []
        if unit == 8:
            return list(struct.unpack_from(f"<{count}Q", raw, 0)) if count else []
        raise AssertionError(name)

    pools: dict[str, object] = {}
    pools["bytecode_literals"] = take_count("bytecode_literals", 1)
    pools["shorts"] = take_count("shorts", 2)
    pools["ints"] = take_count("ints", 4)
    pools["int64s"] = take_count("int64s", 8)
    pools["reals_raw"] = take_count("reals_raw", 8)

    strings: list[str] = []
    string_count = u32(data, p)
    p += 4
    for _ in range(string_count):
        length = u32(data, p)
        p += 4
        raw = data[p : p + 2 * length]
        p += align4(2 * length)
        strings.append(raw.decode("utf-16le", errors="replace"))
    pools["strings"] = strings

    octets: list[bytes] = []
    if p + 4 <= len(data):
        octet_count = u32(data, p)
        p += 4
        for _ in range(octet_count):
            length = u32(data, p)
            p += 4
            octets.append(data[p : p + length])
            p += align4(length)
    pools["octets"] = octets
    pools["parsed_size"] = p
    return pools


def parse_objs_chunk(chunk: Chunk) -> dict[str, object]:
    body = chunk.body
    result: dict[str, object] = {}
    if len(body) < 8:
        return result

    result["unknown0"] = i32(body, 0)
    result["object_count"] = u32(body, 4)
    objects = []
    p = 8
    for index in range(result["object_count"]):
        if p + 8 > len(body):
            break
        tag = body[p : p + 4].decode("ascii", errors="replace")
        size = u32(body, p + 4)
        obj_body = body[p + 8 : p + 8 + size]
        header_dwords = [
            i32(obj_body, off)
            for off in range(0, min(len(obj_body), 0x38), 4)
            if off + 4 <= len(obj_body)
        ]
        code_size = u32(obj_body, 0x34) if len(obj_body) >= 0x38 else 0
        code_start = 0x38
        code_end = min(len(obj_body), code_start + code_size)
        code_bytes = obj_body[code_start:code_end]
        code_words = list(struct.unpack_from(f"<{len(code_bytes)//2}H", code_bytes, 0))
        tail = obj_body[code_end:]
        dwords = [
            i32(obj_body, off)
            for off in range(0, min(len(obj_body), 64), 4)
            if off + 4 <= len(obj_body)
        ]
        objects.append(
            {
                "index": index,
                "tag": tag,
                "offset": chunk.offset + 8 + p,
                "size": size,
                "header_dwords": header_dwords,
                "code_size": code_size,
                "tail_size": len(tail),
                "first_dwords": dwords,
                "code_words": code_words,
                "tail_words": list(struct.unpack_from(f"<{len(tail)//2}H", tail, 0)),
            }
        )
        p += 8 + size
    result["objects"] = objects
    result["parsed_size"] = p
    return result


def inspect(path: Path) -> None:
    data = path.read_bytes()
    print(f"{path}: size={len(data):#x}")
    for chunk in parse_chunks(data):
        print(f"chunk {chunk.tag} offset={chunk.offset:#x} size={chunk.size:#x}")
        if chunk.tag == "DATA":
            pools = parse_data_chunk(chunk)
            for key in ("bytecode_literals", "shorts", "ints", "int64s", "reals_raw"):
                value = pools[key]
                print(f"  {key}: {len(value)}")
            print(f"  strings: {len(pools['strings'])}")
            for i, s in enumerate(pools["strings"]):
                print(f"    [{i}] {s!r}")
            print(f"  octets: {len(pools['octets'])}")
            print(f"  parsed DATA bytes: {pools['parsed_size']:#x}/{len(chunk.body):#x}")
        elif chunk.tag == "OBJS":
            objs = parse_objs_chunk(chunk)
            print(f"  unknown0={objs.get('unknown0')} object_count={objs.get('object_count')}")
            for obj in objs.get("objects", []):
                print(
                    f"  object[{obj['index']}] tag={obj['tag']} "
                    f"offset={obj['offset']:#x} size={obj['size']:#x}"
                )
                print(f"    header_dwords={obj['header_dwords']}")
                words = obj["code_words"]
                preview = " ".join(f"{w:04x}" for w in words)
                print(f"    code_size={obj['code_size']:#x} code_words={preview}")
                tail_preview = " ".join(f"{w:04x}" for w in obj["tail_words"][:48])
                print(f"    tail_size={obj['tail_size']:#x} tail_words[0:48]={tail_preview}")
            print(f"  parsed OBJS bytes: {objs.get('parsed_size'):#x}/{len(chunk.body):#x}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect Kirikiri TJS2100 bytecode containers.")
    parser.add_argument("paths", nargs="+", type=Path)
    args = parser.parse_args()
    for path in args.paths:
        inspect(path)


if __name__ == "__main__":
    main()
