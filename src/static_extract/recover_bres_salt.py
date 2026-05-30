#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parents[1]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from common.decrypt_bres_resource import decrypt_bres
from common.pe_image import PeImage, find_resource
from static_extract.bres_bootstrap import (
    DEFAULT_SALT_RVA,
    DEFAULT_STARTUP_RESOURCE,
    DEFAULT_TEXT_RESOURCE,
    SALT_SIZE,
    decode_bres_root,
    parse_int,
    parse_resource_ref,
)


def verify_salt(salt: bytes, startup_cipher: bytes, startup_key: str) -> bool:
    if len(salt) != SALT_SIZE:
        return False
    try:
        return decrypt_bres(startup_cipher, startup_key, salt)[:8] == b"TJS2100\0"
    except Exception:
        return False


def read_at(path: Path, offset: int) -> bytes | None:
    if offset < 0:
        return None
    with path.open("rb") as f:
        f.seek(offset)
        data = f.read(SALT_SIZE)
    return data if len(data) == SALT_SIZE else None


def candidate_offsets(args: argparse.Namespace, source_size: int) -> list[tuple[str, int]]:
    offsets: list[tuple[str, int]] = []
    if args.file_offset is not None:
        offsets.append((f"file offset 0x{args.file_offset:x}", args.file_offset))
    if args.va is not None and args.image_base is not None:
        offsets.append((f"VA 0x{args.va:x} with image base 0x{args.image_base:x}", args.va - args.image_base))
    if args.rva is not None:
        offsets.append((f"flat RVA/file offset 0x{args.rva:x}", args.rva))

    seen: set[int] = set()
    unique: list[tuple[str, int]] = []
    for label, offset in offsets:
        if 0 <= offset <= source_size - SALT_SIZE and offset not in seen:
            seen.add(offset)
            unique.append((label, offset))
    return unique


def scan_file(
    path: Path,
    startup_cipher: bytes,
    startup_key: str,
    *,
    alignment: int,
) -> tuple[int, bytes] | None:
    data = path.read_bytes()
    if len(data) < SALT_SIZE:
        return None
    step = max(1, alignment)
    for offset in range(0, len(data) - SALT_SIZE + 1, step):
        salt = data[offset : offset + SALT_SIZE]
        if verify_salt(salt, startup_cipher, startup_key):
            return offset, salt
    return None


def load_startup_probe(
    exe_path: Path,
    startup_resource: tuple[object, object],
    text_resource: tuple[object, object],
) -> tuple[bytes, str]:
    exe = PeImage(exe_path)
    resources = exe.resources()
    startup_cipher = find_resource(resources, *startup_resource)
    startup_key = decode_bres_root(find_resource(resources, *text_resource))
    return startup_cipher, startup_key


def try_pe_rva(path: Path, rva: int) -> tuple[int, bytes] | None:
    image = PeImage(path)
    offset = image.rva_to_offset(rva)
    salt = image.data[offset : offset + SALT_SIZE]
    if len(salt) != SALT_SIZE:
        return None
    return offset, salt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Extract and verify the 8192-byte bres salt for this bres resource encryption family."
    )
    parser.add_argument("--exe", type=Path, required=True, help="target PE used as the STARTUP.TJS probe")
    parser.add_argument("--source", type=Path, action="append", help="unpacked image or memory dump to read")
    parser.add_argument("--out", type=Path, default=Path("bres_salt.bin"))
    parser.add_argument("--va", type=parse_int, help="virtual address of the salt in a flat memory dump")
    parser.add_argument("--image-base", type=parse_int, help="image base for --va, for example 0xC60000")
    parser.add_argument("--rva", type=parse_int, help="read salt at flat RVA/file offset from source")
    parser.add_argument("--file-offset", type=parse_int, help="read salt at exact file offset from source")
    parser.add_argument(
        "--pe-rva",
        type=parse_int,
        default=DEFAULT_SALT_RVA,
        help="map this PE RVA through source section headers; default matches known samples in this family",
    )
    parser.add_argument(
        "--startup-resource",
        type=parse_resource_ref,
        default=DEFAULT_STARTUP_RESOURCE,
        help="resource TYPE/NAME for encrypted STARTUP.TJS; default 10/STARTUP.TJS",
    )
    parser.add_argument(
        "--text-resource",
        type=parse_resource_ref,
        default=DEFAULT_TEXT_RESOURCE,
        help="resource TYPE/NAME containing the bres root URL; default TEXT/127",
    )
    parser.add_argument(
        "--scan",
        action="store_true",
        help="scan source files for an aligned 8192-byte block that decrypts STARTUP.TJS",
    )
    parser.add_argument("--scan-alignment", type=parse_int, default=0x1000)
    args = parser.parse_args(argv)

    startup_cipher, startup_key = load_startup_probe(args.exe, args.startup_resource, args.text_resource)
    sources = args.source or [args.exe]

    for source in sources:
        source = source.resolve()
        if not source.exists():
            print(f"[-] source not found: {source}")
            continue

        source_size = source.stat().st_size
        if args.pe_rva is not None:
            try:
                result = try_pe_rva(source, args.pe_rva)
            except Exception as exc:
                print(f"[-] {source}: PE RVA 0x{args.pe_rva:x}: {exc}")
            else:
                if result is not None:
                    offset, salt = result
                    if verify_salt(salt, startup_cipher, startup_key):
                        args.out.parent.mkdir(parents=True, exist_ok=True)
                        args.out.write_bytes(salt)
                        print(f"[+] recovered salt from {source} PE RVA 0x{args.pe_rva:x} / file offset 0x{offset:x}")
                        print(f"[+] wrote {args.out} sha256={hashlib.sha256(salt).hexdigest()}")
                        return 0
                    print(f"[-] {source}: PE RVA 0x{args.pe_rva:x} did not verify")

        for label, offset in candidate_offsets(args, source_size):
            salt = read_at(source, offset)
            if salt is None:
                continue
            if verify_salt(salt, startup_cipher, startup_key):
                args.out.parent.mkdir(parents=True, exist_ok=True)
                args.out.write_bytes(salt)
                print(f"[+] recovered salt from {source} {label} / file offset 0x{offset:x}")
                print(f"[+] wrote {args.out} sha256={hashlib.sha256(salt).hexdigest()}")
                return 0
            print(f"[-] {source}: {label} did not verify")

        if args.scan:
            found = scan_file(source, startup_cipher, startup_key, alignment=args.scan_alignment)
            if found is not None:
                offset, salt = found
                args.out.parent.mkdir(parents=True, exist_ok=True)
                args.out.write_bytes(salt)
                print(f"[+] recovered salt from {source} scan offset 0x{offset:x}")
                print(f"[+] wrote {args.out} sha256={hashlib.sha256(salt).hexdigest()}")
                return 0
            print(f"[-] {source}: scan did not find a verifying salt")

    print("[!] no valid salt recovered")
    print("    For the packed Steam EXE alone this is expected; provide an unpacked main image/dump or IDA-exported bytes.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
