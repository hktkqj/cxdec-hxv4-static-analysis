#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import zlib
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parents[1]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from common.decrypt_bres_resource import decrypt_bres
from common.pe_image import PeImage, find_resource
from common.resource_hash import file_hash, path_hash
from static_extract.bres_bootstrap import (
    DEFAULT_BOOTSTRAP_RESOURCE,
    DEFAULT_BOOTSTRAP_ZLIB_OFFSET,
    DEFAULT_STARTUP_RESOURCE,
    DEFAULT_TABLE_RVA,
    DEFAULT_TEXT_RESOURCE,
    bres_key_from_url,
    choose_dotnet_x86,
    decode_bres_root,
    derive_drip_program,
    find_bootstrap_prefix,
    find_bootstrap_url,
    iter_auto_salt_candidates,
    load_salt,
    parse_config_table,
    parse_int,
    parse_resource_ref,
    parse_tjs_strings,
    require_config,
    salt_args_are_explicit,
    write_file,
)


def debug(args: argparse.Namespace, message: str) -> None:
    if args.debug:
        print(f"[debug] {message}")


def build_parser(repo_root: Path) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Recover System.bootStrap inputs from a game EXE, derive the runtime "
            "hash_key, and compute optional pathHash/fileHash values."
        )
    )
    parser.add_argument("--exe", type=Path, required=True, help="target PE file that provides game resources")
    parser.add_argument("--work-dir", type=Path, default=repo_root / "data" / "hash_probe")
    parser.add_argument("--out", type=Path, help="optional JSON summary output path")
    parser.add_argument("--drip-out", type=Path, help="derived manager JSON path; defaults to work-dir/drip_program.json")
    parser.add_argument("--pathname", action="append", default=[], help="logical pathname to hash; may be repeated")
    parser.add_argument("--filename", action="append", default=[], help="logical filename to hash; may be repeated")
    parser.add_argument("--pathname-extra", help="optional second TJS string appended before pathHash")
    parser.add_argument("--filename-extra", help="optional second TJS string appended before fileHash")
    parser.add_argument(
        "--keyed",
        action="store_true",
        help="experimental: use System.bootStrap hash_key as the SipHash/BLAKE2s key; default matches this DLL and uses key length 0",
    )
    parser.add_argument(
        "--salt-file",
        type=Path,
        help="read the 8192-byte bres salt from this file; overrides --salt-source-exe and --salt-rva",
    )
    parser.add_argument(
        "--salt-source-exe",
        "--runtime-exe",
        dest="salt_source_exe",
        type=Path,
        help="program image used only for salt extraction; defaults to --exe when salt source is explicit",
    )
    parser.add_argument("--salt-rva", type=parse_int, help="explicitly read salt from this PE RVA")
    parser.add_argument(
        "--salt-file-offset",
        type=parse_int,
        help="read salt at an exact file offset from --salt-source-exe/--exe instead of mapping --salt-rva",
    )
    parser.add_argument(
        "--table-rva",
        type=parse_int,
        default=DEFAULT_TABLE_RVA,
        help="BOOTSTRAP DLL config table RVA",
    )
    parser.add_argument(
        "--startup-resource",
        type=parse_resource_ref,
        default=DEFAULT_STARTUP_RESOURCE,
        help="resource TYPE/NAME for encrypted STARTUP.TJS; default 10/STARTUP.TJS",
    )
    parser.add_argument(
        "--bootstrap-resource",
        type=parse_resource_ref,
        default=DEFAULT_BOOTSTRAP_RESOURCE,
        help="resource TYPE/NAME for encrypted BOOTSTRAP; default 10/BOOTSTRAP",
    )
    parser.add_argument(
        "--text-resource",
        type=parse_resource_ref,
        default=DEFAULT_TEXT_RESOURCE,
        help="resource TYPE/NAME containing the bres root URL; default TEXT/127",
    )
    parser.add_argument(
        "--bootstrap-zlib-offset",
        type=parse_int,
        default=DEFAULT_BOOTSTRAP_ZLIB_OFFSET,
        help="bytes to skip before zlib-decompressing BOOTSTRAP payload; default 8",
    )
    parser.add_argument("--dotnet-x86", type=Path)
    parser.add_argument("--debug", action="store_true", help="print recovery diagnostics")
    return parser


def decrypt_startup(args: argparse.Namespace, startup_cipher: bytes, startup_key: str, salt: bytes) -> tuple[bytes, bytes, str]:
    startup_plain = decrypt_bres(startup_cipher, startup_key, salt)
    if startup_plain[:8] == b"TJS2100\0":
        return startup_plain, salt, "selected"

    if salt_args_are_explicit(args):
        raise ValueError("STARTUP.TJS did not decrypt to TJS2100")

    salt_source_path = args.salt_source_exe or args.exe
    for candidate in iter_auto_salt_candidates(PeImage(salt_source_path)):
        candidate_plain = decrypt_bres(startup_cipher, startup_key, candidate.salt)
        if candidate_plain[:8] == b"TJS2100\0":
            return candidate_plain, candidate.salt, candidate.source_label(salt_source_path)
    raise ValueError("STARTUP.TJS did not decrypt to TJS2100")


def recover_bootstrap(args: argparse.Namespace, repo_root: Path) -> dict[str, object]:
    work_dir: Path = args.work_dir
    work_dir.mkdir(parents=True, exist_ok=True)

    exe = PeImage(args.exe)
    resources = exe.resources()
    startup_cipher = find_resource(resources, *args.startup_resource)
    bootstrap_cipher = find_resource(resources, *args.bootstrap_resource)
    text_resource = find_resource(resources, *args.text_resource)
    salt, salt_source = load_salt(args)

    startup_key = decode_bres_root(text_resource)
    startup_plain, salt, auto_salt_source = decrypt_startup(args, startup_cipher, startup_key, salt)
    if auto_salt_source != "selected":
        salt_source = auto_salt_source
    debug(args, f"STARTUP.TJS decrypted bytes={len(startup_plain)}")

    strings = parse_tjs_strings(startup_plain)
    bootstrap_url = find_bootstrap_url(strings)
    bootstrap_key = bres_key_from_url(bootstrap_url)
    bootstrap_prefix = find_bootstrap_prefix(strings)

    bootstrap_plain = decrypt_bres(bootstrap_cipher, bootstrap_key, salt)
    try:
        dll_bytes = zlib.decompress(bootstrap_plain[args.bootstrap_zlib_offset :])
    except zlib.error as exc:
        raise ValueError(
            "BOOTSTRAP decrypted but did not zlib-decompress; check salt, bootstrap key, or --bootstrap-zlib-offset"
        ) from exc
    if dll_bytes[:2] != b"MZ":
        raise ValueError("decompressed BOOTSTRAP payload is not a PE DLL")
    debug(args, f"BOOTSTRAP decrypted bytes={len(bootstrap_plain)} dll_bytes={len(dll_bytes)}")

    dll_path = work_dir / "bootstrap.dll"
    write_file(work_dir / "bres_salt.bin", salt)
    write_file(work_dir / "STARTUP.TJS.dec", startup_plain)
    write_file(work_dir / "BOOTSTRAP.dec", bootstrap_plain)
    write_file(dll_path, dll_bytes)

    config = parse_config_table(dll_path, args.table_rva)
    warning = require_config(config, "WARNING").decode("ascii")
    archive_unique_key = require_config(config, "UNIQUE").decode("utf-16le")
    final_bootstrap = bootstrap_prefix + warning
    debug(args, f"DLL config labels={','.join(sorted(config))}")

    drip_path = args.drip_out or (work_dir / "drip_program.json")
    derive_drip_program(
        repo_root=repo_root,
        dotnet_x86=choose_dotnet_x86(args.dotnet_x86),
        dll_path=dll_path,
        output=drip_path,
        bootstrap_prefix=bootstrap_prefix,
        archive_text=archive_unique_key,
    )
    drip = json.loads(drip_path.read_text(encoding="utf-8"))
    if not drip.get("hash_key"):
        raise ValueError("derived JSON does not contain hash_key; rebuild tools/FilterManagerDerive")

    return {
        "exe": str(args.exe),
        "work_dir": str(work_dir),
        "salt_source": salt_source,
        "startup_key": startup_key,
        "bootstrap_url": bootstrap_url,
        "bootstrap_key": bootstrap_key,
        "bootstrap_prefix": bootstrap_prefix,
        "warning": warning,
        "final_bootstrap": final_bootstrap,
        "archive_unique_key": archive_unique_key,
        "bootstrap_dll": str(dll_path),
        "drip_program": str(drip_path),
        "hash_key": drip["hash_key"],
        "path_hash_key": drip["hash_key"][:32],
        "file_hash_key": drip["hash_key"],
        "hxv4_key": drip.get("hxv4_key"),
        "hxv4_nonce0": drip.get("hxv4_nonce0"),
        "hxv4_nonce1": drip.get("hxv4_nonce1"),
    }


def main(argv: list[str] | None = None) -> int:
    repo_root = Path(__file__).resolve().parents[2]
    args = build_parser(repo_root).parse_args(argv)
    summary = recover_bootstrap(args, repo_root)
    hash_key = bytes.fromhex(str(summary["hash_key"]))

    path_results = []
    for pathname in args.pathname:
        digest = path_hash(pathname, hash_key, args.pathname_extra, keyed=args.keyed).hex()
        path_results.append({"pathname": pathname, "path_hash": digest})

    file_results = []
    for filename in args.filename:
        digest = file_hash(filename, hash_key, args.filename_extra, keyed=args.keyed).hex()
        file_results.append({"filename": filename, "file_hash": digest})

    summary["path_hashes"] = path_results
    summary["file_hashes"] = file_results
    summary["hasher_keyed"] = args.keyed

    out_path = args.out or (args.work_dir / "resource_hash.summary.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"bootstrap_prefix: {summary['bootstrap_prefix']}")
    print(f"warning: {summary['warning']}")
    print(f"final_bootstrap: {summary['final_bootstrap']}")
    print(f"hash_key: {summary['hash_key']}")
    print(f"path_hash_key: {summary['path_hash_key']}")
    print(f"file_hash_key: {summary['file_hash_key']}")
    print(f"hasher_keyed: {args.keyed}")
    for item in path_results:
        print(f"pathHash({item['pathname']}): {item['path_hash']}")
    for item in file_results:
        print(f"fileHash({item['filename']}): {item['file_hash']}")
    print(f"summary: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
