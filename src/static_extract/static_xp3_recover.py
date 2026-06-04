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
from common.pe_image import PeImage, find_optional_resource, find_resource
from static_extract.bres_bootstrap import (
    DEFAULT_BOOTSTRAP_RESOURCE,
    DEFAULT_BOOTSTRAP_ZLIB_OFFSET,
    DEFAULT_PLUGIN_RESOURCE,
    DEFAULT_STARTUP_RESOURCE,
    DEFAULT_TABLE_RVA,
    DEFAULT_TEXT_RESOURCE,
    bres_key_from_url,
    choose_dotnet_x86,
    decode_bres_root,
    decompile_tjs2,
    derive_drip_program,
    find_bootstrap_prefix,
    find_bootstrap_prefix_from_source,
    find_bootstrap_url,
    iter_auto_salt_candidates,
    load_salt,
    parse_config_table,
    parse_int,
    parse_resource_ref,
    parse_tjs_strings,
    require_config,
    run_xp3_action,
    salt_args_are_explicit,
    write_file,
)


def debug(args: argparse.Namespace, message: str) -> None:
    if getattr(args, "debug", False):
        print(f"[debug] {message}")


def build_parser(repo_root: Path) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Recover XP3 keys for this bres/BOOTSTRAP/Hxv4 encryption family from static files."
    )
    parser.add_argument(
        "--exe",
        type=Path,
        required=True,
        help="target game EXE; supplies resources and is also used for bres salt lookup",
    )
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=repo_root / "data" / "static_recover",
        help="directory for recovered intermediate files; default: data/static_recover",
    )
    parser.add_argument(
        "--out",
        type=Path,
        help="output drip_program.json path; default: work-dir/drip_program.json",
    )
    parser.add_argument(
        "--salt-file",
        type=Path,
        help="read the 8192-byte bres salt from this file instead of locating it in --exe",
    )
    parser.add_argument(
        "--salt-rva",
        type=parse_int,
        help="read the bres salt from this RVA in --exe; accepts decimal or 0x-prefixed values",
    )
    parser.add_argument(
        "--salt-file-offset",
        type=parse_int,
        help="read the bres salt from this file offset in --exe; accepts decimal or 0x-prefixed values",
    )
    parser.add_argument(
        "--table-rva",
        type=parse_int,
        default=DEFAULT_TABLE_RVA,
        help="BOOTSTRAP DLL config table RVA; default matches known samples in this family",
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
        "--plugin-resource",
        type=parse_resource_ref,
        default=DEFAULT_PLUGIN_RESOURCE,
        help="optional resource TYPE/NAME copied for diagnostics; default 10/PLUGIN",
    )
    parser.add_argument(
        "--bootstrap-zlib-offset",
        type=parse_int,
        default=DEFAULT_BOOTSTRAP_ZLIB_OFFSET,
        help="bytes to skip before zlib-decompressing BOOTSTRAP payload; default 8",
    )
    parser.add_argument(
        "--dotnet-x86",
        type=Path,
        help="path to the x86 dotnet executable used by FilterManagerDerive; auto-detected when omitted",
    )
    parser.add_argument(
        "--skip-derive",
        action="store_true",
        help="stop after recovering/decompressing resources and parsing DLL config; do not create drip_program.json",
    )
    parser.add_argument(
        "--xp3",
        nargs="*",
        type=Path,
        help="optional XP3 archives passed to xp3_inspect.py for verification or extraction after derivation",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="verify --xp3 archives with the recovered filter state after creating drip_program.json",
    )
    parser.add_argument(
        "--verify-max-entries",
        type=int,
        help="when --verify is used, verify at most this many non-warning entries per XP3 archive",
    )
    parser.add_argument(
        "--extract-output",
        type=Path,
        help="output directory for xp3_inspect.py extract-all; requires --xp3 and a derived drip_program.json",
    )
    parser.add_argument("--debug", action="store_true", help="print stage-level recovery diagnostics")
    return parser


def main(argv: list[str] | None = None) -> int:
    repo_root = Path(__file__).resolve().parents[2]
    args = build_parser(repo_root).parse_args(argv)

    work_dir: Path = args.work_dir
    work_dir.mkdir(parents=True, exist_ok=True)
    debug(args, f"work_dir={work_dir}")

    exe = PeImage(args.exe)
    debug(args, f"loaded PE: sections={len(exe.sections)} resource_rva=0x{exe.resource_rva:x}")
    resources = exe.resources()
    debug(args, f"resources={len(resources)}")
    startup_cipher = find_resource(resources, *args.startup_resource)
    bootstrap_cipher = find_resource(resources, *args.bootstrap_resource)
    plugin_resource = find_optional_resource(resources, *args.plugin_resource)
    text_resource = find_resource(resources, *args.text_resource)
    salt, salt_source = load_salt(args)
    debug(
        args,
        "resource sizes: "
        f"STARTUP.TJS={len(startup_cipher)} BOOTSTRAP={len(bootstrap_cipher)} "
        f"PLUGIN={len(plugin_resource) if plugin_resource is not None else 0} salt={len(salt)}",
    )

    startup_key = decode_bres_root(text_resource)
    startup_plain = decrypt_bres(startup_cipher, startup_key, salt)
    if startup_plain[:8] != b"TJS2100\0":
        if salt_args_are_explicit(args):
            raise ValueError("STARTUP.TJS did not decrypt to TJS2100")
        for candidate in iter_auto_salt_candidates(PeImage(args.exe)):
            candidate_plain = decrypt_bres(startup_cipher, startup_key, candidate.salt)
            if candidate_plain[:8] == b"TJS2100\0":
                salt = candidate.salt
                salt_source = candidate.source_label(args.exe)
                startup_plain = candidate_plain
                debug(args, f"auto salt matched: {salt_source}")
                break
        else:
            raise ValueError("STARTUP.TJS did not decrypt to TJS2100")
    debug(args, f"STARTUP.TJS decrypted bytes={len(startup_plain)}")

    startup_plain_path = work_dir / "STARTUP.TJS.dec"
    startup_source_path = work_dir / "STARTUP.TJS"
    bootstrap_plain_path = work_dir / "BOOTSTRAP.dec"
    dll_path = work_dir / "bootstrap.dll"
    drip_path = args.out or (work_dir / "drip_program.json")

    write_file(work_dir / "bres_salt.bin", salt)
    write_file(work_dir / "STARTUP_TJS.rcdata.bin", startup_cipher)
    write_file(startup_plain_path, startup_plain)
    try:
        startup_source = decompile_tjs2(repo_root, startup_plain_path, startup_source_path)
    except ValueError as exc:
        debug(args, f"{exc}; STARTUP.TJS source output unavailable")
        startup_source = None

    strings = parse_tjs_strings(startup_plain)
    bootstrap_url = find_bootstrap_url(strings)
    bootstrap_key = bres_key_from_url(bootstrap_url)
    bootstrap_plain = decrypt_bres(bootstrap_cipher, bootstrap_key, salt)
    try:
        dll_bytes = zlib.decompress(bootstrap_plain[args.bootstrap_zlib_offset :])
    except zlib.error as exc:
        raise ValueError(
            "BOOTSTRAP decrypted but did not zlib-decompress. "
            "Check the bootstrap key, --bootstrap-zlib-offset, salt, or payload format."
        ) from exc
    if dll_bytes[:2] != b"MZ":
        raise ValueError("decompressed BOOTSTRAP payload is not a PE DLL; check --bootstrap-zlib-offset or format")
    debug(args, f"BOOTSTRAP decrypted bytes={len(bootstrap_plain)} dll_bytes={len(dll_bytes)}")

    write_file(work_dir / "BOOTSTRAP.rcdata.bin", bootstrap_cipher)
    write_file(bootstrap_plain_path, bootstrap_plain)
    write_file(dll_path, dll_bytes)
    if plugin_resource is not None:
        write_file(work_dir / "PLUGIN.rcdata.bin", plugin_resource)

    config = parse_config_table(dll_path, args.table_rva)
    unique = require_config(config, "UNIQUE").decode("utf-16le")
    warning = require_config(config, "WARNING").decode("ascii")
    try:
        if startup_source is None:
            raise ValueError("STARTUP.TJS source is unavailable")
        bootstrap_prefix = find_bootstrap_prefix_from_source(startup_source)
        debug(args, "bootstrap_prefix source=STARTUP.TJS decompiled _bootStrap call")
    except ValueError as exc:
        debug(args, f"{exc}; falling back to STARTUP.TJS string-pool 'all' candidates")
        bootstrap_prefix = find_bootstrap_prefix(strings)
        debug(args, "bootstrap_prefix source=STARTUP.TJS string-pool 'all' candidate")
    final_bootstrap = bootstrap_prefix + warning
    debug(args, f"DLL config labels={','.join(sorted(config))}")

    summary = {
        "exe": str(args.exe),
        "salt_source": salt_source,
        "startup_key": startup_key,
        "bootstrap_url": bootstrap_url,
        "bootstrap_key": bootstrap_key,
        "bootstrap_prefix": bootstrap_prefix,
        "warning": warning,
        "final_bootstrap": final_bootstrap,
        "archive_unique_key": unique,
        "outputs": {
            "work_dir": str(work_dir),
            "startup_dec": str(startup_plain_path),
            "startup_source": str(startup_source_path),
            "bootstrap_dec": str(bootstrap_plain_path),
            "dll": str(dll_path),
            "drip_program": str(drip_path),
        },
    }
    (work_dir / "static_recover.summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    debug(args, f"summary={work_dir / 'static_recover.summary.json'}")

    print(f"startup_key: {startup_key}")
    print(f"bootstrap_key: {bootstrap_key}")
    print(f"salt_source: {salt_source}")
    print(f"bootstrap_prefix: {bootstrap_prefix}")
    print(f"archive_unique_key: {unique}")
    print(f"work_dir: {work_dir}")

    if not args.skip_derive:
        derive_drip_program(
            repo_root=repo_root,
            dotnet_x86=choose_dotnet_x86(args.dotnet_x86),
            dll_path=dll_path,
            output=drip_path,
            bootstrap_prefix=bootstrap_prefix,
            archive_text=unique,
        )
        payload = json.loads(drip_path.read_text(encoding="utf-8"))
        print(f"hxv4_key: {payload.get('hxv4_key')}")
        print(f"hxv4_nonce0: {payload.get('hxv4_nonce0')}")
        print(f"hxv4_nonce1: {payload.get('hxv4_nonce1')}")
        run_xp3_action(repo_root, args, drip_path)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
