#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import struct
import subprocess
import sys
import zlib
from dataclasses import dataclass
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parents[1]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from common.decrypt_bres_resource import decrypt_bres
from common.tjs2_inspect import parse_chunks, parse_data_chunk


DEFAULT_SALT_RVA = 0x2E4A00
DEFAULT_TABLE_RVA = 0x80E38
DEFAULT_DOTNET_X86 = Path(r"C:\Program Files (x86)\dotnet\dotnet.exe")
DEFAULT_STARTUP_RESOURCE = (10, "STARTUP.TJS")
DEFAULT_BOOTSTRAP_RESOURCE = (10, "BOOTSTRAP")
DEFAULT_TEXT_RESOURCE = ("TEXT", 127)
DEFAULT_PLUGIN_RESOURCE = (10, "PLUGIN")
DEFAULT_BOOTSTRAP_ZLIB_OFFSET = 8
SALT_SIZE = 0x2000


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


def write_file(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def parse_int(value: str) -> int:
    return int(value, 0)


def parse_resource_component(value: str) -> object:
    try:
        return int(value, 0)
    except ValueError:
        return value


def parse_resource_ref(value: str) -> tuple[object, object]:
    parts = value.split("/")
    if len(parts) != 2:
        raise argparse.ArgumentTypeError("resource reference must be TYPE/NAME, for example 10/STARTUP.TJS")
    return parse_resource_component(parts[0]), parse_resource_component(parts[1])


def read_file_offset(path: Path, offset: int, size: int) -> bytes:
    if offset < 0:
        raise ValueError(f"negative file offset: 0x{offset:x}")
    with path.open("rb") as f:
        f.seek(offset)
        data = f.read(size)
    if len(data) != size:
        raise ValueError(f"{path}: offset 0x{offset:x} has {len(data)} bytes; expected {size}")
    return data


def load_salt(args: argparse.Namespace) -> tuple[bytes, str]:
    explicit_salt_file = args.salt_file is not None
    explicit_salt_source = (
        args.salt_source_exe is not None
        or args.salt_file_offset is not None
        or args.salt_rva != DEFAULT_SALT_RVA
    )

    if explicit_salt_file:
        salt_path = args.salt_file
        salt = salt_path.read_bytes()
        salt_source = str(salt_path)
    elif explicit_salt_source:
        salt_source_path = args.salt_source_exe or args.exe
        if args.salt_file_offset is not None:
            salt = read_file_offset(salt_source_path, args.salt_file_offset, SALT_SIZE)
            salt_source = f"{salt_source_path}:file offset 0x{args.salt_file_offset:x}"
        else:
            salt_image = PeImage(salt_source_path)
            salt = salt_image.read_rva(args.salt_rva, SALT_SIZE)
            salt_source = f"{salt_source_path}:RVA 0x{args.salt_rva:x}"
    else:
        salt = PeImage(args.exe).read_rva(args.salt_rva, SALT_SIZE)
        salt_source = f"{args.exe}:RVA 0x{args.salt_rva:x}"

    if len(salt) != SALT_SIZE:
        raise ValueError(f"{salt_source} is {len(salt)} bytes; expected {SALT_SIZE}")
    return salt, salt_source


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


def decode_bres_root(text_resource: bytes) -> str:
    text = text_resource.decode("utf-16le", errors="strict").rstrip("\0")
    marker = "bres://./"
    if not text.startswith(marker):
        raise ValueError(f"unexpected bres root: {text!r}")
    return text[len(marker) :].strip("/")


def parse_tjs_strings(data: bytes) -> list[str]:
    for chunk in parse_chunks(data):
        if chunk.tag == "DATA":
            pools = parse_data_chunk(chunk)
            return list(pools["strings"])
    raise ValueError("TJS bytecode has no DATA chunk")


def bres_key_from_url(url: str) -> str:
    marker = "bres://./"
    if not url.startswith(marker):
        raise ValueError(f"not a local bres URL: {url!r}")
    rest = url[len(marker) :]
    return rest.split("/", 1)[0]


def find_bootstrap_url(strings: list[str]) -> str:
    for value in strings:
        if value.startswith("bres://./") and value.lower().endswith("/bootstrap"):
            return value
    raise ValueError("could not find bootstrap bres URL in STARTUP.TJS strings")


def find_bootstrap_prefix(strings: list[str]) -> str:
    for value in strings:
        if "All Rights Reserved." in value:
            return value
    raise ValueError("could not find System.bootStrap prefix string in STARTUP.TJS strings")


def parse_config_table(dll_path: Path, table_rva: int) -> dict[str, bytes]:
    image = PeImage(dll_path)
    off = image.rva_to_offset(table_rva)
    result: dict[str, bytes] = {}
    cursor = off
    while cursor < len(image.data):
        end = image.data.find(b"\0", cursor)
        if end < 0:
            raise ValueError("unterminated DLL config label")
        label = image.data[cursor:end].decode("ascii", errors="strict")
        cursor = end + 1
        if not label:
            break
        length = u16(image.data, cursor)
        cursor += 2
        result[label] = image.data[cursor : cursor + length]
        cursor += length
    return result


def require_config(config: dict[str, bytes], label: str) -> bytes:
    try:
        return config[label]
    except KeyError as exc:
        labels = ", ".join(sorted(config)) or "<none>"
        raise ValueError(
            f"DLL config label {label!r} was not found; available labels: {labels}. "
            "Check --table-rva or the BOOTSTRAP DLL layout."
        ) from exc


def choose_dotnet_x86(explicit: Path | None) -> Path:
    if explicit is not None:
        return explicit
    if DEFAULT_DOTNET_X86.exists():
        return DEFAULT_DOTNET_X86
    found = shutil.which("dotnet")
    if found:
        return Path(found)
    raise ValueError("could not find dotnet; pass --dotnet-x86")


def run_command(args: list[str], cwd: Path) -> None:
    print("+", " ".join(args))
    subprocess.run(args, cwd=cwd, check=True)


def debug(args: argparse.Namespace, message: str) -> None:
    if getattr(args, "debug", False):
        print(f"[debug] {message}")


def derive_drip_program(
    *,
    repo_root: Path,
    dotnet_x86: Path,
    dll_path: Path,
    output: Path,
    bootstrap_prefix: str,
    archive_text: str,
) -> None:
    tool = repo_root / "tools" / "FilterManagerDerive" / "bin" / "Debug" / "net8.0" / "FilterManagerDerive.dll"
    if not tool.exists():
        csproj = repo_root / "tools" / "FilterManagerDerive" / "FilterManagerDerive.csproj"
        run_command(["dotnet", "build", str(csproj), "-p:PlatformTarget=x86"], repo_root)

    run_command(
        [
            str(dotnet_x86),
            str(tool),
            "--dll",
            str(dll_path),
            "--out",
            str(output),
            "--bootstrap-prefix",
            bootstrap_prefix,
            "--archive-text",
            archive_text,
        ],
        repo_root,
    )


def run_xp3_action(repo_root: Path, args: argparse.Namespace, drip_program: Path) -> None:
    if not args.xp3:
        return
    xp3_args = [str(path) for path in args.xp3]
    if args.verify:
        verify_args = []
        if args.verify_max_entries is not None:
            verify_args = ["--max-entries", str(args.verify_max_entries)]
        run_command(
            [
                sys.executable,
                str(repo_root / "src" / "common" / "xp3_inspect.py"),
                "verify",
                "--filter",
                "recovered",
                "--drip-program",
                str(drip_program),
                *verify_args,
                *xp3_args,
            ],
            repo_root,
        )
    if args.extract_output:
        run_command(
            [
                sys.executable,
                str(repo_root / "src" / "common" / "xp3_inspect.py"),
                "extract-all",
                str(args.extract_output),
                "--filter",
                "recovered",
                "--drip-program",
                str(drip_program),
                *xp3_args,
            ],
            repo_root,
        )


def main(argv: list[str] | None = None) -> int:
    repo_root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(
        description="Recover XP3 keys for this bres/BOOTSTRAP/Hxv4 encryption family from static files."
    )
    parser.add_argument("--exe", type=Path, required=True, help="target PE file that provides game resources")
    parser.add_argument("--work-dir", type=Path, default=repo_root / "data" / "static_recover")
    parser.add_argument("--out", type=Path, help="output drip_program.json path; defaults to work-dir/drip_program.json")
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
    parser.add_argument(
        "--salt-rva",
        type=parse_int,
        default=DEFAULT_SALT_RVA,
        help="read salt from this PE RVA in the salt source; default matches known samples in this family",
    )
    parser.add_argument(
        "--salt-file-offset",
        type=parse_int,
        help="read salt at an exact file offset from --salt-source-exe/--exe instead of mapping --salt-rva",
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
    parser.add_argument("--dotnet-x86", type=Path)
    parser.add_argument("--skip-derive", action="store_true")
    parser.add_argument("--xp3", nargs="*", type=Path, help="optional XP3 archives to verify or extract")
    parser.add_argument("--verify", action="store_true", help="verify XP3 entries with recovered filter state")
    parser.add_argument(
        "--verify-max-entries",
        type=int,
        help="when --verify is used, verify at most this many non-warning entries per XP3 archive",
    )
    parser.add_argument("--extract-output", type=Path, help="optional output directory for xp3_inspect extract-all")
    parser.add_argument("--debug", action="store_true", help="print stage-level recovery diagnostics")
    args = parser.parse_args(argv)

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
    text_127 = find_resource(resources, *args.text_resource)
    salt, salt_source = load_salt(args)
    debug(
        args,
        "resource sizes: "
        f"STARTUP.TJS={len(startup_cipher)} BOOTSTRAP={len(bootstrap_cipher)} "
        f"PLUGIN={len(plugin_resource) if plugin_resource is not None else 0} salt={len(salt)}",
    )

    startup_key = decode_bres_root(text_127)
    startup_plain = decrypt_bres(startup_cipher, startup_key, salt)
    if startup_plain[:8] != b"TJS2100\0":
        raise ValueError("STARTUP.TJS did not decrypt to TJS2100")
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
            "BOOTSTRAP decrypted but did not zlib-decompress. "
            "Check the bootstrap key, --bootstrap-zlib-offset, salt, or payload format."
        ) from exc
    if dll_bytes[:2] != b"MZ":
        raise ValueError("decompressed BOOTSTRAP payload is not a PE DLL; check --bootstrap-zlib-offset or format")
    debug(args, f"BOOTSTRAP decrypted bytes={len(bootstrap_plain)} dll_bytes={len(dll_bytes)}")

    salt_path = work_dir / "bres_salt.bin"
    startup_cipher_path = work_dir / "STARTUP_TJS.rcdata.bin"
    startup_plain_path = work_dir / "STARTUP.TJS.dec"
    bootstrap_cipher_path = work_dir / "BOOTSTRAP.rcdata.bin"
    bootstrap_plain_path = work_dir / "BOOTSTRAP.dec"
    dll_path = work_dir / "bootstrap.dll"
    drip_path = args.out or (work_dir / "drip_program.json")

    write_file(salt_path, salt)
    write_file(startup_cipher_path, startup_cipher)
    write_file(startup_plain_path, startup_plain)
    write_file(bootstrap_cipher_path, bootstrap_cipher)
    write_file(bootstrap_plain_path, bootstrap_plain)
    write_file(dll_path, dll_bytes)
    if plugin_resource is not None:
        write_file(work_dir / "PLUGIN.rcdata.bin", plugin_resource)

    config = parse_config_table(dll_path, args.table_rva)
    unique = require_config(config, "UNIQUE").decode("utf-16le")
    warning = require_config(config, "WARNING").decode("ascii")
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
