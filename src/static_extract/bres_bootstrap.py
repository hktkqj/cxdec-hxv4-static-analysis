from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

from common.pe_image import PeImage, read_file_offset, u16
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
