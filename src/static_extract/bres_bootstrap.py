from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from common.pe_image import PeImage, read_file_offset, u16, u32
from common.tjs2_inspect import parse_chunks, parse_data_chunk


DEFAULT_TABLE_RVA = 0x80E38
DEFAULT_DOTNET_X86 = Path(r"C:\Program Files (x86)\dotnet\dotnet.exe")
DEFAULT_STARTUP_RESOURCE = (10, "STARTUP.TJS")
DEFAULT_BOOTSTRAP_RESOURCE = (10, "BOOTSTRAP")
DEFAULT_TEXT_RESOURCE = ("TEXT", 127)
DEFAULT_PLUGIN_RESOURCE = (10, "PLUGIN")
DEFAULT_BOOTSTRAP_ZLIB_OFFSET = 8
SALT_SIZE = 0x2000


@dataclass(frozen=True)
class SaltCandidate:
    kind: str
    salt_offset: int
    salt: bytes
    salt_rva: int | None = None
    salt_va: int | None = None
    code_rva: int | None = None
    ptr_global_va: int | None = None
    size_global_va: int | None = None
    anchor_offset: int | None = None
    anchor_rva: int | None = None
    anchor_name: str | None = None

    def source_label(self, path: Path) -> str:
        salt_parts = []
        if self.salt_va is not None:
            salt_parts.append(f"VA 0x{self.salt_va:x}")
        if self.salt_rva is not None:
            salt_parts.append(f"RVA 0x{self.salt_rva:x}")
        salt_parts.append(f"file offset 0x{self.salt_offset:x}")
        salt_desc = " / ".join(salt_parts)

        if self.kind == "code_assignment":
            code = f"code RVA 0x{self.code_rva:x}" if self.code_rva is not None else "code assignment"
            return f"{path}:auto {code} salt {salt_desc}"

        anchor = self.anchor_name or "packed-neighborhood"
        if self.anchor_rva is not None:
            return f"{path}:auto {anchor} anchor RVA 0x{self.anchor_rva:x} salt {salt_desc}"
        if self.anchor_offset is not None:
            return f"{path}:auto {anchor} anchor file offset 0x{self.anchor_offset:x} salt {salt_desc}"
        return f"{path}:auto {anchor} salt {salt_desc}"


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


def salt_args_are_explicit(args: argparse.Namespace) -> bool:
    return (
        args.salt_file is not None
        or args.salt_file_offset is not None
        or args.salt_rva is not None
    )


def _offset_location(image: PeImage, offset: int) -> tuple[int | None, int | None]:
    try:
        rva = image.offset_to_rva(offset)
    except ValueError:
        return None, None
    return rva, image.image_base + rva


def _make_salt_candidate(
    image: PeImage,
    *,
    kind: str,
    salt_offset: int,
    seen: set[int],
    code_rva: int | None = None,
    ptr_global_va: int | None = None,
    size_global_va: int | None = None,
    anchor_offset: int | None = None,
    anchor_name: str | None = None,
) -> SaltCandidate | None:
    if salt_offset in seen or salt_offset < 0 or salt_offset + SALT_SIZE > len(image.data):
        return None
    salt_rva, salt_va = _offset_location(image, salt_offset)
    if salt_rva is None:
        return None
    anchor_rva = None
    if anchor_offset is not None:
        anchor_rva, _ = _offset_location(image, anchor_offset)
    seen.add(salt_offset)
    return SaltCandidate(
        kind=kind,
        salt_offset=salt_offset,
        salt_rva=salt_rva,
        salt_va=salt_va,
        salt=image.data[salt_offset : salt_offset + SALT_SIZE],
        code_rva=code_rva,
        ptr_global_va=ptr_global_va,
        size_global_va=size_global_va,
        anchor_offset=anchor_offset,
        anchor_rva=anchor_rva,
        anchor_name=anchor_name,
    )


def iter_salt_assignment_candidates(image: PeImage) -> list[SaltCandidate]:
    """Find x86 static assignments of the bres salt pointer and 0x2000 size.

    Known samples initialize the bres salt globals with adjacent instructions:

        mov dword ptr [salt_ptr_global], offset salt_bytes
        mov dword ptr [salt_size_global], 2000h

    The global addresses move between games, but the immediate 0x2000 length
    and the PE-mapped salt pointer make a compact, verifiable signature.
    """

    data = image.data
    seen: set[int] = set()
    candidates: list[SaltCandidate] = []
    for off in range(0, max(0, len(data) - 20)):
        if data[off : off + 2] != b"\xC7\x05":
            continue
        ptr_global_va = u32(data, off + 2)
        salt_va = u32(data, off + 6)
        if salt_va < image.image_base:
            continue
        salt_rva = image.va_to_rva(salt_va)
        try:
            salt_offset = image.rva_to_offset(salt_rva)
        except ValueError:
            continue
        if salt_offset + SALT_SIZE > len(data):
            continue
        window_end = min(len(data) - 10, off + 64)
        for size_off in range(off + 10, window_end):
            if data[size_off : size_off + 2] != b"\xC7\x05":
                continue
            if u32(data, size_off + 6) != SALT_SIZE:
                continue
            if salt_offset in seen:
                break
            try:
                code_rva = image.offset_to_rva(off)
            except ValueError:
                code_rva = off
            candidate = _make_salt_candidate(
                image,
                kind="code_assignment",
                salt_offset=salt_offset,
                seen=seen,
                code_rva=code_rva,
                ptr_global_va=ptr_global_va,
                size_global_va=u32(data, size_off + 2),
            )
            if candidate is not None:
                candidates.append(candidate)
            break
    return candidates


def iter_packed_neighborhood_salt_candidates(image: PeImage) -> list[SaltCandidate]:
    """Find packed samples where the salt has no code xrefs in the original EXE.

    Sanoba/CafeStella packed images keep the 0x2000-byte salt in .rdata near:

        UTF-16 "TEXT", UTF-16 "yes", ASCII "forcedataxp3", UTF-16 "no"

    In these samples the salt often starts shortly after the marker cluster and
    ends immediately before an ASCII "V2Link" string.  Candidates from this
    heuristic are intentionally verified later by decrypting STARTUP.TJS.
    """

    data = image.data
    seen: set[int] = set()
    candidates: list[SaltCandidate] = []

    def add(offset: int, anchor_offset: int, anchor_name: str) -> None:
        candidate = _make_salt_candidate(
            image,
            kind="packed_neighborhood",
            salt_offset=offset,
            seen=seen,
            anchor_offset=anchor_offset,
            anchor_name=anchor_name,
        )
        if candidate is not None:
            candidates.append(candidate)

    marker = b"V2Link\x00\x00"
    cursor = 0
    while True:
        anchor = data.find(marker, cursor)
        if anchor < 0:
            break
        add(anchor - SALT_SIZE, anchor, "V2Link-before")
        cursor = anchor + 1

    marker = b"forcedataxp3\x00"
    cursor = 0
    while True:
        anchor = data.find(marker, cursor)
        if anchor < 0:
            break
        window_start = (anchor + len(marker) + 0xF) & ~0xF
        window_end = min(anchor + 0x100, len(data) - SALT_SIZE)
        for offset in range(window_start, window_end + 1, 0x10):
            add(offset, anchor, "forcedataxp3-near")
        cursor = anchor + 1

    return candidates


def iter_auto_salt_candidates(image: PeImage) -> list[SaltCandidate]:
    seen_offsets: set[int] = set()
    candidates: list[SaltCandidate] = []
    for candidate in [
        *iter_salt_assignment_candidates(image),
        *iter_packed_neighborhood_salt_candidates(image),
    ]:
        if candidate.salt_offset in seen_offsets:
            continue
        seen_offsets.add(candidate.salt_offset)
        candidates.append(candidate)
    return candidates


def load_salt(args: argparse.Namespace) -> tuple[bytes, str]:
    explicit_salt_file = args.salt_file is not None
    explicit_salt_source = args.salt_file_offset is not None or args.salt_rva is not None

    if explicit_salt_file:
        salt_path = args.salt_file
        salt = salt_path.read_bytes()
        salt_source = str(salt_path)
    elif explicit_salt_source:
        if args.salt_file_offset is not None:
            salt = read_file_offset(args.exe, args.salt_file_offset, SALT_SIZE)
            salt_source = f"{args.exe}:file offset 0x{args.salt_file_offset:x}"
        else:
            salt_image = PeImage(args.exe)
            salt = salt_image.read_rva(args.salt_rva, SALT_SIZE)
            salt_source = f"{args.exe}:RVA 0x{args.salt_rva:x}"
    else:
        salt_image = PeImage(args.exe)
        candidates = iter_auto_salt_candidates(salt_image)
        if not candidates:
            raise ValueError(
                "could not locate bres salt from code assignments or packed data-neighborhood; "
                "pass --salt-rva, --salt-file-offset, or --salt-file"
            )
        candidate = candidates[0]
        salt = candidate.salt
        salt_source = candidate.source_label(args.exe)

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


def decompile_tjs2(repo_root: Path, input_path: Path, output_path: Path) -> str:
    tool = repo_root / "tools" / "tjs2-decompiler" / "tjs2_decompiler.py"
    if not tool.exists():
        raise ValueError(f"could not find TJS2 decompiler: {tool}")
    try:
        completed = subprocess.run(
            [sys.executable, str(tool), str(input_path), "-o", str(output_path), "-e", "utf-8"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        details = (exc.stderr or exc.stdout or "").strip()
        suffix = f": {details}" if details else ""
        raise ValueError(f"could not decompile STARTUP.TJS bytecode{suffix}") from exc
    if completed.stderr:
        print(completed.stderr, file=sys.stderr, end="")
    return output_path.read_text(encoding="utf-8-sig")


def _skip_tjs_space(source: str, offset: int) -> int:
    while offset < len(source) and source[offset].isspace():
        offset += 1
    return offset


def _read_tjs_string_literal(source: str, offset: int) -> tuple[str, int]:
    quote = source[offset]
    if quote not in ("'", '"'):
        raise ValueError("TJS string literal must start with a quote")
    offset += 1
    result: list[str] = []
    while offset < len(source):
        char = source[offset]
        offset += 1
        if char == quote:
            return "".join(result), offset
        if char != "\\":
            result.append(char)
            continue
        if offset >= len(source):
            break
        escape = source[offset]
        offset += 1
        if escape == "n":
            result.append("\n")
        elif escape == "r":
            result.append("\r")
        elif escape == "t":
            result.append("\t")
        elif escape == "b":
            result.append("\b")
        elif escape == "f":
            result.append("\f")
        elif escape == "v":
            result.append("\v")
        elif escape in ("\\", "'", '"'):
            result.append(escape)
        elif escape == "x" and offset + 2 <= len(source):
            result.append(chr(int(source[offset : offset + 2], 16)))
            offset += 2
        elif escape == "u" and offset + 4 <= len(source):
            result.append(chr(int(source[offset : offset + 4], 16)))
            offset += 4
        else:
            result.append(escape)
    raise ValueError("unterminated TJS string literal")


def find_bootstrap_prefix_from_source(source: str) -> str:
    needle = "_bootStrap"
    offset = 0
    while True:
        index = source.find(needle, offset)
        if index < 0:
            break
        offset = index + len(needle)
        call_start = _skip_tjs_space(source, offset)
        if call_start >= len(source) or source[call_start] != "(":
            continue
        first_arg = _skip_tjs_space(source, call_start + 1)
        if first_arg < len(source) and source[first_arg] in ("'", '"'):
            return _read_tjs_string_literal(source, first_arg)[0]
    raise ValueError("could not find System.bootStrap prefix string in STARTUP.TJS source")


def iter_bootstrap_prefix_candidates(strings: list[str]) -> list[str]:
    seen: set[str] = set()
    candidates: list[str] = []
    for value in strings:
        if not value or value in seen or "all" not in value.casefold():
            continue
        seen.add(value)
        candidates.append(value)
    return candidates


def find_bootstrap_prefix(strings: list[str]) -> str:
    candidates = iter_bootstrap_prefix_candidates(strings)
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        raise ValueError("could not find System.bootStrap prefix string with 'all' in STARTUP.TJS strings")

    reserved = [
        value
        for value in candidates
        if "right" in value.casefold() or "reserved" in value.casefold()
    ]
    if len(reserved) == 1:
        return reserved[0]
    if reserved:
        candidates = reserved

    preview = ", ".join(repr(value) for value in candidates[:5])
    raise ValueError(
        "ambiguous System.bootStrap prefix string in STARTUP.TJS strings; "
        f"{len(candidates)} candidates contain 'all': {preview}"
    )


def _filter_manager_tool_paths(repo_root: Path) -> tuple[Path, Path]:
    project = repo_root / "tools" / "FilterManagerDerive" / "FilterManagerDerive.csproj"
    tool = project.parent / "bin" / "Debug" / "net8.0" / "FilterManagerDerive.dll"
    return project, tool


def ensure_filter_manager_derive(repo_root: Path) -> Path:
    csproj, tool = _filter_manager_tool_paths(repo_root)
    source_files = list(csproj.parent.glob("*.cs")) + [csproj]
    needs_build = not tool.exists() or any(path.stat().st_mtime > tool.stat().st_mtime for path in source_files)
    if needs_build:
        run_command(["dotnet", "build", str(csproj), "-p:PlatformTarget=x86"], repo_root)
    return tool


def _filter_manager_derive_args(
    *,
    tool: Path,
    dotnet_x86: Path,
    dll_path: Path,
    output: Path,
    bootstrap_prefix: str,
    archive_text: str,
) -> list[str]:
    return [
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
    ]


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
    tool = ensure_filter_manager_derive(repo_root)
    run_command(
        _filter_manager_derive_args(
            tool=tool,
            dotnet_x86=dotnet_x86,
            dll_path=dll_path,
            output=output,
            bootstrap_prefix=bootstrap_prefix,
            archive_text=archive_text,
        ),
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
