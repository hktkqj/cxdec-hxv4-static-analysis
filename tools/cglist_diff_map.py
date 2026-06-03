#!/usr/bin/env python3
"""Resolve CG tags from cglist.csv through imagediffmap.csv.

The output is a Python-literal dictionary:

    {"EV103AA": ("EV103A", "AA"), ...}

Rows in cglist.csv use the first column as the thumbnail name and the remaining
columns as CG tags. Rows beginning with ':' are page/group markers.
"""
from __future__ import annotations

import argparse
import ast
import csv
import json
import pprint
import sys
from pathlib import Path
from typing import Iterable


DEFAULT_CGLIST = Path(r"Temp\unscramble\allage\entry_00002_5002.txt")
DEFAULT_IMAGEDIFFMAP = Path(r"Temp\unscramble\data\entry_03344_5d0f.txt")


def read_text(path: Path) -> str:
    data = path.read_bytes()
    for encoding in ("utf-8-sig", "utf-16", "cp932"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def iter_csv_rows(path: Path) -> Iterable[list[str]]:
    text = read_text(path)
    reader = csv.reader(text.splitlines())
    for row in reader:
        cleaned = [col.strip() for col in row]
        if not cleaned:
            continue
        first = cleaned[0]
        if first == "" or first.startswith("#"):
            continue
        yield cleaned


def parse_imagediffmap(path: Path) -> dict[str, tuple[str, str]]:
    """Return case-insensitive CG tag -> (base file, diff tag)."""
    result: dict[str, tuple[str, str]] = {}
    for row in iter_csv_rows(path):
        if len(row) < 2:
            continue
        tag = row[0]
        base = row[1]
        attrs = {row[i].lower(): row[i + 1] for i in range(2, len(row) - 1, 2)}
        result[tag.lower()] = (base, attrs.get("diff", ""))
    return result


def parse_cg_cell(cell: str) -> list[str]:
    """Extract CG file-like tags from one cglist cell.

    This follows the common subset used by CgGalleryMode.parseItem:
    - strip unlock flag suffix after '?'
    - split optional composite specs after '|'
    - remove leading '*' marker on composite base entries
    - strip optional '<x:y:pos>' placement suffix
    """
    cell = cell.strip()
    if not cell:
        return []
    cell = cell.split("?", 1)[0].strip()
    tags: list[str] = []
    for part in cell.split("|"):
        part = part.strip()
        if not part:
            continue
        if part.startswith("*"):
            part = part[1:].strip()
        if "<" in part:
            part = part.split("<", 1)[0].strip()
        if part:
            tags.append(part)
    return tags


def parse_cglist(path: Path) -> list[str]:
    tags: list[str] = []
    seen: set[str] = set()
    for row in iter_csv_rows(path):
        if not row:
            continue
        first = row[0]
        if first.startswith(":") or first.startswith("*"):
            continue
        for cell in row[1:]:
            for tag in parse_cg_cell(cell):
                key = tag.lower()
                if key not in seen:
                    seen.add(key)
                    tags.append(tag)
    return tags


def resolve_cglist(
    cglist_path: Path,
    imagediffmap_path: Path,
    *,
    include_unmapped: bool = True,
) -> tuple[dict[str, tuple[str, str]], list[str]]:
    diffmap = parse_imagediffmap(imagediffmap_path)
    resolved: dict[str, tuple[str, str | None]] = {}
    unresolved: list[str] = []
    for tag in parse_cglist(cglist_path):
        mapped = diffmap.get(tag.lower())
        if mapped is None:
            unresolved.append(tag)
            if include_unmapped:
                resolved[tag] = (tag, "")
        else:
            resolved[tag] = mapped
    return resolved, unresolved


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Resolve CG tags in cglist.csv to (BASE_FILE, DIFFTAG) using imagediffmap.csv."
    )
    parser.add_argument("cglist", nargs="?", type=Path, default=DEFAULT_CGLIST)
    parser.add_argument("imagediffmap", nargs="?", type=Path, default=DEFAULT_IMAGEDIFFMAP)
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit JSON instead of a Python dict literal; tuples become arrays",
    )
    parser.add_argument(
        "--only-mapped",
        action="store_true",
        help="omit CG tags that are not present in imagediffmap",
    )
    parser.add_argument(
        "--no-stats",
        action="store_true",
        help="do not print summary stats to stderr",
    )
    parser.add_argument(
        "--assert",
        dest="expected",
        type=Path,
        help="compare the resolved dictionary with a Python-literal expected file",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    resolved, unresolved = resolve_cglist(
        args.cglist,
        args.imagediffmap,
        include_unmapped=not args.only_mapped,
    )

    if args.expected is not None:
        expected = ast.literal_eval(read_text(args.expected))
        if resolved != expected:
            print("resolved dictionary does not match expected file", file=sys.stderr)
            return 1

    if args.json:
        print(json.dumps(resolved, ensure_ascii=False, indent=2))
    else:
        pprint.pp(resolved, sort_dicts=False, width=120)

    if not args.no_stats:
        print(
            f"resolved={len(resolved)} unresolved={len(unresolved)}",
            file=sys.stderr,
        )
        if unresolved:
            preview = ", ".join(unresolved[:20])
            suffix = " ..." if len(unresolved) > 20 else ""
            print(f"unresolved tags: {preview}{suffix}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
