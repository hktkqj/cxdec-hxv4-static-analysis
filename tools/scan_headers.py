#!/usr/bin/env python3
"""Scan extracted .bin files and classify by file header."""
from __future__ import annotations

import argparse
import collections
import glob
import os
import sys

def classify(header: bytes) -> str:
    if header[:8] == b'TJS2100\x00':
        return 'TJS2 bytecode (.tjs)'
    if header[:4] == b'\x89PNG':
        return 'PNG image (.png)'
    if header[:3] == b'\xff\xd8\xff':
        return 'JPEG image (.jpg)'
    if header[:4] == b'TLG0' or header[:6] == b'TLG5.0':
        return 'TLG image (.tlg)'
    if header[:4] == b'OggS':
        return 'OGG audio (.ogg)'
    if header[:4] == b'RIFF':
        return 'RIFF/WAVE audio (.wav)'
    if header[:4] == b'Opus':
        return 'Opus audio (.opus)'
    if header[:4] == b'AMV1':
        return 'AMV video (.amv)'
    if header[:2] == b'MZ':
        return 'PE/DLL executable'
    if header[:4] == b'\x1b\x4c\x4a\x01':
        return 'KAG scenario (.ks)'
    if header[:4] == b'XBND':
        return 'XBND bundle'
    if header[:4] == b'PSB\x00':
        return 'PSB (Painter Scribble)'
    if header[:4] == b'mdf\x00':
        return 'MDF container (zlib compressed)'
    if header[:7] == b'TJS/4s0':
        return 'TJS compiled script data'
    if header[:4] == b'OTTO':
        return 'OTTO font/data format'
    if header.startswith(b'TVP pre-rendered'):
        return 'TVP pre-rendered data'
    if header[:3] == b'#2.' or header.startswith(b'# 2.'):
        return 'SLI loop info text (.sli)'
    if header[:4] == b'\x00\x01\x00\x00' and header[12:16] == b'GSUB':
        return 'TrueType/OpenType font (.ttf/.otf)'
    if header[:4] == b'\x30\x26\xb2\x75':
        return 'WMV/ASF video (.wmv)'
    if header[:2] == b'\xfe\xfe' and len(header) >= 5 and header[3:5] == b'\xff\xfe':
        mode = header[2]
        mode_names = {0: 'mode0_xor', 1: 'mode1_bitswap', 2: 'mode2_zlib'}
        mode_str = mode_names.get(mode, f'mode{mode}')
        return f'Kirikiri scrambled UTF-16LE text ({mode_str})'
    if header[:4] == b'\x00\x00\x00\x00':
        if len(set(header[:32])) == 1:
            return 'All zeros (encrypted/unfiltered?)'
        return 'Null-padded binary'
    if len(header) == 0:
        return 'Empty file'
    return f'Unknown ({header[:16].hex(" ")})'


def scan_directory(base: str, output_file: str | None = None) -> int:
    """Scan a base directory for .bin files and classify by header.

    Expects directory layout: <base>/<name>/<name>/*.bin
    Returns the grand total of scanned files.
    """
    lines: list[str] = []
    grand_total = 0

    for dirname in sorted(os.listdir(base)):
        dirpath = os.path.join(base, dirname)
        if not os.path.isdir(dirpath):
            continue
        subdir = os.path.join(dirpath, dirname)
        if not os.path.isdir(subdir):
            continue

        bins = glob.glob(os.path.join(subdir, '*.bin'))
        if not bins:
            continue

        results = collections.Counter()
        unknowns = collections.defaultdict(list)  # type_label -> [paths]
        for b in sorted(bins):
            with open(b, 'rb') as f:
                header = f.read(64)
            label = classify(header)
            results[label] += 1
            if label.startswith('Unknown') or label.startswith('Empty'):
                unknowns[label].append(b)

        total = sum(results.values())
        grand_total += total
        lines.append(f'\n=== {dirname} ({total} files) ===')
        for ftype, count in results.most_common():
            lines.append(f'  {count:>6}  {ftype}')

        if unknowns:
            lines.append(f'\n  --- 未知/无法识别的文件路径: ---')
            for label, paths in sorted(unknowns.items()):
                for p in paths:
                    lines.append(f'  [{label}]  {p}')

    lines.append(f'\n{"="*50}')
    lines.append(f'GRAND TOTAL: {grand_total} files')

    output = '\n'.join(lines)
    print(output)

    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(output + '\n')
        print(f'\nResults saved to: {output_file}')

    return grand_total


def main():
    parser = argparse.ArgumentParser(
        description='Scan extracted .bin files and classify by file header.'
    )
    parser.add_argument(
        '-i', '--input',
        required=True,
        help='Base directory containing extracted archives (layout: <base>/<name>/<name>/*.bin)',
    )
    parser.add_argument(
        '-o', '--output',
        default=None,
        help='Optional output file path to save scan results',
    )
    args = parser.parse_args()

    base = args.input
    if not os.path.isdir(base):
        print(f'Error: input directory not found: {base}', file=sys.stderr)
        sys.exit(1)

    scan_directory(base, args.output)


if __name__ == '__main__':
    main()
