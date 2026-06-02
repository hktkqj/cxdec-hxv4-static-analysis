#!/usr/bin/env python3
"""
Descramble Kirikiri scrambled UTF-16LE text files (FE FE xx FF FE header).

Based on: https://github.com/arcusmaximus/KirikiriTools/blob/master/KirikiriDescrambler/Descrambler.cs

Modes:
  0: XOR-based scramble (byte[i+1] ^= byte[i] & 0xFE; byte[i] ^= 1)
  1: Bit-swap scramble (swap adjacent bits of each 16-bit char)
  2: Zlib-compressed (DeflateStream)
"""
from __future__ import annotations

import argparse
import glob
import os
import struct
import sys
import zlib
from pathlib import Path
from collections import Counter


def descramble_mode0(data: bytes) -> bytes:
    """Mode 0: XOR descramble."""
    result = bytearray(data)
    for i in range(0, len(result) - 1, 2):
        if result[i + 1] == 0 and result[i] < 0x20:
            continue  # Skip control characters
        result[i + 1] ^= (result[i] & 0xFE)
        result[i] ^= 1
    return bytes(result)


def descramble_mode1(data: bytes) -> bytes:
    """Mode 1: Bit-swap descramble (symmetric — same op scrambles and descrambles)."""
    result = bytearray(data)
    for i in range(0, len(result) - 1, 2):
        # Read as little-endian 16-bit char
        c = result[i] | (result[i + 1] << 8)
        # Swap adjacent bits
        c = ((c & 0xAAAA) >> 1) | ((c & 0x5555) << 1)
        # Write back
        result[i] = c & 0xFF
        result[i + 1] = (c >> 8) & 0xFF
    return bytes(result)


def descramble_mode2(data: bytes) -> bytes:
    """Mode 2: Zlib decompress."""
    # Header: int64 compressed_len, int64 uncompressed_len, int16 zlib_header
    # Data starts at offset 18 (2+1+2+8+8+2 = ... wait, let me recheck)
    # Actually the Descrambler.cs reads: int64 compressedLength, int64 uncompressedLength, short zlibHeader
    # So offset = 2 (magic) + 1 (mode) + 2 (bom) + 8 + 8 + 2 = 23
    # But mode 2 is rare, implement based on Descrambler.cs
    raise NotImplementedError("Mode 2 (zlib) not yet implemented")


def descramble_file(path: Path) -> tuple[str | None, bytes | None, str]:
    """
    Descramble a file. Returns (mode_name, descrambled_bytes, error_reason).
    """
    with open(path, 'rb') as f:
        header = f.read(5)

    if len(header) < 5:
        return None, None, 'File too small'

    magic = header[:2]
    if magic != b'\xfe\xfe':
        return None, None, 'Not scrambled (bad magic)'

    mode = header[2]
    bom = header[3:5]
    if bom != b'\xff\xfe':
        return None, None, f'Bad BOM: {bom.hex()}'

    with open(path, 'rb') as f:
        f.seek(5)
        body = f.read()

    try:
        if mode == 0:
            descrambled = descramble_mode0(body)
            mode_name = 'mode0_xor'
        elif mode == 1:
            descrambled = descramble_mode1(body)
            mode_name = 'mode1_bitswap'
        elif mode == 2:
            descrambled = descramble_mode2(body)
            mode_name = 'mode2_zlib'
        else:
            return None, None, f'Unknown mode: {mode}'
    except Exception as e:
        return None, None, f'Descramble error: {e}'

    return mode_name, descrambled, ''


def descramble_all(base: Path, output: Path) -> tuple[int, int]:
    """Descramble all scrambled .bin files under base, writing results to output.

    Expects directory layout: <base>/<name>/<name>/*.bin
    Returns (ok_count, error_count).
    """
    output.mkdir(parents=True, exist_ok=True)

    # Auto-detect archive directories (same layout as scan_headers.py)
    all_files: list[Path] = []
    for dirname in sorted(base.iterdir()):
        if not dirname.is_dir():
            continue
        subdir = dirname / dirname.name
        if not subdir.is_dir():
            continue
        for f in sorted(subdir.glob('*.bin')):
            with open(f, 'rb') as fh:
                magic = fh.read(2)
            if magic == b'\xfe\xfe':
                all_files.append(f)

    print(f'Found {len(all_files)} scrambled files')
    print()

    stats = Counter()
    ok = 0
    err = 0

    for i, f in enumerate(all_files):
        rel = f.relative_to(base)
        archive = rel.parent.name
        out_dir = output / archive
        out_dir.mkdir(parents=True, exist_ok=True)

        mode_name, descrambled, error = descramble_file(f)
        if descrambled is None:
            print(f'  SKIP [{rel}]: {error}')
            err += 1
            continue

        # Save as .txt (UTF-16LE decoded to UTF-8 for readability)
        out_path_txt = out_dir / (f.stem + '.txt')
        try:
            text = descrambled.decode('utf-16-le')
            out_path_txt.write_text(text, encoding='utf-8')
        except UnicodeDecodeError:
            # Binary data — save raw
            out_path_txt.write_bytes(descrambled)

        # Save raw descrambled bytes as .bin
        out_path_bin = out_dir / (f.stem + '.descrambled.bin')
        out_path_bin.write_bytes(descrambled)

        stats[mode_name] += 1
        ok += 1

        if (i + 1) % 50 == 0:
            print(f'  [{i+1}/{len(all_files)}] ...')

    print(f'\nDone: {ok} ok, {err} errors, {len(all_files)} total')
    print(f'\nMode distribution:')
    for mode, count in stats.most_common():
        print(f'  {mode}: {count} files')
    print(f'\nOutput: {output}')

    # Show samples
    print('\n=== Sample descrambled text (first 200 chars) ===')
    sample_count = 0
    for txt in sorted(output.rglob('*.txt')):
        if sample_count >= 8:
            break
        try:
            content = txt.read_text(encoding='utf-8')[:300]
            rel = txt.relative_to(output)
            print(f'\n--- {rel} ---')
            print(content)
            sample_count += 1
        except Exception:
            pass

    return ok, err


def main():
    parser = argparse.ArgumentParser(
        description='Descramble Kirikiri scrambled UTF-16LE text files (FE FE xx FF FE header).'
    )
    parser.add_argument(
        '-i', '--input',
        required=True,
        help='Base directory containing extracted archives (layout: <base>/<name>/<name>/*.bin)',
    )
    parser.add_argument(
        '-o', '--output',
        required=True,
        help='Output directory for descrambled files',
    )
    args = parser.parse_args()

    base = Path(args.input)
    if not base.is_dir():
        print(f'Error: input directory not found: {base}', file=sys.stderr)
        sys.exit(1)

    output = Path(args.output)
    descramble_all(base, output)


if __name__ == '__main__':
    main()
