#!/usr/bin/env python3
"""Compute no-key resource hashes and optionally look them up in manifest.jsonl."""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

SRC_ROOT = Path(__file__).resolve().parents[1]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))
TOOLS_ROOT = Path(__file__).resolve().parents[2] / "tools"
if str(TOOLS_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOLS_ROOT))

from common.resource_hash import file_hash, path_hash
from scan_headers import classify

DEFAULT_EXTRA = "xp3hnp"

# Ordered from the most common runtime resource paths to broader fallback types.
# These come from Temp/TJS2 auto-extension probes plus explicit .mtn storage use.
DEFAULT_FILENAME_EXTENSIONS = (
    "png","tlg","tlg5","tlg6","jpeg","jpg","bmp","pimg","emf","wmf","psd","mtn",
    "wav","ogg","opus","tcw","sli","opus.sli","wmv",
    "mpg","mpeg","mp4","mpv","m1v","m2v","amv","swf",
    "csv","tsv","txt","tjs","ks","ini","func","pbd","psb","ttf","otf",
    "stand","event","sinfo",
)


@dataclass(frozen=True)
class LookupEntry:
    archive: str
    output: str
    filename_hash: str
    pathname_hash: str


class LookUp:
    """Lookup extracted resources by filename_hash from an extract-all manifest."""

    def __init__(self, manifest_path: Path):
        self.manifest_path = manifest_path
        self.entries: list[LookupEntry] = []
        self._by_filename_hash: dict[str, list[LookupEntry]] = {}
        self._load()

    @staticmethod
    def _norm_hash(value: object) -> str:
        return str(value or "").lower()

    @staticmethod
    def _norm_archive(value: str | None) -> str | None:
        return value.lower() if value is not None else None

    def _load(self) -> None:
        with self.manifest_path.open("r", encoding="utf-8") as handle:
            for lineno, line in enumerate(handle, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"{self.manifest_path}:{lineno}: invalid JSON") from exc

                filename_hash = self._norm_hash(item.get("filename_hash"))
                pathname_hash = self._norm_hash(item.get("pathname_hash"))
                if not filename_hash:
                    continue
                entry = LookupEntry(
                    archive=str(item.get("archive", "")),
                    output=str(item.get("output", "")),
                    filename_hash=filename_hash,
                    pathname_hash=pathname_hash,
                )
                self.entries.append(entry)
                self._by_filename_hash.setdefault(filename_hash, []).append(entry)

    def find(
        self,
        filename_hash: str,
        pathname_hash: str | None = None,
        archive: str | None = None,
    ) -> list[LookupEntry]:
        wanted_pathname_hash = self._norm_hash(pathname_hash) if pathname_hash is not None else None
        wanted_archive = self._norm_archive(archive)
        matches = self._by_filename_hash.get(self._norm_hash(filename_hash), [])
        if wanted_pathname_hash is not None:
            matches = [entry for entry in matches if entry.pathname_hash == wanted_pathname_hash]
        if wanted_archive is not None:
            matches = [entry for entry in matches if entry.archive.lower() == wanted_archive]
        return matches

    def exists(
        self,
        filename_hash: str,
        pathname_hash: str | None = None,
        archive: str | None = None,
    ) -> bool:
        return bool(self.find(filename_hash, pathname_hash=pathname_hash, archive=archive))


class Hasher:
    """No-key pathHash/fileHash helper for this game's Hxv4 lookup flow."""

    def __init__(
        self,
        pathname_extra: str | None = DEFAULT_EXTRA,
        filename_extra: str | None = DEFAULT_EXTRA,
        filename_extensions: tuple[str, ...] = DEFAULT_FILENAME_EXTENSIONS,
    ):
        self.pathname_extra = self.normalize(pathname_extra) if pathname_extra is not None else None
        self.filename_extra = self.normalize(filename_extra) if filename_extra is not None else None
        self.filename_extensions = tuple(self.normalize(ext).lstrip(".") for ext in filename_extensions)

    @staticmethod
    def normalize(value: str) -> str:
        return str(value).lower()

    @staticmethod
    def _has_extension(filename: str) -> bool:
        name = filename.replace("\\", "/").rsplit("/", 1)[-1]
        return "." in name and not name.endswith(".")

    @staticmethod
    def _dedupe(values: list[str]) -> list[str]:
        seen: set[str] = set()
        result: list[str] = []
        for value in values:
            value = value.lower()
            if value in seen:
                continue
            seen.add(value)
            result.append(value)
        return result

    def filename_candidates(self, filename: str) -> list[str]:
        normalized = self.normalize(filename)
        if self._has_extension(normalized):
            return [normalized]
        candidates = [normalized]
        candidates.extend(f"{normalized}.{ext}" for ext in self.filename_extensions)
        return self._dedupe(candidates)

    def path_hash(self, pathname: str) -> str:
        return path_hash(self.normalize(pathname), b"", self.pathname_extra, keyed=False).hex()

    def file_hash(self, filename: str) -> str:
        return file_hash(self.normalize(filename), b"", self.filename_extra, keyed=False).hex()


def parse_optional_extra(value: str | None) -> str | None:
    if value is None:
        return DEFAULT_EXTRA
    if value == "":
        return None
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Compute no-key pathHash/fileHash values and optionally look up filename_hash in manifest.jsonl."
    )
    parser.add_argument("--pathname", action="append", default=[], help="logical pathname to hash; may be repeated")
    parser.add_argument("--filename", action="append", default=[], help="logical filename to hash; may be repeated")
    parser.add_argument(
        "--pathname-extra",
        help='extra TJS string appended before pathHash; default "xp3hnp"; pass an empty string to disable',
    )
    parser.add_argument(
        "--filename-extra",
        help='extra TJS string appended before fileHash; default "xp3hnp"; pass an empty string to disable',
    )
    parser.add_argument("--manifest", type=Path, help="optional extract-all manifest.jsonl for filename_hash lookup")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of human-readable text")
    return parser


def detect_manifest_output(base_dir: Path, output: str) -> dict[str, object]:
    path = base_dir / output
    if not path.is_file():
        return {
            "detected": False,
            "path": str(path),
            "format": "missing output file",
            "size": None,
        }
    with path.open("rb") as handle:
        header = handle.read(64)
    return {
        "detected": True,
        "path": str(path),
        "format": classify(header),
        "size": path.stat().st_size,
    }


def lookup_entries(lookup: LookUp | None, filename_hash: str) -> list[dict[str, object]]:
    if lookup is None:
        return []
    base_dir = lookup.manifest_path.parent
    results: list[dict[str, object]] = []
    for entry in lookup.find(filename_hash):
        item: dict[str, object] = asdict(entry)
        item.update(detect_manifest_output(base_dir, entry.output))
        results.append(item)
    return results


def make_summary(args: argparse.Namespace) -> dict[str, object]:
    if not args.pathname and not args.filename:
        raise ValueError("at least one --pathname or --filename is required")

    hasher = Hasher(
        pathname_extra=parse_optional_extra(args.pathname_extra),
        filename_extra=parse_optional_extra(args.filename_extra),
    )
    lookup = LookUp(args.manifest) if args.manifest is not None else None

    path_results: list[dict[str, object]] = []
    for pathname in args.pathname:
        normalized = hasher.normalize(pathname)
        path_results.append(
            {
                "pathname": pathname,
                "normalized": normalized,
                "extra": hasher.pathname_extra,
                "pathname_hash": hasher.path_hash(pathname),
            }
        )

    file_results: list[dict[str, object]] = []
    for filename in args.filename:
        candidates = []
        for candidate in hasher.filename_candidates(filename):
            digest = hasher.file_hash(candidate)
            candidate_result: dict[str, object] = {
                "filename": candidate,
                "extra": hasher.filename_extra,
                "filename_hash": digest,
            }
            if lookup is not None:
                matches = lookup_entries(lookup, digest)
                if not matches:
                    continue
                candidate_result["matches"] = matches
            candidates.append(candidate_result)
        result_group: dict[str, object] = {
            "input": filename,
            "normalized": hasher.normalize(filename),
            "candidates": candidates,
        }
        if lookup is not None:
            result_group["matched"] = bool(candidates)
        file_results.append(result_group)

    return {
        "mode": "no_key",
        "manifest": str(args.manifest) if args.manifest is not None else None,
        "default_extra": DEFAULT_EXTRA,
        "path_hashes": path_results,
        "file_hashes": file_results,
    }


def print_text(summary: dict[str, object]) -> None:
    print("mode: no_key")
    if summary["manifest"] is not None:
        print(f"manifest: {summary['manifest']}")

    for item in summary["path_hashes"]:
        assert isinstance(item, dict)
        print(
            "pathHash({normalized!r}, extra={extra!r}): {pathname_hash}".format(
                normalized=item["normalized"],
                extra=item["extra"],
                pathname_hash=item["pathname_hash"],
            )
        )

    for group in summary["file_hashes"]:
        assert isinstance(group, dict)
        print(f"filename input: {group['input']} -> {group['normalized']}")
        if summary["manifest"] is not None and not group["candidates"]:
            print("  no manifest matches for generated filename candidates")
            continue
        for candidate in group["candidates"]:
            assert isinstance(candidate, dict)
            print(
                "  fileHash({filename!r}, extra={extra!r}): {filename_hash}".format(
                    filename=candidate["filename"],
                    extra=candidate["extra"],
                    filename_hash=candidate["filename_hash"],
                )
            )
            matches = candidate.get("matches")
            if matches:
                for match in matches:
                    print(
                        "    match: archive={archive} output={output} pathname_hash={pathname_hash}".format(
                            **match
                        )
                    )
                    print(
                        "      format: {format} size={size} path={path}".format(
                            **match
                        )
                    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    summary = make_summary(args)
    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    else:
        print_text(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
