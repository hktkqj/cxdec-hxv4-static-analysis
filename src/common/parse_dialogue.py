#!/usr/bin/env python3
"""
Sanoba Witch 对话文本解析器
解析 Kirikiri (KAG) 引擎的编译后 JSON 脚本，提取角色对话文本（多语言）。

输入: 包含 .ks.json 文件的目录
输出: 结构化的 JSON/CSV 文件，包含角色名称和各语言文本
"""

import json
import os
import sys
import csv
import argparse
from pathlib import Path
from collections import defaultdict
from typing import Any

# ---------------------------------------------------------------------------
# 数据模型
# ---------------------------------------------------------------------------

class DialogueEntry:
    """单条对话记录"""
    __slots__ = (
        "source_file", "scene_label", "scene_title", "text_index",
        "character",           # 原始角色名（日文）
        "lang_data",           # dict: lang_code -> {"name": ..., "text": ...}
        "voice",               # voice info or None
        "duration",            # 显示时长 (ms)
        "is_narration",        # 是否为旁白/叙述
    )

    def __init__(self, source_file: str, scene_label: str, scene_title: str,
                 text_index: int, character: str | None,
                 lang_data: dict, voice: Any, duration: int):
        self.source_file = source_file
        self.scene_label = scene_label
        self.scene_title = scene_title
        self.text_index = text_index
        self.character = character
        self.lang_data = lang_data
        self.voice = voice
        self.duration = duration
        self.is_narration = character is None

    def to_dict(self) -> dict:
        return {
            "source": self.source_file,
            "scene": self.scene_label,
            "scene_title": self.scene_title,
            "index": self.text_index,
            "character": self.character,
            "is_narration": self.is_narration,
            "languages": self.lang_data,
            "voice": self.voice,
            "duration_ms": self.duration,
        }


# ---------------------------------------------------------------------------
# 核心解析逻辑
# ---------------------------------------------------------------------------

class KsJsonParser:
    """解析单个 .ks.json 文件中的对话文本"""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
        with open(filepath, "r", encoding="utf-8") as f:
            self.data = json.load(f)
        self.languages: list[str] = self.data.get("languages", [])

    def parse(self) -> list[DialogueEntry]:
        """解析所有场景的对话，返回 DialogueEntry 列表"""
        entries: list[DialogueEntry] = []
        for scene in self.data.get("scenes", []):
            entries.extend(self._parse_scene(scene))
        return entries

    def _parse_scene(self, scene: dict) -> list[DialogueEntry]:
        label = scene.get("label", "")
        title = scene.get("title", "") or ""
        texts = scene.get("texts", [])
        if not texts:
            return []

        entries: list[DialogueEntry] = []
        for idx, text_entry in enumerate(texts):
            entry = self._parse_text_entry(text_entry, label, title, idx)
            if entry:
                entries.append(entry)
        return entries

    def _parse_text_entry(self, text_entry: list, scene_label: str,
                          scene_title: str, index: int) -> DialogueEntry | None:
        if not text_entry or len(text_entry) < 2:
            return None

        character = text_entry[0]       # str or None (narration)
        lang_array = text_entry[1]       # [JP, CN, TW, ...]
        voice = text_entry[2] if len(text_entry) > 2 else None
        duration = text_entry[3] if len(text_entry) > 3 else 0

        # 解析各语言文本
        lang_data: dict[str, dict[str, str]] = {}
        # 语言顺序: 0=Japanese, 1..N=按 data["languages"] 顺序
        self._parse_japanese(lang_data, lang_array[0])
        for i, lang_code in enumerate(self.languages):
            li = i + 1
            if li < len(lang_array):
                self._parse_language(lang_data, lang_code, lang_array[li])

        return DialogueEntry(
            source_file=self.filename,
            scene_label=scene_label,
            scene_title=scene_title,
            text_index=index,
            character=character,
            lang_data=lang_data,
            voice=voice,
            duration=duration,
        )

    @staticmethod
    def _parse_japanese(lang_data: dict, jp_entry: list) -> None:
        """解析日语文本条目

        日语条目有两种格式:
        - 3 元素: [display_name, text, char_count]              (无 ruby)
        - 5 元素: [display_name, text_with_br, char_count,
                    text_no_br, text_furigana_resolved]          (有 ruby 或换行)
        其中 text_with_br 使用 \\n 换行（最接近原始显示效果）
        """
        if not jp_entry or len(jp_entry) < 3:
            return
        display_name = jp_entry[0]
        text = jp_entry[1]  # 优先取带换行的原始文本
        lang_data["jp"] = {
            "name": display_name,
            "text": text,
        }

    @staticmethod
    def _parse_language(lang_data: dict, lang_code: str, entry: list) -> None:
        """解析单条翻译语言条目

        格式: [display_name, text, char_count]
        """
        if not entry or len(entry) < 3:
            return
        display_name = entry[0]
        text = entry[1]
        lang_data[lang_code] = {
            "name": display_name,
            "text": text,
        }


# ---------------------------------------------------------------------------
# 批量解析 & 输出
# ---------------------------------------------------------------------------

def parse_directory(json_dir: str) -> list[DialogueEntry]:
    """解析目录下所有 .ks.json 文件，返回所有对话条目"""
    all_entries: list[DialogueEntry] = []
    pattern = os.path.join(json_dir, "*.ks.json")
    import glob
    files = sorted(glob.glob(pattern))
    for i, filepath in enumerate(files):
        parser = KsJsonParser(filepath)
        entries = parser.parse()
        all_entries.extend(entries)
        if (i + 1) % 20 == 0 or i == len(files) - 1:
            print(f"已处理: {i + 1}/{len(files)} 个文件, "
                  f"累计 {len(all_entries)} 条对话", flush=True)
    return all_entries


def export_json(entries: list[DialogueEntry], output_path: str) -> None:
    """导出为 JSON 格式"""
    data = [e.to_dict() for e in entries]
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"JSON 已导出至: {output_path}")


def export_csv(entries: list[DialogueEntry], output_path: str) -> None:
    """导出为 CSV 格式（UTF-8 BOM，兼容 Excel）"""
    # 收集所有语言代码
    all_langs: set[str] = set()
    for e in entries:
        all_langs.update(e.lang_data.keys())

    # 按获取顺序稳定排列，但日语 (jp) 始终在最前面
    ordered_langs: list[str] = []
    if "jp" in all_langs:
        ordered_langs.append("jp")
        all_langs.discard("jp")
    ordered_langs.extend(sorted(all_langs))

    # 构建表头
    headers = ["source", "scene", "scene_title", "index",
               "character", "is_narration", "duration_ms", "voice"]
    for lang in ordered_langs:
        headers.append(f"name_{lang}")
        headers.append(f"text_{lang}")

    with open(output_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        for e in entries:
            row = [e.source_file, e.scene_label, e.scene_title,
                   e.text_index, e.character, e.is_narration, e.duration,
                   json.dumps(e.voice, ensure_ascii=False) if e.voice else ""]
            for lang in ordered_langs:
                ld = e.lang_data.get(lang, {})
                row.append(ld.get("name", ""))
                row.append(ld.get("text", ""))
            writer.writerow(row)
    print(f"CSV 已导出至: {output_path}")


def export_text_only(entries: list[DialogueEntry], output_path: str) -> None:
    """导出为纯文本格式，每种语言一个文件"""
    all_langs: set[str] = set()
    for e in entries:
        all_langs.update(e.lang_data.keys())

    ordered_langs: list[str] = []
    if "jp" in all_langs:
        ordered_langs.append("jp")
        all_langs.discard("jp")
    ordered_langs.extend(sorted(all_langs))

    lang_files: dict[str, list] = {lang: [] for lang in ordered_langs}

    for e in entries:
        name = e.character or "（旁白）"
        for lang in ordered_langs:
            ld = e.lang_data.get(lang, {})
            display_name = ld.get("name") or name
            text = ld.get("text", "")
            if text:
                lang_files[lang].append(f"【{display_name}】{text}")

    for lang in ordered_langs:
        out = output_path.replace(".txt", f"_{lang}.txt")
        with open(out, "w", encoding="utf-8") as f:
            f.write("\n\n".join(lang_files[lang]))
        print(f"文本已导出至: {out}  ({len(lang_files[lang])} 行)")


# ---------------------------------------------------------------------------
# 统计信息
# ---------------------------------------------------------------------------

def print_statistics(entries: list[DialogueEntry]) -> None:
    """打印数据集统计信息"""
    characters = defaultdict(int)
    narration = 0
    langs: set[str] = set()

    for e in entries:
        if e.is_narration:
            narration += 1
        else:
            characters[e.character] += 1
        langs.update(e.lang_data.keys())

    print(f"\n{'='*50}")
    print(f"数据集统计")
    print(f"{'='*50}")
    print(f"总对话数:     {len(entries)}")
    print(f"旁白/叙述:    {narration}")
    print(f"角色对话:     {len(entries) - narration}")
    print(f"语言:         {sorted(langs)}")
    print(f"角色数:       {len(characters)}")
    print(f"\n--- 角色对话数量 TOP 15 ---")
    top = sorted(characters.items(), key=lambda x: -x[1])[:15]
    for name, count in top:
        print(f"  {name:12s}  {count:5d}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="解析 Sanoba Witch .ks.json 文件中的角色对话文本")
    parser.add_argument(
        "input_dir", nargs="?", default=".",
        help="包含 .ks.json 文件的目录（默认: 当前目录）")
    parser.add_argument(
        "--output-dir", "-o", default=".",
        help="输出目录（默认: 当前目录）")
    parser.add_argument(
        "--format", "-f", choices=["json", "csv", "txt", "all"],
        default="all",
        help="输出格式（默认: all）")
    parser.add_argument(
        "--prefix", "-p", default="dialogue_export",
        help="输出文件名前缀（默认: dialogue_export）")
    args = parser.parse_args()

    # 验证输入目录
    json_dir = os.path.abspath(args.input_dir)
    if not os.path.isdir(json_dir):
        print(f"错误: 目录不存在 - {json_dir}")
        sys.exit(1)

    # 解析
    print(f"开始解析目录: {json_dir}")
    import glob
    file_count = len(glob.glob(os.path.join(json_dir, "*.ks.json")))
    print(f"发现 {file_count} 个 JSON 文件")
    print()

    entries = parse_directory(json_dir)
    print()

    if not entries:
        print("未找到任何对话数据")
        sys.exit(0)

    # 统计
    print_statistics(entries)

    # 导出
    os.makedirs(args.output_dir, exist_ok=True)
    prefix = os.path.join(args.output_dir, args.prefix)

    if args.format in ("json", "all"):
        export_json(entries, prefix + ".json")
    if args.format in ("csv", "all"):
        export_csv(entries, prefix + ".csv")
    if args.format in ("txt", "all"):
        export_text_only(entries, prefix + ".txt")


if __name__ == "__main__":
    main()
