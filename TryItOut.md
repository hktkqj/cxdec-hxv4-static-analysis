# 复现操作文档 — 从零开始提取 Sanoba Witch XP3 资源

本文档提供完整的复现操作指南，从环境搭建到成功提取全部资源。

---

## 前提条件

### 已安装的软件

- **Python 3.9+** — 主脚本语言
- **PyCryptodome** — XChaCha20-Poly1305 解密

```powershell
pip install pycryptodome
```

### 需要的文件

从本仓库获取：

| 文件 | 位置 | 说明 |
|------|------|------|
| `xp3_inspect.py` | `src/` | 主提取脚本 |
| `inspect_manager_dump.py` | `src/` | Dump 状态导出脚本 |
| `manager_ready.drip_program.json` | `data/` | DripValue VM 核心状态（离线提取必需） |

### 游戏文件（已购买安装）

游戏目录应包含以下 `.xp3` 文件：

```
allage.xp3   bgimage.xp3   bgm.xp3    data.xp3
evimage.xp3  fgimage.xp3   scn.xp3    steam.xp3
video.xp3    voice.xp3
```

---

## 步骤 A：从运行时 Dump 导出 Drip Program（仅需一次）

> **注意**：如果已有 `data/manager_ready.drip_program.json`，可跳过此步骤直接进入步骤 B。

### A.1 捕获运行时 Dump

使用 `watch_random_plugin_dump.py` 监控游戏进程，在随机 DLL 的 FilterManager 就绪时自动 dump：

```powershell
python src/watch_random_plugin_dump.py `
  --attach-name SabbatOfTheWitch.exe `
  --manager-slot-rva 0xAC9AC `
  --deref-manager0 `
  --output ./manager_ready.full.dmp
```

参数说明：
- `--attach-name`：附加到已运行的游戏进程
- `--manager-slot-rva 0xAC9AC`：随机 DLL 中 `g_FilterManager` 的 RVA
- `--deref-manager0`：要求 `manager[0]` wrapper 非空，确保 FilterManager 已初始化
- `--settle-ms`：等待时间（默认 250ms），确保状态稳定

### A.2 验证 Dump 有效性

```powershell
python src/inspect_manager_dump.py ./manager_ready.full.dmp `
  --manager-slot-rva 0xAC9AC
```

成功时应看到：

```
random plugin: base=0x711D0000 ...
g_FilterManager slot 0x7127C9AC -> 0x06511F08 (4b048db14c27.dll+0xAC9AC)
manager[0] wrapper -> 0x0319B5C8 (mapped)
drip impl          -> 0x06534FC8 (mapped)
```

### A.3 导出 Drip Program

```powershell
python src/inspect_manager_dump.py ./manager_ready.full.dmp `
  --manager-slot-rva 0xAC9AC `
  --out-prefix ./manager_ready
```

成功时应看到：

```
wrote manager_ready.drip_program.json (128 lanes, 3106 context dwords)
```

导出的文件包括：
- `manager_ready.drip_program.json` — **离线提取核心依赖**
- `manager_ready.filter_manager.bin` — FilterManager 二进制 dump
- `manager_ready.drip_impl.bin` — DripValueImpl 二进制 dump

---

## 步骤 B：验证 Filter 正确性

在提取前，先验证 recovered filter 是否与运行时一致：

```powershell
python src/xp3_inspect.py verify ./bgm.xp3 `
  --filter recovered `
  --drip-program ./data/manager_ready.drip_program.json
```

预期输出：

```
bgm.xp3: checked=93 failed=0 unresolved_filter=0
```

可以一次性验证全部 XP3：

```powershell
@("allage","bgimage","bgm","data","evimage","fgimage","scn","steam","video","voice") | ForEach-Object {
  python src/xp3_inspect.py verify "./$_.xp3" `
    --filter recovered `
    --drip-program ./data/manager_ready.drip_program.json
}
```

---

## 步骤 C：离线提取

### C.1 查看 XP3 摘要

```powershell
python src/xp3_inspect.py summary ./data.xp3 --samples 5
```

### C.2 查看 Hxv4 映射表

```powershell
python src/xp3_inspect.py hxv4 ./data.xp3 --samples 10 `
  --drip-program ./data/manager_ready.drip_program.json
```

### C.3 提取单个文件

```powershell
# 提取 data.xp3 中的 startup.tjs
python src/xp3_inspect.py extract ./data.xp3 startup.tjs ./startup.tjs `
  --filter recovered --drip-program ./data/manager_ready.drip_program.json
```

### C.4 提取整个包

```powershell
# 提取 bgm.xp3（93 个 OGG 音频文件）
python src/xp3_inspect.py extract-all ./output/bgm ./bgm.xp3 `
  --filter recovered --drip-program ./data/manager_ready.drip_program.json
```

### C.5 一次性提取全部 10 个包

```powershell
$outBase = "./output"
$drip = "./data/manager_ready.drip_program.json"

@("allage","bgimage","bgm","data","evimage","fgimage","scn","steam","video","voice") | ForEach-Object {
  python src/xp3_inspect.py extract-all "$outBase\$_" "./$_.xp3" `
    --filter recovered --drip-program $drip
}
```

提取完成后，每个包对应一个输出子目录：

```
output/
├── allage/allage/      (91 files)
├── bgimage/bgimage/    (108 files)
├── bgm/bgm/            (93 OGG files)
├── data/data/          (4,087 files)
├── evimage/evimage/    (319 files)
├── fgimage/fgimage/    (1,554 files)
├── scn/scn/            (26 files)
├── steam/steam/        (3 files)
├── video/video/        (12 files)
└── voice/voice/        (28,988 files)
```

每个目录下包含 `manifest.jsonl`，记录了每条 entry 的提取状态和 Adler32 校验结果。

---

## 步骤 D：提取结果分析

### D.1 查看提取结果

```powershell
# 查看 manifest 统计
Get-Content ./output/bgm/bgm/manifest.jsonl | ForEach-Object {
  ($_ | ConvertFrom-Json).status
} | Group-Object | Select-Object Name, Count
```

### D.2 文件类型识别

对提取目录做 magic 扫描以确定文件真实格式：

```powershell
# 示例：检查 bgm 输出的文件头
Get-Content ./output/bgm/bgm/entry_00001_5001.bin -Encoding Byte -TotalCount 4 |
  ForEach-Object { "{0:X2}" -f $_ }
# OggS → OGG Vorbis 音频

# 已知 magic 对应关系：
# OggS   → .ogg (OGG Vorbis)
# 89 50 4E 47 → .png
# FF D8 FF → .jpg
# TLG0 → .tlg
# TJS2100 → .tjs
```

### D.3 解析场景脚本（scn.xp3）

提取 `scn.xp3` 后，可以使用 `tjs2_inspect.py` 检查其输出文件的格式：

```powershell
python src/tjs2_inspect.py ./output/scn/scn/entry_00001_5001.bin
```

如果输出是 TJS2100 字节码，可进一步解析其 constant pool 和 opcode。

### D.4 解析对话文本

如果 `scn.xp3` 已解析为 `.ks.json` 场景文件，可使用 `parse_dialogue.py` 提取对话：

```powershell
python src/parse_dialogue.py ./scn_json_dir --format all --output-dir ./dialogues
```

---

## 常见问题

### Q1: `ModuleNotFoundError: No module named 'Crypto'`

```powershell
pip install pycryptodome
```

### Q2: Adler32 不匹配

检查以下三项：
1. `open_flag` 是否正确（应使用 `Hxv4 descriptor.flags & 1`，而非 `record.filter_flag & 1`）
2. 有 `startup.tjs` 的包 entry 映射是否有 `+1` 偏移
3. `startup.tjs` 本身可能 raw Adler 已正确，不应强制套 filter

### Q3: 提取的 bgm 文件无法播放

提取后文件没有扩展名，需要根据 magic bytes 重命名：

```powershell
# 批量按 magic 重命名（PowerShell）
Get-ChildItem ./output/bgm/bgm/*.bin | ForEach-Object {
  $head = Get-Content $_.FullName -Encoding Byte -TotalCount 4
  if ($head[0..3] -join ' ' -eq '79 103 103 83') {
    Rename-Item $_.FullName "$($_.BaseName).ogg"
  }
}
```

### Q4: 如何从新的 dump 重新生成 drip_program.json

```powershell
python src/inspect_manager_dump.py ./new_dump.full.dmp `
  --manager-slot-rva 0xAC9AC `
  --out-prefix ./new_manager_ready
```

---

## 完整命令索引

| 操作 | 命令 |
|------|------|
| 查看摘要 | `python src/xp3_inspect.py summary ./file.xp3` |
| 查找文件 | `python src/xp3_inspect.py find "keyword" ./file.xp3` |
| 查看映射表 | `python src/xp3_inspect.py hxv4 ./file.xp3 --drip-program drip.json` |
| 导出 metadata JSON | `python src/xp3_inspect.py json ./file.xp3 output.json` |
| 验证 filter | `python src/xp3_inspect.py verify ./file.xp3 --filter recovered --drip-program drip.json` |
| 提取单文件 | `python src/xp3_inspect.py extract ./file.xp3 "name" out.bin --filter recovered --drip-program drip.json` |
| 提取整包 | `python src/xp3_inspect.py extract-all ./outdir ./file.xp3 --filter recovered --drip-program drip.json` |
| 导出 Drip Program | `python src/inspect_manager_dump.py dump.dmp --manager-slot-rva 0xAC9AC --out-prefix out` |
| 分析 TJS 字节码 | `python src/tjs2_inspect.py ./file.bin` |
| 解析对话文本 | `python src/parse_dialogue.py ./json_dir --format all` |

---

## 最小复现流程（TL;DR）

如果你已经有 `data/manager_ready.drip_program.json`，只需要：

```powershell
# 1. 验证
python src/xp3_inspect.py verify ./bgm.xp3 --filter recovered --drip-program ./data/manager_ready.drip_program.json

# 2. 提取
python src/xp3_inspect.py extract-all ./output/bgm ./bgm.xp3 --filter recovered --drip-program ./data/manager_ready.drip_program.json

# 3. 全部包
$drip = "./data/manager_ready.drip_program.json"
@("allage","bgimage","bgm","data","evimage","fgimage","scn","steam","video","voice") | ForEach-Object {
  python src/xp3_inspect.py extract-all "./output/$_" "./$_.xp3" --filter recovered --drip-program $drip
}
```
