# 复现操作文档 — 从零开始提取 XP3 资源

本文档提供完整的复现操作指南，从环境搭建到成功提取资源。当前推荐优先使用静态流程：不启动游戏、不附加 debugger，直接从目标 EXE 的 PE Resources、bres salt 和 BOOTSTRAP DLL 派生 `drip_program.json`。旧的运行时 dump 流程保留为备选。

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
| `static_xp3_recover.py` | `src/static_extract/` | 静态恢复 bres 资源、BOOTSTRAP DLL 和 `drip_program.json` |
| `xp3_inspect.py` | `src/common/` | XP3 摘要、验证、Hxv4 调试和提取脚本 |
| `FilterManagerDerive` | `tools/` | x86 dotnet 派生工具 |

### 游戏文件（已购买安装）

游戏目录应包含主程序 EXE 和若干 `.xp3` 文件。例如：

```
allage.xp3   bgimage.xp3   bgm.xp3    data.xp3
evimage.xp3  fgimage.xp3   scn.xp3    steam.xp3
video.xp3    voice.xp3
```

---

## 步骤 A：静态生成 Drip Program

### A.1 静态探测

先用 `--skip-derive --debug` 确认目标游戏是否属于当前 bres/BOOTSTRAP/Hxv4 加密链路。所有中间文件建议写到目标游戏目录的 `temp` 下：

```powershell
$game = "F:\SteamLibrary\steamapps\common\CafeStella"

python src\static_extract\static_xp3_recover.py `
  --exe "$game\CafeStella.exe" `
  --work-dir "$game\temp\static_recover_probe" `
  --skip-derive `
  --debug
```

成功时应看到：

```text
[debug] STARTUP.TJS decrypted bytes=...
[debug] BOOTSTRAP decrypted bytes=... dll_bytes=...
[debug] DLL config labels=PARAMS,PUBKEY,UNIQUE,WARNING
archive_unique_key: ...
```

CafeStella 已确认值：

```text
salt_source        = CafeStella.exe:RVA 0x2e4a00
bootstrap_prefix   = Cafe Stella and the Reapers Butterflies (C)YUZUSOFT/JUNOS INC. All Rights Reserved.
archive_unique_key = {Kanna+Natsume+Nozomi+Mei+Suzune}
```

如果 `STARTUP.TJS` 无法解密为 `TJS2100\0`，优先调整 `--salt-rva`、`--salt-file-offset` 或 `--salt-file`。如果 BOOTSTRAP 已解密但无法 zlib 解压，检查 `--bootstrap-zlib-offset`。如果 DLL 配置表找不到 `UNIQUE` / `WARNING`，优先调整 `--table-rva`。

### A.2 生成 drip program

```powershell
python src\static_extract\static_xp3_recover.py `
  --exe "$game\CafeStella.exe" `
  --work-dir "$game\temp\static_recover" `
  --debug
```

输出文件：

```text
$game\temp\static_recover\static_recover.summary.json
$game\temp\static_recover\drip_program.json
```

`drip_program.json` 必须和生成它的目标 EXE/DLL 配套使用，不要混用其他游戏或其他版本生成的 JSON。

---

## 步骤 B：验证 Filter 正确性

验证时先限制条目数，避免对大型包或整个目录做长时间全量验证：

```powershell
$drip = "$game\temp\static_recover\drip_program.json"

python src\common\xp3_inspect.py verify `
  "$game\main.xp3" "$game\scn.xp3" "$game\data.xp3" `
  --filter recovered `
  --drip-program $drip `
  --max-entries 20 `
  --verbose
```

预期输出：

```text
main.xp3: checked=20 failed=0 unresolved_filter=0 limited_to=20
scn.xp3: checked=20 failed=0 unresolved_filter=0 limited_to=20
data.xp3: checked=20 failed=0 unresolved_filter=0 limited_to=20
```

也可以在静态恢复脚本中透传有限验证：

```powershell
python src\static_extract\static_xp3_recover.py `
  --exe "$game\CafeStella.exe" `
  --work-dir "$game\temp\static_recover" `
  --xp3 "$game\main.xp3" "$game\scn.xp3" `
  --verify `
  --verify-max-entries 20 `
  --debug
```

如果只验证单个小包，也可以不传 `--max-entries`。不要把整个游戏目录作为初次 verify 目标。

---

## 步骤 C：离线提取

### C.1 查看 XP3 摘要

```powershell
python src\common\xp3_inspect.py summary "$game\data.xp3" --samples 5
```

### C.2 查看 Hxv4 映射表和 filter state

```powershell
python src\common\xp3_inspect.py hxv4 "$game\main.xp3" --samples 5 `
  --drip-program $drip `
  --output "$game\temp\main.hxv4.json" `
  --states-output "$game\temp\main.filter_states.json"
```

### C.3 提取单个文件

如果 XP3 中存在可见文件名，可以按名称提取：

```powershell
python src\common\xp3_inspect.py extract "$game\data.xp3" startup.tjs "$game\temp\startup.tjs" `
  --filter recovered --drip-program $drip
```

### C.4 提取整个包

```powershell
python src\common\xp3_inspect.py extract-all `
  "$game\temp\evimage_extract" `
  "$game\evimage.xp3" `
  --filter recovered `
  --drip-program $drip
```

CafeStella `evimage.xp3` 已确认结果：

```text
processed=528 written=528 unresolved_filter=0 failed=0
```

每个提取目录下包含 `manifest.jsonl`，记录每条 entry 的状态和 Adler32 校验结果。

---

## 步骤 D：运行时 Dump 备选流程

> 仅当静态流程无法定位 salt、BOOTSTRAP DLL 或派生逻辑时使用。

使用 `watch_random_plugin_dump.py` 监控游戏进程，在随机 DLL 的 FilterManager 就绪时自动 dump：

```powershell
python src/dynamic_capture/watch_random_plugin_dump.py `
  --attach-name SabbatOfTheWitch.exe `
  --manager-slot-rva 0xAC9AC `
  --deref-manager0 `
  --output ./manager_ready.full.dmp
```

导出 Drip Program：

```powershell
python src/dynamic_capture/inspect_manager_dump.py ./manager_ready.full.dmp `
  --manager-slot-rva 0xAC9AC `
  --out-prefix ./manager_ready
```

导出的 `manager_ready.drip_program.json` 可替代静态流程生成的 `drip_program.json` 用于验证和提取。

---

## 步骤 E：提取结果分析

### E.1 查看 manifest 统计

```powershell
Get-Content "$game\temp\evimage_extract\manifest.jsonl" | ForEach-Object {
  ($_ | ConvertFrom-Json).status
} | Group-Object | Select-Object Name, Count
```

### E.2 文件类型识别

对提取目录做 magic 扫描以确定文件真实格式。很多受保护条目没有原始文件名，输出会使用 `entry_*.bin`：

```powershell
Get-Content "$game\temp\evimage_extract\evimage\entry_00001_5001.bin" -Encoding Byte -TotalCount 4 |
  ForEach-Object { "{0:X2}" -f $_ }
```

常见 magic：

```text
OggS        -> .ogg
89 50 4E 47 -> .png
FF D8 FF    -> .jpg
TLG0        -> .tlg
TJS2100     -> .tjs
```

### E.3 解析场景脚本

提取 `scn.xp3` 后，可以使用 `tjs2_inspect.py` 检查其输出文件的格式：

```powershell
python src/common/tjs2_inspect.py "$game\temp\scn_extract\scn\entry_00001_5001.bin"
```

如果输出是 TJS2100 字节码，可进一步解析其 constant pool 和 opcode。

### E.4 解析对话文本

如果 `scn.xp3` 已解析为 `.ks.json` 场景文件，可使用 `parse_dialogue.py` 提取对话：

```powershell
python src/common/parse_dialogue.py ./scn_json_dir --format all --output-dir ./dialogues
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
4. 当前 `drip_program.json` 是否由同一游戏的 EXE/DLL 派生，不要混用其他游戏的 JSON

### Q3: 静态探测失败时如何检查和汇报

先保留 `--debug --skip-derive` 的完整输出，并检查 `static_recover.summary.json` 是否生成。如果没有走到 `archive_unique_key`，按现象优先定位：

| 现象 | 定位目标 |
|------|----------|
| `resource ... was not found` | `--startup-resource` / `--bootstrap-resource` / `--text-resource` 是否匹配目标 EXE 资源表 |
| `STARTUP.TJS did not decrypt to TJS2100` | `--salt-rva` / `--salt-file-offset` / `--salt-file`，或 salt 长度不是 0x2000 |
| BOOTSTRAP 无法 zlib 解压 | BOOTSTRAP key、`--bootstrap-zlib-offset` 或 payload 格式 |
| 解压结果不是 PE DLL | BOOTSTRAP payload 布局或压缩偏移 |
| 配置表无 `UNIQUE` / `WARNING` | `--table-rva` |
| `FilterManagerDerive` 失败 | DLL 派生函数 RVA / 调用约定 |
| `verify` 出现 Adler mismatch | `drip_program.json` 是否来自同一目标、Hxv4 映射、open flag 或 archive key update |

汇报问题时请提供：

```text
目标游戏名 / 版本 / 商店来源:
EXE 文件名和 SHA256:
执行的完整命令:
--debug 输出:
static_recover.summary.json:
失败的 XP3 名称:
verify 输出或 manifest.jsonl 中的失败条目:
已尝试的 --salt-rva / --salt-file-offset / --table-rva / --bootstrap-zlib-offset:
```

只有静态探测或小范围验证失败，并且上述信息指向偏移或派生逻辑变化时，才需要进入 IDA 定位新的 salt RVA、配置表 RVA 或 DLL 派生逻辑。

### Q4: 提取的 bgm 文件无法播放

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

### Q5: 如何从新的 dump 重新生成 drip_program.json

```powershell
python src/dynamic_capture/inspect_manager_dump.py ./new_dump.full.dmp `
  --manager-slot-rva 0xAC9AC `
  --out-prefix ./new_manager_ready
```

---

## 完整命令索引

| 操作 | 命令 |
|------|------|
| 查看摘要 | `python src/common/xp3_inspect.py summary ./file.xp3` |
| 查找文件 | `python src/common/xp3_inspect.py find "keyword" ./file.xp3` |
| 查看映射表 | `python src/common/xp3_inspect.py hxv4 ./file.xp3 --drip-program drip.json` |
| 导出 metadata JSON | `python src/common/xp3_inspect.py json ./file.xp3 output.json` |
| 验证 filter | `python src/common/xp3_inspect.py verify ./file.xp3 --filter recovered --drip-program drip.json` |
| 有限验证 filter | `python src/common/xp3_inspect.py verify ./file.xp3 --filter recovered --drip-program drip.json --max-entries 20` |
| 提取单文件 | `python src/common/xp3_inspect.py extract ./file.xp3 "name" out.bin --filter recovered --drip-program drip.json` |
| 提取整包 | `python src/common/xp3_inspect.py extract-all ./outdir ./file.xp3 --filter recovered --drip-program drip.json` |
| 静态生成 Drip Program | `python src/static_extract/static_xp3_recover.py --exe game.exe --work-dir game\temp\static_recover --debug` |
| 静态探测 | `python src/static_extract/static_xp3_recover.py --exe game.exe --work-dir game\temp\probe --skip-derive --debug` |
| 静态派生并有限验证 | `python src/static_extract/static_xp3_recover.py --exe game.exe --work-dir game\temp\static_recover --xp3 main.xp3 --verify --verify-max-entries 20 --debug` |
| 导出 Drip Program | `python src/dynamic_capture/inspect_manager_dump.py dump.dmp --manager-slot-rva 0xAC9AC --out-prefix out` |
| 分析 TJS 字节码 | `python src/common/tjs2_inspect.py ./file.bin` |
| 解析对话文本 | `python src/common/parse_dialogue.py ./json_dir --format all` |

---

## 最小复现流程（TL;DR）

静态路径最小流程：

```powershell
$game = "F:\SteamLibrary\steamapps\common\CafeStella"
$drip = "$game\temp\static_recover\drip_program.json"

# 1. 生成 drip program
python src/static_extract/static_xp3_recover.py --exe "$game\CafeStella.exe" --work-dir "$game\temp\static_recover" --debug

# 2. 有限验证
python src/common/xp3_inspect.py verify "$game\main.xp3" --filter recovered --drip-program $drip --max-entries 20

# 3. 提取目标包
python src/common/xp3_inspect.py extract-all "$game\temp\evimage_extract" "$game\evimage.xp3" --filter recovered --drip-program $drip
```
