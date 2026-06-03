# Cross-Game Static Flow Adaptation

本文记录如何把当前静态 XP3 恢复流程用于同一类 bres/BOOTSTRAP/Hxv4 加密的游戏。目标是先确认静态链路是否成立，再做小范围 XP3 验证，最后按需提取单个包；不要一开始就对整个游戏目录做全量验证或提取。

## 适用前提

静态流程依赖以下结构仍然成立：

| 项目 | 预期 |
|------|------|
| 主程序 | Windows PE，资源表中有 `RCDATA/STARTUP.TJS`、`RCDATA/BOOTSTRAP`、可选 `RCDATA/PLUGIN` 和 `TEXT/127` |
| bres salt | 默认可从 `--exe` 的初始化汇编中定位；packed 原始 EXE 可回退到 `forcedataxp3` / `TEXT` / `V2Link` 数据邻域；也可显式用 PE RVA / 文件偏移读取 0x2000 字节 |
| STARTUP.TJS | 用 `TEXT/127` path key + salt 解密后为 `TJS2100\0` |
| BOOTSTRAP | 解密后跳过 8 字节 header，剩余数据可 zlib 解压为 PE DLL |
| DLL 配置表 | 默认 RVA `0x80E38`，包含 `UNIQUE` 和 `WARNING` |
| 派生工具 | x86 dotnet 可加载 BOOTSTRAP DLL 并运行 `FilterManagerDerive` |

这些是“同类加密”的判定条件，不是某一款游戏的专用条件。如果这些条件中任一项失败，先调整脚本参数；只有参数无法解释失败时，再考虑 IDA 定位新的 salt 初始化逻辑、DLL 配置表 RVA 或 bootstrap 逻辑。只要 `--debug --skip-derive` 能完整走到 `archive_unique_key` 输出，通常暂时不需要 IDA。

## 推荐适配步骤

### 1. 建立临时输出目录

所有新游戏的中间文件建议放在目标游戏目录下的 `temp` 子目录，避免污染分析仓库：

```powershell
$game = "F:\SteamLibrary\steamapps\common\CafeStella"
New-Item -ItemType Directory -Force "$game\temp" | Out-Null
```

### 2. 先做静态探测

探测阶段只解密 bres 资源、解包 BOOTSTRAP DLL 和读取配置表，不生成 `drip_program.json`：

```powershell
python src\static_extract\static_xp3_recover.py `
  --exe "$game\CafeStella.exe" `
  --work-dir "$game\temp\static_recover_probe" `
  --skip-derive `
  --debug
```

成功时应看到类似输出：

```text
[debug] loaded PE: sections=7 resource_rva=0x41a000
[debug] resource sizes: STARTUP.TJS=6904 BOOTSTRAP=327658 PLUGIN=54 salt=8192
[debug] STARTUP.TJS decrypted bytes=6904
[debug] BOOTSTRAP decrypted bytes=327658 dll_bytes=763392
[debug] DLL config labels=PARAMS,PUBKEY,UNIQUE,WARNING
startup_key: xfgp9i53ygpktxjfjyzcjf5hg2
bootstrap_key: daagz6fftpcf5ayewqa7246z6w
salt_source: F:\SteamLibrary\steamapps\common\CafeStella\CafeStella.exe:auto V2Link-before anchor RVA ... salt VA ... / RVA ... / file offset ...
archive_unique_key: {Kanna+Natsume+Nozomi+Mei+Suzune}
```

如果 `STARTUP.TJS did not decrypt to TJS2100`，优先检查自动定位输出、`--salt-rva` / `--salt-file-offset` / `--salt-file`。如果 DLL 配置表缺少 `UNIQUE` 或 `WARNING`，优先检查 `--table-rva`。

### 3. 生成静态 drip program

确认探测成功后再生成完整恢复状态：

```powershell
python src\static_extract\static_xp3_recover.py `
  --exe "$game\CafeStella.exe" `
  --work-dir "$game\temp\static_recover" `
  --debug
```

关键输出：

```text
$game\temp\static_recover\static_recover.summary.json
$game\temp\static_recover\drip_program.json
```

`drip_program.json` 必须与生成它的目标游戏 EXE/DLL 配套使用；不要混用其他游戏或其他版本生成的 JSON。需要兼容旧文档时，也可以用 `--out` 指定历史文件名。

### 4. 小范围验证 XP3

先验证小包或代表性包的前若干条，不要直接把整个游戏目录作为 verify 目标：

```powershell
$drip = "$game\temp\static_recover\drip_program.json"

python src\common\xp3_inspect.py verify `
  "$game\main.xp3" "$game\scn.xp3" "$game\data.xp3" `
  --filter recovered `
  --drip-program $drip `
  --max-entries 20 `
  --verbose
```

预期输出示例：

```text
main.xp3: checked=20 failed=0 unresolved_filter=0 limited_to=20
scn.xp3: checked=20 failed=0 unresolved_filter=0 limited_to=20
data.xp3: checked=20 failed=0 unresolved_filter=0 limited_to=20
```

也可以通过 `static_xp3_recover.py` 透传有限验证：

```powershell
python src\static_extract\static_xp3_recover.py `
  --exe "$game\CafeStella.exe" `
  --work-dir "$game\temp\static_recover" `
  --xp3 "$game\main.xp3" "$game\scn.xp3" `
  --verify `
  --verify-max-entries 20 `
  --debug
```

### 5. 导出 Hxv4 / filter state 调试信息

需要确认 archive 映射和每条 entry 的 filter state 时，导出单包 JSON：

```powershell
python src\common\xp3_inspect.py hxv4 "$game\main.xp3" `
  --samples 5 `
  --drip-program $drip `
  --output "$game\temp\main.hxv4.json" `
  --states-output "$game\temp\main.filter_states.json"
```

### 6. 按包提取

确认小范围验证通过后，再提取目标包。例如提取 CafeStella 的 `evimage.xp3`：

```powershell
python src\common\xp3_inspect.py extract-all `
  "$game\temp\evimage_extract" `
  "$game\evimage.xp3" `
  --filter recovered `
  --drip-program $drip
```

成功结果示例：

```text
processed=528 written=528 unresolved_filter=0 failed=0
manifest=F:\SteamLibrary\steamapps\common\CafeStella\temp\evimage_extract\manifest.jsonl
```

## CafeStella 已确认参数

| 项目 | 值 |
|------|----|
| 游戏目录 | `F:\SteamLibrary\steamapps\common\CafeStella` |
| 主程序 | `CafeStella.exe` |
| salt source | 自动定位；packed 原始 EXE 通常通过 `V2Link-before` / `forcedataxp3-near` 数据邻域命中 |
| DLL 配置表 RVA | `0x80E38` |
| STARTUP key | `xfgp9i53ygpktxjfjyzcjf5hg2` |
| BOOTSTRAP key | `daagz6fftpcf5ayewqa7246z6w` |
| bootstrap prefix | `Cafe Stella and the Reapers Butterflies (C)YUZUSOFT/JUNOS INC. All Rights Reserved.` |
| archive unique key | `{Kanna+Natsume+Nozomi+Mei+Suzune}` |

已做的小范围验证：

```text
main.xp3: checked=20 failed=0 unresolved_filter=0 limited_to=20
scn.xp3: checked=20 failed=0 unresolved_filter=0 limited_to=20
data.xp3: checked=20 failed=0 unresolved_filter=0 limited_to=20
```

已完成的按包提取：

```text
evimage.xp3: processed=528 written=528 unresolved_filter=0 failed=0
```

## 何时需要 IDA

以下情况才需要把目标 EXE 或 BOOTSTRAP DLL 加载到 IDA：

| 现象 | 优先定位 |
|------|----------|
| `STARTUP.TJS did not decrypt to TJS2100` | 新的 bres salt 地址、salt 长度或 bres key 派生逻辑 |
| BOOTSTRAP 解密后无法 zlib 解压 | BOOTSTRAP path key、header 长度或压缩格式变化 |
| 解压结果不是 PE DLL | BOOTSTRAP payload 布局变化 |
| 配置表找不到 `UNIQUE` / `WARNING` | DLL 配置表 RVA 变化，调整 `--table-rva` |
| `FilterManagerDerive` 失败 | DLL 内派生函数 RVA 或调用约定变化，需要更新派生工具 |
| 小范围 verify 出现 Adler mismatch | Hxv4 解析、open flag、archive update 或 filter runtime state 变化 |

## 失败检查和问题汇报

出现提取失败时，先区分失败阶段：

| 阶段 | 检查项 |
|------|--------|
| 资源读取失败 | 用报错中的 available resources 检查 `--startup-resource`、`--bootstrap-resource`、`--text-resource` |
| `STARTUP.TJS` 解密失败 | 确认 salt 是 0x2000 字节，并尝试 `--salt-rva`、`--salt-file-offset`、`--salt-file` |
| BOOTSTRAP 解包失败 | 检查 `--bootstrap-zlib-offset`，以及 STARTUP 常量池中的 BOOTSTRAP URL 是否正确 |
| 配置表失败 | 调整 `--table-rva`，确认 DLL 配置表仍包含 `UNIQUE` / `WARNING` |
| 派生工具失败 | 确认 x86 dotnet 可用；如果 DLL 内函数 RVA 变化，需要更新 `FilterManagerDerive` |
| verify / extract 失败 | 确认 `drip_program.json` 与目标 EXE/DLL/XP3 属于同一游戏版本，并查看 `manifest.jsonl` |

汇报问题时请附上以下信息，避免只贴“提取失败”：

```text
目标游戏名 / 版本 / 商店来源:
EXE 文件名和 SHA256:
XP3 文件名和大小:
执行的完整命令:
static_xp3_recover.py --debug 输出:
static_recover.summary.json 内容:
verify 输出:
extract-all manifest.jsonl 中 status != ok 的行:
已尝试的参数:
  --salt-rva / --salt-file-offset / --salt-file
  --table-rva
  --bootstrap-zlib-offset
  --startup-resource / --bootstrap-resource / --text-resource
```

## 参数速查

| 参数 | 用途 |
|------|------|
| `--exe` | 提供 PE Resources 的目标游戏 EXE，并作为 bres salt 自动定位、`--salt-rva`、`--salt-file-offset` 的读取来源 |
| `--work-dir` | 中间文件和 `drip_program.json` 输出目录 |
| `--out` | 指定 `drip_program.json` 输出路径 |
| `--salt-file` | 直接指定 0x2000 字节 bres salt 文件 |
| `--salt-rva` | 显式从 `--exe` 的 PE RVA 读取 salt |
| `--salt-file-offset` | 从 `--exe` 的文件偏移读取 salt |
| `--table-rva` | BOOTSTRAP DLL 配置表 RVA，默认 `0x80E38` |
| `--startup-resource` / `--bootstrap-resource` / `--text-resource` | 目标 PE 中的资源名覆盖 |
| `--bootstrap-zlib-offset` | BOOTSTRAP 明文中 zlib payload 的起始偏移，默认 `8` |
| `--skip-derive` | 只做静态资源解密和 DLL 解包，不生成 drip program |
| `--debug` | 输出阶段级诊断信息 |
| `--verify` | 派生后调用 `xp3_inspect.py verify` |
| `--verify-max-entries` | 透传有限验证条数，避免全量 verify |
| `xp3_inspect.py verify --max-entries` | 每个 XP3 最多验证多少个非 warning entry |
