# 复现操作文档 — 静态恢复并提取 XP3 资源

本文档记录当前仓库的推荐用法：不启动游戏、不附加 debugger，直接从目标 EXE 的 PE Resources、bres salt 和 BOOTSTRAP DLL 派生 `drip_program.json`，再用该 JSON 验证或提取 XP3。

以下命令假设当前工作目录是仓库根目录。

---

## 1. 准备环境

需要：

- Python 3.9+
- PyCryptodome
- .NET 8 x86 runtime / SDK，用于运行 `tools\FilterManagerDerive`

```powershell
pip install pycryptodome
```

先设置和具体游戏无关的变量。不同游戏只需要改 `$game` 和 `$exeName`：

```powershell
$repo = "F:\SteamLibrary\steamapps\common\sanobawitchi_xp3analysis"
Set-Location $repo

$game = "G:\Galgames\枯れない世界と終わる花"
$exeName = "sweet_01kareseka.exe"
$exe = Join-Path $game $exeName

$work = Join-Path $repo "Temp\static_recover_current"
$drip = Join-Path $work "drip_program.json"
$extractRoot = Join-Path $repo "Temp\xp3_extract_current"
```

如果希望中间文件写回游戏目录，也可以把 `$work` / `$extractRoot` 改成：

```powershell
$work = Join-Path $game "temp\static_recover"
$extractRoot = Join-Path $game "temp\xp3_extract"
```

---

## 2. 查看目标文件

列出目标目录下的 XP3：

```powershell
$xp3s = Get-ChildItem $game -Filter *.xp3 | Sort-Object Name
$xp3s | Select-Object Name, Length
```

`枯れない世界と終わる花` 已确认的包包括：

```text
adult.xp3
censored.xp3
data.xp3
evimage.xp3
fgimage.xp3
video.xp3
voice.xp3
```

---

## 3. 静态生成 Drip Program

先只探测，不派生：

```powershell
python src\static_extract\static_xp3_recover.py `
  --exe $exe `
  --work-dir $work `
  --skip-derive `
  --debug
```

成功时应看到：

```text
[debug] STARTUP.TJS decrypted bytes=...
[debug] BOOTSTRAP decrypted bytes=... dll_bytes=...
[debug] bootstrap_prefix source=STARTUP.TJS decompiled _bootStrap call
[debug] DLL config labels=PARAMS,PUBKEY,UNIQUE,WARNING
bootstrap_prefix: ...
archive_unique_key: ...
```

生成完整恢复状态：

```powershell
python src\static_extract\static_xp3_recover.py `
  --exe $exe `
  --work-dir $work `
  --debug
```

关键输出：

```text
$work\static_recover.summary.json
$work\STARTUP.TJS.dec
$work\STARTUP.TJS
$work\bootstrap.dll
$work\drip_program.json
```

`STARTUP.TJS` 是反编译源码，用于检查 `_bootStrap("...")` 的第一参数。`FilterManagerDerive` 会打印 `archive seed: ...`，用于确认当前样本使用 DLL 静态 seed 还是 `ArchiveUpdate` 默认 seed。

`枯れない世界と終わる花` 当前确认值：

```text
startup_key        = ryup2edvnxgdk4pf9hjqqnegt6
bootstrap_key      = nwaqa3kd38e5hdywszzy7y64ha
bootstrap_prefix   = SWEETandTEA_AllRightsReserved.
archive_unique_key = {Haru@Kotose@Yukina@Ren}
archive seed       = ceeaaf2cefbeadde
```

---

## 4. 有限验证

验证时先限制条目数，避免对大型包做长时间全量验证：

```powershell
python src\common\xp3_inspect.py verify `
  ($xp3s | ForEach-Object FullName) `
  --filter recovered `
  --drip-program $drip `
  --max-entries 20
```

也可以让静态恢复脚本透传验证。注意 `--xp3` 只写一次，后面跟多个 XP3 路径：

```powershell
python src\static_extract\static_xp3_recover.py `
  --exe $exe `
  --work-dir $work `
  --xp3 ($xp3s | ForEach-Object FullName) `
  --verify `
  --verify-max-entries 20 `
  --debug
```

如果只验证单个包：

```powershell
python src\common\xp3_inspect.py verify `
  (Join-Path $game "censored.xp3") `
  --filter recovered `
  --drip-program $drip `
  --max-entries 20
```

---

## 5. 提取资源

### 5.1 提取一个包

```powershell
python src\common\xp3_inspect.py extract-all `
  $extractRoot `
  (Join-Path $game "censored.xp3") `
  --filter recovered `
  --drip-program $drip
```

本仓库当前对 `枯れない世界と終わる花\censored.xp3` 的提取结果：

```text
processed=36 written=36 unresolved_filter=0 failed=0
manifest=Temp\kareseka_extract_sample\manifest.jsonl
```

### 5.2 提取多个包

如果确认磁盘空间足够，可以一次传多个 XP3：

```powershell
python src\common\xp3_inspect.py extract-all `
  $extractRoot `
  ($xp3s | ForEach-Object FullName) `
  --filter recovered `
  --drip-program $drip
```

大型包可能产生数 GB 输出。初次提取建议先从 `censored.xp3`、`voice.xp3` 或其他较小包开始。

### 5.3 查看提取结果

每个提取目录下都有 `manifest.jsonl`：

```powershell
Get-Content "$extractRoot\manifest.jsonl" | ConvertFrom-Json |
  Group-Object status | Select-Object Name, Count
```

常见状态：

```text
written           已成功写出
failed            解密、解压或校验失败
unresolved_filter 需要尚未恢复的 filter 状态
```

很多受保护条目没有原始文件名，输出会使用 `entry_*.bin`。可以按 magic bytes 判断格式：

```powershell
Get-Content "$extractRoot\censored\entry_00001_5001.bin" -Encoding Byte -TotalCount 4 |
  ForEach-Object { "{0:X2}" -f $_ }
```

常见 magic：

```text
OggS        -> .ogg
89 50 4E 47 -> .png
FF D8 FF    -> .jpg
TLG0        -> .tlg
TJS2100     -> .tjs bytecode
```

---

## 6. 常见问题

### `ModuleNotFoundError: No module named 'Crypto'`

```powershell
pip install pycryptodome
```

### `STARTUP.TJS did not decrypt to TJS2100`

优先检查：

- `$exe` 是否指向正确游戏 EXE。
- `--work-dir` 里是否有旧文件混淆判断。
- 是否需要显式传 `--salt-rva`、`--salt-file-offset` 或 `--salt-file`。

### `bootstrap_prefix` 可疑

检查：

```powershell
Select-String -Path "$work\STARTUP.TJS" -Pattern "_bootStrap"
```

当前脚本优先解析反编译源码中的 `_bootStrap("...")` 第一参数；反编译失败时才回退到常量池中包含 `all` 的候选。

### `FilterManagerDerive` 失败

确认 x86 dotnet 可用：

```powershell
& 'C:\Program Files (x86)\dotnet\dotnet.exe' --info
```

如果 DLL 内函数 RVA 或调用约定变化，需要更新 `tools\FilterManagerDerive`。

### verify 或 extract 出现 Adler mismatch

检查：

- `drip_program.json` 是否由同一游戏、同一版本 EXE/DLL 派生。
- `Hxv4 descriptor.flags & 1` 选择的 nonce 是否正确。
- archive key update 的 `UNIQUE` 是否来自同一个 `bootstrap.dll` 配置表。

---

## 7. 命令索引

| 操作 | 命令 |
|------|------|
| XP3 摘要 | `python src/common/xp3_inspect.py summary file.xp3` |
| 查找 entry | `python src/common/xp3_inspect.py find keyword file.xp3` |
| 查看 Hxv4 映射 | `python src/common/xp3_inspect.py hxv4 file.xp3 --drip-program drip.json` |
| 有限验证 | `python src/common/xp3_inspect.py verify file.xp3 --filter recovered --drip-program drip.json --max-entries 20` |
| 提取单文件 | `python src/common/xp3_inspect.py extract file.xp3 name out.bin --filter recovered --drip-program drip.json` |
| 提取整包 | `python src/common/xp3_inspect.py extract-all outdir file.xp3 --filter recovered --drip-program drip.json` |
| 静态探测 | `python src/static_extract/static_xp3_recover.py --exe game.exe --work-dir Temp\probe --skip-derive --debug` |
| 静态派生 | `python src/static_extract/static_xp3_recover.py --exe game.exe --work-dir Temp\static_recover --debug` |
