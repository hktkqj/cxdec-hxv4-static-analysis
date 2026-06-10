# 复现操作文档：静态恢复、XP3 提取和资源后处理

本文档覆盖当前仓库的推荐工具链：从目标 EXE 静态恢复 `drip_program.json`，用它验证或提取 XP3，再对提取结果做格式识别、PSB/PIMG 合成、文本解扰和辅助索引。

以下命令假设当前工作目录是仓库根目录。

---

## 1. 准备环境

需要：

- Python 3.9+
- `pycryptodome`
- Pillow，用于 PSB/PIMG 图片合成
- .NET 8 x86 runtime / SDK，用于运行 `tools\FilterManagerDerive`

```powershell
pip install pycryptodome pillow
```

设置变量。不同游戏通常只需要改 `$game` 和 `$exeName`：

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

如果希望中间文件写回游戏目录，可以改成：

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

后续示例中的 `($xp3s | ForEach-Object FullName)` 会把这些 XP3 路径作为多参数传给 Python 脚本。

---

## 3. 静态恢复工具

主入口：

```powershell
python src\static_extract\static_xp3_recover.py --exe $exe --work-dir $work --debug
```

### 3.1 只探测，不派生

用于确认 `STARTUP.TJS`、`BOOTSTRAP`、prefix 和 DLL 配置表是否能被正确恢复：

```powershell
python src\static_extract\static_xp3_recover.py `
  --exe $exe `
  --work-dir $work `
  --skip-derive `
  --debug
```

成功时通常会看到：

```text
[debug] STARTUP.TJS decrypted bytes=...
[debug] BOOTSTRAP decrypted bytes=... dll_bytes=...
[debug] bootstrap_prefix source=STARTUP.TJS decompiled _bootStrap call
[debug] DLL config labels=PARAMS,PUBKEY,UNIQUE,WARNING
bootstrap_prefix: ...
archive_unique_key: ...
```

### 3.2 生成完整 Drip Program

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
$work\bres_salt.bin
$work\drip_program.json
```

`STARTUP.TJS.dec` 是解密后的 TJS2 字节码；`STARTUP.TJS` 是反编译源码，用于检查 `_bootStrap("...")` 第一参数。`drip_program.json` 同时包含 Hxv4 key/nonce 和 FilterManager/DripValue 派生所需的状态。

### 3.3 常用适配参数

默认资源布局不匹配时可以显式指定：

```powershell
python src\static_extract\static_xp3_recover.py `
  --exe $exe `
  --work-dir $work `
  --startup-resource "10/STARTUP.TJS" `
  --bootstrap-resource "10/BOOTSTRAP" `
  --text-resource "TEXT/127" `
  --plugin-resource "10/PLUGIN" `
  --bootstrap-zlib-offset 8 `
  --debug
```

salt 自动定位失败时可以指定来源：

```powershell
python src\static_extract\static_xp3_recover.py `
  --exe $exe `
  --work-dir $work `
  --salt-rva 0x123456 `
  --debug
```

也可以单独使用 salt 恢复工具：

```powershell
python src\static_extract\recover_bres_salt.py `
  --exe $exe `
  --scan `
  --out "$work\bres_salt.bin"
```

---

## 4. XP3 查看、验证和提取

`src\common\xp3_inspect.py` 是 XP3 主工具，支持：

```text
summary      查看包摘要
find         按名称子串查找 entry
hxv4         解密并解析 Hxv4 资源映射表
verify       解密/解压后校验 adlr
extract      提取单个 entry
extract-all  提取全部可恢复 entry
json         导出 XP3 index 元数据
```

### 4.1 摘要和查找

```powershell
python src\common\xp3_inspect.py summary ($xp3s | ForEach-Object FullName)

python src\common\xp3_inspect.py find startup ($xp3s | ForEach-Object FullName)

python src\common\xp3_inspect.py json `
  (Join-Path $game "scn.xp3") `
  (Join-Path $repo "Temp\scn_index.json")
```

### 4.2 查看 Hxv4 映射

```powershell
python src\common\xp3_inspect.py hxv4 `
  (Join-Path $game "scn.xp3") `
  --drip-program $drip `
  --output "$work\scn.hxv4.json" `
  --states-output "$work\scn.filter_states.json" `
  --samples 20
```

`--states-output` 写出的紧凑状态可用于检查单个资源的 filter seed 是否能被恢复。

### 4.3 有限验证

验证时先限制条目数，避免对大型包做长时间全量验证：

```powershell
python src\common\xp3_inspect.py verify `
  ($xp3s | ForEach-Object FullName) `
  --filter recovered `
  --drip-program $drip `
  --max-entries 20
```

静态恢复脚本也可以透传验证。注意 `--xp3` 只写一次，后面跟多个 XP3 路径：

```powershell
python src\static_extract\static_xp3_recover.py `
  --exe $exe `
  --work-dir $work `
  --xp3 ($xp3s | ForEach-Object FullName) `
  --verify `
  --verify-max-entries 20 `
  --debug
```

### 4.4 提取单个 entry

```powershell
python src\common\xp3_inspect.py extract `
  (Join-Path $game "scn.xp3") `
  "startup.tjs" `
  "$extractRoot\startup.tjs.bin" `
  --filter recovered `
  --drip-program $drip
```

### 4.5 提取整包

`extract-all` 的参数顺序是先输出目录，再跟一个或多个 XP3 路径：

```powershell
python src\common\xp3_inspect.py extract-all `
  $extractRoot `
  (Join-Path $game "censored.xp3") `
  --filter recovered `
  --drip-program $drip
```

一次提取多个包：

```powershell
python src\common\xp3_inspect.py extract-all `
  $extractRoot `
  ($xp3s | ForEach-Object FullName) `
  --filter recovered `
  --drip-program $drip
```

`extract-all` 会写出 `manifest.jsonl`。常见状态：

```text
written            已成功写出
failed             解密、解压或校验失败
unresolved_filter  需要尚未恢复的 filter 状态
```

---

## 5. 提取结果识别

### 5.1 查看 manifest 状态

```powershell
Get-Content "$extractRoot\manifest.jsonl" | ConvertFrom-Json |
  Group-Object status | Select-Object Name, Count
```

### 5.2 全量 header 扫描

`tools\scan_headers.py` 只负责扫描目录下已提取的 `.bin` 文件。`xp3_inspect.py extract-all` 的输出通常使用 `flat` 布局：

```powershell
python tools\scan_headers.py `
  -i $extractRoot `
  -o "$extractRoot\file_type_report.txt" `
  --layout flat
```

旧批处理输出如果是 `<base>\<archive>\<archive>\*.bin`，使用默认 `nested` 布局：

```powershell
python tools\scan_headers.py -i Temp\legacy_extract -o Temp\legacy_report.txt
```

### 5.3 精确计算资源哈希并查 manifest

`compute_resource_hash.py` 用于计算无 key 的 pathHash/fileHash，也可以结合 `manifest.jsonl` 找到提取结果和检测到的格式：

```powershell
python src\static_extract\compute_resource_hash.py `
  --filename cglist.csv `
  --manifest "$extractRoot\manifest.jsonl"
```

JSON 输出：

```powershell
python src\static_extract\compute_resource_hash.py `
  --filename cglist.csv `
  --manifest "$extractRoot\manifest.jsonl" `
  --json
```

如果某款游戏没有使用默认额外字符串 `xp3hnp`，可以传空字符串：

```powershell
python src\static_extract\compute_resource_hash.py `
  --filename startup.tjs `
  --filename-extra "" `
  --manifest "$extractRoot\manifest.jsonl"
```

---

## 6. 文本和脚本辅助工具

### 6.1 TJS2 字节码检查

```powershell
python src\common\tjs2_inspect.py "$work\STARTUP.TJS.dec"
```

反编译 TJS2 可使用仓库内第三方工具：

```powershell
python tools\tjs2-decompiler\tjs2_decompiler.py "$work\STARTUP.TJS.dec"
```

### 6.2 Kirikiri scrambled UTF-16LE 文本解扰

`tools\descramble_files.py` 用于 `FE FE xx FF FE` 头的 scrambled 文本：

```powershell
python tools\descramble_files.py `
  -i $extractRoot `
  -o "$repo\Temp\descrambled_text"
```

### 6.3 KAG/KS 对话导出

```powershell
python src\common\parse_dialogue.py `
  "$repo\Temp\ks_json" `
  -o "$repo\Temp\dialogue" `
  -f all `
  -p dialogue_export
```

---

## 7. PSB/PIMG 和 CG 合成工具

`tools\psb_parser.py` 当前只保留三个用户入口：

```text
inspect      检查 PSB/PIMG 结构、字符串表和合成关系
extract-all  导出所有嵌入图片资源，并写 manifest
compose-all  内部执行提取、TLG 转 PNG、合成所有命名图层/差分并清理临时目录
```

### 7.1 检查 PSB/PIMG

```powershell
python tools\psb_parser.py inspect `
  "$extractRoot\evimage\entry_00001_5001.bin" `
  --strings `
  --composition `
  --json "$repo\Temp\composition.json"
```

### 7.2 导出嵌入图片

```powershell
python tools\psb_parser.py extract-all `
  "$extractRoot\evimage\entry_00001_5001.bin" `
  -o "$repo\Temp\psb_resources" `
  --png
```

`--png` 会把 TLG 资源通过 `tools\tlg2png\tlg2png.exe` 转为 PNG；嵌入 PNG 会保持 PNG 输出。

### 7.3 一步合成 CG

```powershell
python tools\psb_parser.py compose-all `
  "$extractRoot\evimage\entry_00001_5001.bin" `
  -o "$repo\Temp\output\entry_00001_5001"
```

保留中间文件用于调试：

```powershell
python tools\psb_parser.py compose-all `
  "$extractRoot\evimage\entry_00001_5001.bin" `
  -o "$repo\Temp\output\entry_00001_5001" `
  --work-dir "$repo\Temp\psb_work" `
  --keep-temp
```

### 7.4 PNG 和 PSB/PIMG 混合输出的处理

从 XP3 提取出来的文件可能本身就是 PNG，也可能是 PSB/PIMG。不要只看扩展名，优先看 magic bytes：

```powershell
Get-Content "$extractRoot\evimage\entry_00001_5001.bin" -Encoding Byte -TotalCount 8 |
  ForEach-Object { "{0:X2}" -f $_ }
```

常见 magic：

```text
50 53 42 00              PSB/PIMG，交给 psb_parser.py compose-all
89 50 4E 47 0D 0A 1A 0A  PNG，可直接改扩展名或复制为 .png
54 4C 47 30              TLG0，可用 tlg2png.exe 转换
```

### 7.5 CG 列表和差分映射

```powershell
python tools\cglist_diff_map.py `
  "$extractRoot\data\cglist.csv" `
  "$extractRoot\data\imagediffmap.csv" `
  --json `
  --only-mapped
```

---

## 8. `枯れない世界と終わる花` 参考值

当前已确认的示例值：

```text
startup_key        = ryup2edvnxgdk4pf9hjqqnegt6
bootstrap_key      = nwaqa3kd38e5hdywszzy7y64ha
bootstrap_prefix   = SWEETandTEA_AllRightsReserved.
archive_unique_key = {Haru@Kotose@Yukina@Ren}
archive seed       = ceeaaf2cefbeadde
```

已确认包名包括：

```text
adult.xp3
censored.xp3
data.xp3
evimage.xp3
fgimage.xp3
video.xp3
voice.xp3
```

这些值是样例，不应硬编码到工具或新游戏文档中。

---

## 9. 常见问题

### `ModuleNotFoundError: No module named 'Crypto'`

```powershell
pip install pycryptodome
```

### `ModuleNotFoundError: No module named 'PIL'`

```powershell
pip install pillow
```

### `STARTUP.TJS did not decrypt to TJS2100`

优先检查：

- `$exe` 是否指向正确游戏 EXE。
- `$work` 里是否混入旧样本文件。
- 是否需要显式传 `--salt-rva`、`--salt-file-offset` 或 `--salt-file`。

### `bootstrap_prefix` 可疑

检查反编译结果：

```powershell
Select-String -Path "$work\STARTUP.TJS" -Pattern "_bootStrap"
```

当前脚本优先解析反编译源码中的 `_bootStrap("...")` 第一参数；反编译失败时才回退到常量池中包含 `all` 的候选。

### `FilterManagerDerive` 失败

确认 x86 dotnet 可用：

```powershell
& 'C:\Program Files (x86)\dotnet\dotnet.exe' --info
```

如果 DLL 内函数 RVA 或调用约定变化，需要更新 `tools\FilterManagerDerive` 或传入匹配的静态恢复参数。

### verify 或 extract 出现 Adler mismatch

检查：

- `drip_program.json` 是否由同一游戏、同一版本 EXE/DLL 派生。
- `Hxv4 descriptor.flags & 1` 选择的 nonce 是否正确。
- archive key update 的 `UNIQUE` 是否来自同一个 `bootstrap.dll` 配置表。
- 是否把旧输出目录和新提取结果混在一起。

### `--max-entries` 仍然感觉慢

`verify --max-entries` 限制的是每个 XP3 中进入验证循环的非 warning entry 数；脚本仍然需要先读取 XP3 index，并在 recovered filter 模式下解析 Hxv4 表。大包初次验证仍会有固定开销。

---

## 10. 命令索引

| 操作 | 命令 |
|------|------|
| 静态探测 | `python src/static_extract/static_xp3_recover.py --exe game.exe --work-dir Temp\probe --skip-derive --debug` |
| 静态派生 | `python src/static_extract/static_xp3_recover.py --exe game.exe --work-dir Temp\static_recover --debug` |
| 静态派生并有限验证 | `python src/static_extract/static_xp3_recover.py --exe game.exe --work-dir Temp\static_recover --xp3 main.xp3 scn.xp3 --verify --verify-max-entries 20` |
| 单独扫描 bres salt | `python src/static_extract/recover_bres_salt.py --exe game.exe --scan --out bres_salt.bin` |
| XP3 摘要 | `python src/common/xp3_inspect.py summary file.xp3` |
| 查找 entry | `python src/common/xp3_inspect.py find keyword file.xp3` |
| 导出 XP3 index JSON | `python src/common/xp3_inspect.py json file.xp3 index.json` |
| 查看 Hxv4 映射 | `python src/common/xp3_inspect.py hxv4 file.xp3 --drip-program drip_program.json --output hxv4.json --states-output states.json` |
| 有限验证 | `python src/common/xp3_inspect.py verify file.xp3 --filter recovered --drip-program drip_program.json --max-entries 20` |
| 提取单文件 | `python src/common/xp3_inspect.py extract file.xp3 name out.bin --filter recovered --drip-program drip_program.json` |
| 提取整包 | `python src/common/xp3_inspect.py extract-all outdir file.xp3 --filter recovered --drip-program drip_program.json` |
| 全量 header 分类 | `python tools/scan_headers.py -i outdir -o report.txt --layout flat` |
| 计算资源 hash / 查 manifest | `python src/static_extract/compute_resource_hash.py --filename cglist.csv --manifest outdir\manifest.jsonl` |
| 检查 PSB/PIMG | `python tools/psb_parser.py inspect file.bin --strings --composition` |
| 导出 PSB/PIMG 内嵌图片 | `python tools/psb_parser.py extract-all file.bin -o out_resources --png` |
| 一步合成 PSB/PIMG CG | `python tools/psb_parser.py compose-all file.bin -o out_cg` |
| 解扰 scrambled 文本 | `python tools/descramble_files.py -i outdir -o descrambled` |
| 导出对话 | `python src/common/parse_dialogue.py ks_json_dir -o dialogue -f all` |
| 解析 CG 差分映射 | `python tools/cglist_diff_map.py cglist.csv imagediffmap.csv --json` |
