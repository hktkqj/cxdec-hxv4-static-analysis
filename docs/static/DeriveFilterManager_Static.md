# DeriveFilterManager Static Flow

本文记录当前推荐的全静态流程：不启动游戏、不做运行时 dump、不附加 debugger，仅从目标 EXE 资源、bres salt 和 BOOTSTRAP DLL 的静态配置派生 XP3 解密所需状态。

## 结论

当前脚本面向同一类 bres/BOOTSTRAP/Hxv4 加密，而不是某一款游戏。只要目标 EXE 资源布局、bres salt、BOOTSTRAP DLL 配置表和 DLL 派生入口保持一致，就不需要运行时 dump。

```powershell
python src\static_extract\static_xp3_recover.py --exe path\to\game.exe
```

脚本输出：

```text
data/static_recover/drip_program.json
```

该 JSON 应与运行时 dump 或已验证样本在关键解密材料上等价：

```text
hxv4_key    = e4dc1d99d9d9fb1ae5f7529ee70f841bfadb13d12f4d22b99170d6cc6a62bc54
hxv4_nonce0 = d99230e02623f4a0c4f2857682b4de6dfefe820b57060e50
hxv4_nonce1 = b96f89630850dd23a13810c7718ad003936d1d4a3ae00890
context_u32 = 3106 项完全一致
lanes       = records 完全一致；VA 字段因离线进程加载地址不同而变化
```

使用目标游戏目录下的代表性 XP3 验证：

```powershell
python src\static_extract\static_xp3_recover.py `
  --exe path\to\game.exe `
  --xp3 path\to\scn.xp3 `
  --verify
```

结果：

```text
scn.xp3: checked=26 failed=0 unresolved_filter=0
```

适配新游戏时使用目标目录下的 `temp` 保存中间文件，并只做小范围验证：

```powershell
$game = "D:\Games\TargetGame"
$exeName = "TargetGame.exe"

python src\static_extract\static_xp3_recover.py `
  --exe "$game\$exeName" `
  --work-dir "$game\temp\static_recover" `
  --debug

python src\common\xp3_inspect.py verify `
  "$game\main.xp3" "$game\scn.xp3" "$game\data.xp3" `
  --filter recovered `
  --drip-program "$game\temp\static_recover\drip_program.json" `
  --max-entries 20 `
  --verbose
```

已确认结果：

```text
main.xp3: checked=20 failed=0 unresolved_filter=0 limited_to=20
scn.xp3: checked=20 failed=0 unresolved_filter=0 limited_to=20
data.xp3: checked=20 failed=0 unresolved_filter=0 limited_to=20
```

## 完成流程总结

当前静态闭环已经整理到 `src/static_extract/static_xp3_recover.py` 中。它的目标是从原始游戏 EXE 和加密模块自身恢复完整 `drip_program.json`，不依赖运行时 dump、调试器附加或临时 DLL 抓取。

不同游戏适配的操作清单见 [Cross-Game Static Flow Adaptation](Porting_Static_Flow.md)。该文档记录了参数记录模板、有限验证策略、`--debug` / `--verify-max-entries` 用法，以及什么时候才需要转入 IDA。

### 1. 静态输入

默认输入为：

| 输入 | 来源 |
|------|------|
| 游戏主程序 | 必须通过 `--exe` 指定目标 PE |
| bres salt | 默认扫描目标 EXE 汇编中的 `salt_ptr` / `0x2000` 初始化赋值；packed 原始 EXE 可回退到 `forcedataxp3` / `TEXT` / `V2Link` 数据邻域；需要复用外部 salt 时显式传 `--salt-file` |
| STARTUP.TJS 密文 | EXE `RCDATA/STARTUP.TJS` |
| BOOTSTRAP 密文 | EXE `RCDATA/BOOTSTRAP` |
| bres root key | EXE `TEXT/127` |
| 派生工具 | `tools/FilterManagerDerive`，需 x86 dotnet 运行 |

执行命令：

```powershell
python src\static_extract\static_xp3_recover.py --exe path\to\game.exe
```

`static_xp3_recover.py` 现在统一使用 `--exe` 作为资源和 salt 来源。默认 `--exe` 同时提供 PE Resources，并通过汇编赋值特征或 packed 数据邻域自动定位 salt。

如果已知 salt 的直接文件偏移，可绕过 PE RVA 映射：

```powershell
python src\static_extract\static_xp3_recover.py `
  --exe path\to\game.exe `
  --salt-file-offset 0x2E3200
```

salt 读取优先级为：

```text
显式 --salt-file
  -> 显式 --salt-rva / --salt-file-offset
  -> 默认 --exe 的自动定位
```

如果需要单独导出 salt：

```powershell
python src\static_extract\recover_bres_salt.py --exe path\to\game.exe --out bres_salt.bin
```

该命令会优先扫描原始 EXE 中类似 `mov [salt_ptr_global], salt_va; mov [salt_size_global], 0x2000` 的初始化汇编；若原始 packed EXE 没有可见 xref，则回退到 `forcedataxp3` / `TEXT` / `V2Link` 数据邻域。所有候选都会用 `STARTUP.TJS` 解密结果是否为 `TJS2100\0` 做校验。

### 2. PE 资源提取

脚本直接解析 PE resource directory，不依赖 `pefile`：

```text
RT_RCDATA / STARTUP.TJS  -> STARTUP_TJS.rcdata.bin
RT_RCDATA / BOOTSTRAP    -> BOOTSTRAP.rcdata.bin
RT_RCDATA / PLUGIN       -> PLUGIN.rcdata.bin
TEXT / 127               -> bres://./9kpzeqme93usra66re54h69ymi
```

`TEXT/127` 是 UTF-16LE 字符串，去掉 `bres://./` 前缀和尾部 `/` 后得到 STARTUP.TJS 的 path key：

```text
9kpzeqme93usra66re54h69ymi
```

### 3. bres:// 流解密

`STARTUP.TJS` 和 `BOOTSTRAP` 使用同一套 bres:// 流加密。密钥材料由 path key 和 0x2000 字节 salt 派生：

```text
digest = SHA3-384(path_key.encode("utf-16-le") + bres_salt)
```

ChaCha8 初始状态：

```text
T[0..3]  = "expand 32-byte k"
T[4..11] = digest[0:32]
T[12]    = LE32(digest[40:44]) ^ block_num
T[13]    = LE32(digest[44:48])
T[14]    = LE32(digest[32:36])
T[15]    = LE32(digest[36:40])
```

每 64 字节生成一个 ChaCha8 keystream block，并与密文 XOR：

```text
plaintext = ciphertext ^ keystream
```

STARTUP.TJS 解密后必须满足：

```text
magic = TJS2100\0
size  = 6944 bytes
```

### 4. STARTUP.TJS 字节码解析和源码反编译

解密后的 `STARTUP.TJS.dec` 是 TJS2 字节码。脚本会先把它写入 `work-dir`，再调用 `tools/tjs2-decompiler/tjs2_decompiler.py` 生成源码文本 `STARTUP.TJS`。

BOOTSTRAP URL 仍从 TJS2 `DATA` chunk 字符串池读取。脚本级 `System.bootStrap` prefix 优先从反编译源码中的 `_bootStrap("...")` 第一参数取得；如果反编译失败或源码中无法定位该调用，则回退到常量池中包含 `all` 的字符串候选。

关键字符串为：

```text
bres://./xuf2b4we2c5y8mi44vwhm6tqee/bootstrap
Sabbat_of_the_Witch (C)YUZUSOFT/JUNOS INC. All Rights Reserved.
```

第一项给出 BOOTSTRAP 的 path key：

```text
xuf2b4we2c5y8mi44vwhm6tqee
```

第二项是旧样本中常量池里可直接看到的脚本级 `System.bootStrap` 第一个参数，也就是后续 `FilterManagerDerive --bootstrap-prefix` 的值。新流程不再要求字符串精确包含 `All Rights Reserved.`；源码 `_bootStrap` 调用优先，常量池只作为兜底。

### 5. BOOTSTRAP 解密和 DLL 提取

使用 BOOTSTRAP path key 和同一 salt 解密 `RCDATA/BOOTSTRAP`。解密后载荷格式为：

```text
+0x00  8-byte custom header
+0x08  zlib-compressed DLL
```

因此脚本跳过前 8 字节，对剩余数据执行 zlib 解压，得到随机加密 DLL：

```text
data/static_recover/bootstrap.dll
```

解压结果以 `MZ` 开头，大小约 763392 bytes。该 DLL 是 `FilterManagerDerive` 离线派生所需的真实加密模块。

### 6. DLL 配置表读取

脚本按 PE RVA `0x80E38` 读取 `bootstrap.dll` 内的配置表。表结构为连续的 label-length-value：

```text
ascii label + NUL
uint16 length
raw value[length]
```

关键字段：

```text
UNIQUE  = {NENeMEGURuTSUMUGiTOUKoWAKANa}
WARNING = Warning! Extracting this game data may infringe on author's rights.
```

`UNIQUE` 是 UTF-16LE，用于 archive key update；`WARNING` 是 ASCII，用于补全最终 bootstrap 字符串。

### 7. 最终 bootstrap 字符串确定

IDA 中 `System_bootStrap_callback` 的关键路径已经确认：

```text
0x1000F083  构造 WARNING TJSString
0x1000F1ED  构造脚本传入的第一个参数
0x1000F216  拼接 script_arg + WARNING
0x1000F269  调用 sub_10015630
```

因此最终传入 DLL bootstrap 派生函数的 UTF-16LE 字符串是：

```text
Sabbat_of_the_Witch (C)YUZUSOFT/JUNOS INC. All Rights Reserved.Warning! Extracting this game data may infringe on author's rights.
```

脚本传给 `FilterManagerDerive` 的是 `--bootstrap-prefix`，工具内部会读取 DLL 配置表中的 `WARNING` 并追加，效果等价于直接传完整 `--bootstrap-text`。

### 8. FilterManager 离线派生

脚本调用 x86 dotnet 运行 `FilterManagerDerive.dll`：

```powershell
& 'C:\Program Files (x86)\dotnet\dotnet.exe' `
  tools\FilterManagerDerive\bin\Debug\net8.0\FilterManagerDerive.dll `
  --dll data\static_recover\bootstrap.dll `
  --out data\static_recover\drip_program.json `
  --bootstrap-prefix "Sabbat_of_the_Witch (C)YUZUSOFT/JUNOS INC. All Rights Reserved." `
  --archive-text "{NENeMEGURuTSUMUGiTOUKoWAKANa}"
```

`FilterManagerDerive` 在离线进程中加载 DLL，并调用：

| RVA | 作用 |
|-----|------|
| `0x0E2D0` | `FilterManager` 构造函数 |
| `0x15630` | bootstrap 派生函数，输入最终 bootstrap 字符串和 `PARAMS` |
| `0x157D0` | archive key update，输入 `UNIQUE` 和解析后的 archive seed |

archive seed 由 `FilterManagerDerive` 自动决定：

1. 显式 `--archive-seed-hex` 优先，用于调试或特殊样本。
2. 否则读取 `bootstrap.dll` RVA `0x81758` 的 8 字节静态 seed。
3. 如果该位置全 0，则扫描 `0x157D0` 函数体中的默认 seed 常量；`0x2CAFEACE, 0xDEADBEEF` 按小端组合为 `ceeaaf2cefbeadde`。

工具会打印实际使用的 seed，例如：

```text
archive seed: bf22368a48210206
archive seed: ceeaaf2cefbeadde
```

生成的 JSON 包含：

```text
hxv4_key
hxv4_nonce0
hxv4_nonce1
holder_words
context_u32
lanes
```

关键结果：

```text
data/static_recover/drip_program.json
hxv4_key    = e4dc1d99d9d9fb1ae5f7529ee70f841bfadb13d12f4d22b99170d6cc6a62bc54
hxv4_nonce0 = d99230e02623f4a0c4f2857682b4de6dfefe820b57060e50
hxv4_nonce1 = b96f89630850dd23a13810c7718ad003936d1d4a3ae00890
```

### 9. XP3 验证和提取

使用静态派生结果验证 XP3：

```powershell
python src\common\xp3_inspect.py verify `
  --filter recovered `
  --drip-program data\static_recover\drip_program.json `
  path\to\scn.xp3
```

验证结果：

```text
scn.xp3: checked=26 failed=0 unresolved_filter=0
```

如果需要实际提取：

```powershell
python src\common\xp3_inspect.py extract-all out\scn `
  --filter recovered `
  --drip-program data\static_recover\drip_program.json `
  path\to\scn.xp3
```

关于如何利用`drip_program.json`对文件进行解密的详细流程，请参考 [XP3 容器结构解析](../core/XP3Extract.md) 和 [Hxv4 / DripValue / FilterRuntimeState 分析](../core/Hxv4Ripped.md)。

因此，对满足上述前提的已验证样本而言，完整提取链路不再需要运行时 dump、调试启动或进程附加；目标 EXE 提供 bres 资源和 salt，BOOTSTRAP 提供 DLL，DLL 配置表提供 bootstrap suffix 和 archive unique key，最终由 `FilterManagerDerive` 在离线进程中复现运行时密钥派生。

## 自动化脚本

脚本：

```text
src/static_extract/static_xp3_recover.py
```

默认输入：

| 输入 | 默认路径或来源 |
|------|----------------|
| 游戏 EXE | 必须通过 `--exe` 指定目标 PE |
| bres salt | 默认扫描 EXE 汇编中的 `salt_ptr` / `0x2000` 初始化赋值；packed 原始 EXE 可回退到 `forcedataxp3` / `TEXT` / `V2Link` 数据邻域；需要复用外部 salt 时显式传 `--salt-file` |
| STARTUP.TJS | EXE `RCDATA/STARTUP.TJS` |
| BOOTSTRAP | EXE `RCDATA/BOOTSTRAP` |
| bres root key | EXE `TEXT/127` |
| DLL 配置表 RVA | `0x80E38` |

默认输出目录：

```text
data/static_recover/
```

关键输出：

| 文件 | 含义 |
|------|------|
| `STARTUP_TJS.rcdata.bin` | PE 资源中的加密 STARTUP.TJS |
| `STARTUP.TJS.dec` | 解密后的 TJS2 字节码 |
| `STARTUP.TJS` | 由 `tools/tjs2-decompiler` 反编译出的 TJS 源码，用于优先提取 `_bootStrap` 参数 |
| `BOOTSTRAP.rcdata.bin` | PE 资源中的加密 BOOTSTRAP |
| `BOOTSTRAP.dec` | 解密后的 BOOTSTRAP 载荷 |
| `bootstrap.dll` | BOOTSTRAP 解包出的 DLL |
| `PLUGIN.rcdata.bin` | 可选插件资源备份 |
| `static_recover.summary.json` | 静态流程摘要 |
| `drip_program.json` | 给 `src/common/xp3_inspect.py` 使用的解密状态 |

## 静态派生步骤

### 1. 提取 PE 资源

脚本直接解析 PE resource directory，读取：

```text
TEXT/127
RCDATA/STARTUP.TJS
RCDATA/BOOTSTRAP
RCDATA/PLUGIN
```

`TEXT/127` 是 UTF-16LE 字符串：

```text
bres://./9kpzeqme93usra66re54h69ymi
```

因此 STARTUP.TJS 的 path key 是：

```text
9kpzeqme93usra66re54h69ymi
```

### 2. 解密 STARTUP.TJS

bres:// 流加密为 SHA3-384 + ChaCha8：

```text
digest = SHA3-384(path_key.encode("utf-16le") + bres_salt)

T[0..3]  = ChaCha const
T[4..11] = digest[0:32]
T[12]    = LE32(digest[40:44]) ^ block_num
T[13]    = LE32(digest[44:48])
T[14]    = LE32(digest[32:36])
T[15]    = LE32(digest[36:40])
```

解密结果 magic：

```text
TJS2100\0
```

### 3. 解析 TJS2 常量池

从 `STARTUP.TJS.dec` 的 DATA chunk 字符串池取到 BOOTSTRAP URL；脚本还会尝试反编译并输出源码 `STARTUP.TJS`，优先从源码 `_bootStrap("...")` 的第一参数确定 bootstrap prefix。旧样本中常量池也能看到：

```text
bres://./xuf2b4we2c5y8mi44vwhm6tqee/bootstrap
Sabbat_of_the_Witch (C)YUZUSOFT/JUNOS INC. All Rights Reserved.
```

BOOTSTRAP 的 path key 是：

```text
xuf2b4we2c5y8mi44vwhm6tqee
```

### 4. 解密并解包 BOOTSTRAP

`BOOTSTRAP` 解密后格式：

```text
+0x00  8-byte custom header
+0x08  zlib-compressed DLL
```

解压后得到：

```text
bootstrap.dll
```

### 5. 读取 DLL 配置表

随机 DLL 配置表位于 RVA `0x80E38`，脚本读取 label-length-value 结构。

关键字段：

```text
UNIQUE  = {NENeMEGURuTSUMUGiTOUKoWAKANa}
WARNING = Warning! Extracting this game data may infringe on author's rights.
```

### 6. 静态确定最终 bootstrap 字符串

`bootstrap.dll` 中的 `System_bootStrap_callback` 会把脚本传入的第一个参数和 DLL 配置表中的 `WARNING` 拼接后传给核心派生函数。

IDA 确认点：

| 地址 | 含义 |
|------|------|
| `0x1000F083` | 从配置表构造默认 `WARNING` TJSString |
| `0x1000F1ED` | 从脚本参数构造 TJSString |
| `0x1000F216` | 拼接脚本参数和 `WARNING` |
| `0x1000F269` | 调用 `sub_10015630` |
| `0x10015630` | bootstrap core derivation |
| `0x100157D0` | archive key update |

因此最终 bootstrap 输入是：

```text
Sabbat_of_the_Witch (C)YUZUSOFT/JUNOS INC. All Rights Reserved.Warning! Extracting this game data may infringe on author's rights.
```

### 7. 调用 FilterManagerDerive

脚本自动调用：

```powershell
& 'C:\Program Files (x86)\dotnet\dotnet.exe' `
  tools\FilterManagerDerive\bin\Debug\net8.0\FilterManagerDerive.dll `
  --dll data\static_recover\bootstrap.dll `
  --out data\static_recover\drip_program.json `
  --bootstrap-prefix "Sabbat_of_the_Witch (C)YUZUSOFT/JUNOS INC. All Rights Reserved." `
  --archive-text "{NENeMEGURuTSUMUGiTOUKoWAKANa}"
```

`--bootstrap-prefix` 表示脚本级 `System.bootStrap` 第一个参数。`FilterManagerDerive` 会读取 DLL 中的 `WARNING` 并追加，因此不需要手工传完整字符串。

`--archive-text` 用于模拟 archive key update：

```text
sub_100157D0(manager + 8, archive_text_utf16le, byte_len, archive_seed)
```

它不是 bootstrap 密码，而是归档级过滤状态更新输入；应使用目标 DLL 配置表中的 `UNIQUE`。某已验证样本中的示例值为：

```text
{NENeMEGURuTSUMUGiTOUKoWAKANa}
```

`archive_seed` 不需要由 Python 判断。当前工具会自动使用 `--archive-seed-hex`、DLL RVA `0x81758` 非零静态 seed、或 `FilterManager_ArchiveUpdate` 内嵌默认 seed 三者之一。对于 RVA `0x81758` 全 0 的样本，默认 seed 是 `ceeaaf2cefbeadde`。

## 跨游戏适配参数

当前静态脚本为不同游戏暴露以下关键参数：

| 参数 | 说明 |
|------|------|
| `--exe` | 目标游戏 EXE，提供 PE Resources，并作为 bres salt 自动定位、`--salt-rva`、`--salt-file-offset` 的读取来源 |
| `--work-dir` | 输出目录；跨游戏分析时建议使用目标游戏目录下的 `temp` |
| `--out` | 指定 `drip_program.json` 输出路径 |
| `--salt-file` | 直接指定 0x2000 字节 bres salt |
| `--salt-rva` | 显式从 `--exe` 的 PE RVA 读取 salt |
| `--salt-file-offset` | 从 `--exe` 的文件偏移读取 salt |
| `--table-rva` | BOOTSTRAP DLL 配置表 RVA，默认 `0x80E38` |
| `--startup-resource` / `--bootstrap-resource` / `--text-resource` | 覆盖目标 PE 中的资源名，默认 `10/STARTUP.TJS`、`10/BOOTSTRAP`、`TEXT/127` |
| `--bootstrap-zlib-offset` | BOOTSTRAP 明文中 zlib payload 的起始偏移，默认 `8` |
| `--skip-derive` | 只做资源解密和 DLL 解包，用于探测 |
| `--debug` | 输出阶段级诊断信息 |
| `--verify-max-entries` | 配合 `--verify` 做有限验证 |

`xp3_inspect.py verify` 也支持有限验证：

```powershell
python src\common\xp3_inspect.py verify `
  --filter recovered `
  --drip-program path\to\drip_program.json `
  --max-entries 20 `
  path\to\main.xp3
```

迁移到新游戏时，推荐顺序是：

1. `--skip-derive --debug` 探测静态资源链路。
2. 生成目标游戏自己的 `drip_program.json`。
3. 对 `main.xp3`、`scn.xp3`、`data.xp3` 这类代表性包做 `--max-entries 20` 小范围验证。
4. 验证通过后再提取目标包。
5. 只有静态探测或小范围验证失败时，再用 IDA 定位新的 salt RVA、配置表 RVA 或 DLL 派生逻辑。

## salt 的边界

`bres_salt.bin` 是 8192 字节 bres salt。旧文档中的 `salt_F44A00.bin` 是同一数据的历史文件名；如果要使用旧文件名，需要通过 `--salt-file` 显式指定。IDA 中它对应脱壳镜像 `.rdata` 的 `g_bres_salt_F44A00`，但它同时也以明文形式存在于已验证样本的同一 PE RVA 映射位置。

已新增自动提取脚本：

```text
src/static_extract/recover_bres_salt.py
```

该脚本的自动化逻辑是：

1. 从原始游戏 EXE 的 PE Resources 读取加密 `STARTUP.TJS` 和 `TEXT/127` 中的 bres root key。
2. 默认扫描原始 EXE 或指定 source 的 `salt_ptr` / `0x2000` 初始化赋值；若没有命中，则扫描 packed 数据邻域；显式参数仍可从 PE RVA / 文件偏移读取 8192 字节候选 salt。
3. 用候选 salt 解密 `STARTUP.TJS`。
4. 只有解密结果以 `TJS2100\0` 开头时，才写出 `bres_salt.bin`。

默认即可从目标游戏 EXE 自动提取：

```powershell
python src\static_extract\recover_bres_salt.py --exe path\to\game.exe --out bres_salt.bin
```

显式 PE RVA 覆盖示例：

```powershell
python src\static_extract\recover_bres_salt.py `
  --exe path\to\game.exe `
  --source path\to\game.exe `
  --pe-rva 0x........ `
  --out bres_salt.bin
```

当前位置：

```text
原始 EXE PE RVA      = 0x2E4A00
原始 EXE file offset = 0x2E3200
脱壳镜像 VA          = 0xF44A00
脱壳镜像 segment     = .rdata
sha256               = 947569c1d4e5dea073d48bf61389c7c8682194cda9fc8138a1b3e3dbf87fd526
```

IDA 中确认的运行时逻辑：

```text
InitBresSaltAndStorageHooks / 0xC9A080
  0xC9A222: g_bres_salt_ptr  = g_bres_salt_F44A00
  0xC9A22C: g_bres_salt_size = 0x2000

DeriveBresBasicCryptoKey / 0xC9BB20
  0xC9BCC0: SHA3-384 update(path_key_utf16le)
  0xC9BCD9: SHA3-384 update(g_bres_salt_ptr, g_bres_salt_size)
```

因此 salt 本身不是运行时生成的；运行时只是把全局指针和长度设置为这段静态数据。

如果输入是 flat 内存 dump，可用 VA 减 image base 的 flat offset：

```powershell
python src\static_extract\recover_bres_salt.py `
  --exe path\to\game.exe `
  --source path\to\flat_memory_dump.bin `
  --image-base 0xC60000 `
  --va 0xF44A00 `
  --out bres_salt.bin
```

如果已知文件偏移，也可以直接指定：

```powershell
python src\static_extract\recover_bres_salt.py `
  --exe path\to\game.exe `
  --source path\to\game.exe `
  --file-offset 0x2E3200 `
  --out bres_salt.bin
```

还可以对未知镜像做对齐扫描：

```powershell
python src\static_extract\recover_bres_salt.py `
  --exe path\to\game.exe `
  --source path\to\unpacked_main.bin `
  --scan `
  --scan-alignment 0x1000 `
  --out bres_salt.bin
```

当前主流程脚本默认不再自动读取仓库根目录中的 salt 文件，也不再使用固定 salt RVA，避免跨游戏误用旧样本。默认行为是从 `--exe` 指定的 PE 中扫描初始化汇编和 packed 数据邻域定位 salt。

如果需要使用 `recover_bres_salt.py` 先导出的文件，必须显式传入：

```powershell
python src\static_extract\static_xp3_recover.py `
  --exe path\to\game.exe `
  --salt-file bres_salt.bin
```

此前失败的原因是使用了错误 RVA `0x344A00`：

```powershell
python src\static_extract\recover_bres_salt.py --exe path\to\game.exe --pe-rva 0x344A00 --out data\static_recover\salt_test.bin
```

```text
PE RVA 0x344a00 did not verify
no valid salt recovered
```

修正为正确 RVA 后，原始 packed EXE 可以直接恢复 salt；现在默认会优先尝试从初始化汇编中自动定位该 RVA。

## 与 LiveDump 流程的差异

| 项目 | 静态流程 |
|------|----------|
| 游戏进程 | 不启动 |
| debugger | 不使用 |
| bootstrap 字符串 | 反编译 `STARTUP.TJS` 中 `_bootStrap` 第一参数，失败时用常量池 `all` 候选；再拼 DLL `WARNING` |
| context | 离线调用 DLL 内部派生函数生成 |
| DLL | 从 EXE `RCDATA/BOOTSTRAP` 解密解包 |
| archive seed | `FilterManagerDerive` 自动解析：显式参数、DLL RVA `0x81758`、或 `ArchiveUpdate` 默认常量 |
| 主要风险 | 需要能从初始化汇编或 packed 数据邻域自动定位 salt，或显式提供正确 salt PE RVA / 文件偏移；同时 x86 dotnet 要能加载目标 DLL |
