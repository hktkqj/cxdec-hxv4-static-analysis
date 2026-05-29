# DeriveFilterManager Static Flow

本文记录当前推荐的全静态流程：不启动游戏、不做运行时 dump、不附加 debugger，仅从 EXE 资源、已提取 salt 和随机加密 DLL 的静态配置派生 XP3 解密所需状态。

## 结论

Sanoba Witch 当前样本可以通过静态文件直接得到可用的 XP3 解密状态。

```powershell
python src\static_extract\static_xp3_recover.py
```

脚本输出：

```text
data/static_recover/sanoba.static.drip_program.json
```

该 JSON 已确认与早期 `data/sanoba_complete.drip_program.json` 在关键解密材料上等价：

```text
hxv4_key    = e4dc1d99d9d9fb1ae5f7529ee70f841bfadb13d12f4d22b99170d6cc6a62bc54
hxv4_nonce0 = d99230e02623f4a0c4f2857682b4de6dfefe820b57060e50
hxv4_nonce1 = b96f89630850dd23a13810c7718ad003936d1d4a3ae00890
context_u32 = 3106 项完全一致
lanes       = records 完全一致；VA 字段因离线进程加载地址不同而变化
```

使用游戏目录下的 `scn.xp3` 验证通过：

```powershell
python src\static_extract\static_xp3_recover.py `
  --xp3 "F:\SteamLibrary\steamapps\common\sanoba witch\scn.xp3" `
  --verify
```

结果：

```text
scn.xp3: checked=26 failed=0 unresolved_filter=0
```

## 完成流程总结

当前静态闭环已经整理到 `src/static_extract/static_xp3_recover.py` 中。它的目标是从原始游戏 EXE 和加密模块自身恢复完整 `drip_program.json`，不依赖运行时 dump、调试器附加或临时 DLL 抓取。

### 1. 静态输入

默认输入为：

| 输入 | 来源 |
|------|------|
| 游戏主程序 | `F:\SteamLibrary\steamapps\common\sanoba witch\SabbatOfTheWitch.exe` |
| bres salt | 优先 `.\salt_F44A00.bin`；不存在时从原始 EXE `PE RVA 0x2E4A00` 读取 |
| STARTUP.TJS 密文 | EXE `RCDATA/STARTUP.TJS` |
| BOOTSTRAP 密文 | EXE `RCDATA/BOOTSTRAP` |
| bres root key | EXE `TEXT/127` |
| 派生工具 | `tools/FilterManagerDerive`，需 x86 dotnet 运行 |

执行命令：

```powershell
python src\static_extract\static_xp3_recover.py
```

`static_xp3_recover.py` 可以把资源来源 EXE 和 salt 来源程序分开指定。默认 `--exe` 同时提供 PE Resources 和 salt；如果需要从另一份运行时程序、脱壳程序或 dump 修复 PE 中取 salt，可使用：

```powershell
python src\static_extract\static_xp3_recover.py `
  --exe "F:\SteamLibrary\steamapps\common\sanoba witch\SabbatOfTheWitch.exe" `
  --runtime-exe path\to\salt_source.exe `
  --salt-rva 0x2E4A00
```

其中 `--runtime-exe` 是 `--salt-source-exe` 的别名，只影响 salt 提取，不影响 `STARTUP.TJS` / `BOOTSTRAP` 的 PE Resource 来源。

如果已知 salt 的直接文件偏移，可绕过 PE RVA 映射：

```powershell
python src\static_extract\static_xp3_recover.py `
  --exe "F:\SteamLibrary\steamapps\common\sanoba witch\SabbatOfTheWitch.exe" `
  --runtime-exe path\to\salt_source.exe `
  --salt-file-offset 0x2E3200
```

salt 读取优先级为：

```text
显式 --salt-file
  -> 显式 --runtime-exe / --salt-source-exe / --salt-rva / --salt-file-offset
  -> 默认 .\salt_F44A00.bin
  -> 默认 --exe + --salt-rva 0x2E4A00
```

如果需要单独导出 salt：

```powershell
python src\static_extract\recover_bres_salt.py --out salt_F44A00.bin
```

该命令会从原始 EXE 的 `PE RVA 0x2E4A00` 映射到文件偏移 `0x2E3200` 读取 0x2000 字节，并用 `STARTUP.TJS` 解密结果是否为 `TJS2100\0` 做校验。

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
digest = SHA3-384(path_key.encode("utf-16-le") + salt_F44A00)
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

### 4. STARTUP.TJS 字节码解析

解密后的 `STARTUP.TJS.dec` 是 TJS2 字节码。脚本解析 chunk 列表，找到 `DATA` chunk，再读取字符串池。

关键字符串为：

```text
bres://./xuf2b4we2c5y8mi44vwhm6tqee/bootstrap
Sabbat_of_the_Witch (C)YUZUSOFT/JUNOS INC. All Rights Reserved.
```

第一项给出 BOOTSTRAP 的 path key：

```text
xuf2b4we2c5y8mi44vwhm6tqee
```

第二项是脚本级 `System.bootStrap` 第一个参数，也就是后续 `FilterManagerDerive --bootstrap-prefix` 的值。

### 5. BOOTSTRAP 解密和 DLL 提取

使用 BOOTSTRAP path key 和同一 salt 解密 `RCDATA/BOOTSTRAP`。解密后载荷格式为：

```text
+0x00  8-byte custom header
+0x08  zlib-compressed DLL
```

因此脚本跳过前 8 字节，对剩余数据执行 zlib 解压，得到随机加密 DLL：

```text
data/static_recover/1ae7153ed25d.dll
```

解压结果以 `MZ` 开头，大小约 763392 bytes。该 DLL 是 `FilterManagerDerive` 离线派生所需的真实加密模块。

### 6. DLL 配置表读取

脚本按 PE RVA `0x80E38` 读取 `1ae7153ed25d.dll` 内的配置表。表结构为连续的 label-length-value：

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
  --dll data\static_recover\1ae7153ed25d.dll `
  --out data\static_recover\sanoba.static.drip_program.json `
  --bootstrap-prefix "Sabbat_of_the_Witch (C)YUZUSOFT/JUNOS INC. All Rights Reserved." `
  --archive-text "{NENeMEGURuTSUMUGiTOUKoWAKANa}"
```

`FilterManagerDerive` 在离线进程中加载 DLL，并调用：

| RVA | 作用 |
|-----|------|
| `0x0E2D0` | `FilterManager` 构造函数 |
| `0x15630` | bootstrap 派生函数，输入最终 bootstrap 字符串和 `PARAMS` |
| `0x157D0` | archive key update，输入 `UNIQUE` 和 archive seed |

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
data/static_recover/sanoba.static.drip_program.json
hxv4_key    = e4dc1d99d9d9fb1ae5f7529ee70f841bfadb13d12f4d22b99170d6cc6a62bc54
hxv4_nonce0 = d99230e02623f4a0c4f2857682b4de6dfefe820b57060e50
hxv4_nonce1 = b96f89630850dd23a13810c7718ad003936d1d4a3ae00890
```

### 9. XP3 验证和提取

使用静态派生结果验证 XP3：

```powershell
python src\common\xp3_inspect.py verify `
  --filter recovered `
  --drip-program data\static_recover\sanoba.static.drip_program.json `
  "F:\SteamLibrary\steamapps\common\sanoba witch\scn.xp3"
```

验证结果：

```text
scn.xp3: checked=26 failed=0 unresolved_filter=0
```

如果需要实际提取：

```powershell
python src\common\xp3_inspect.py extract-all out\scn `
  --filter recovered `
  --drip-program data\static_recover\sanoba.static.drip_program.json `
  "F:\SteamLibrary\steamapps\common\sanoba witch\scn.xp3"
```

因此，对当前 Sanoba Witch 样本而言，完整提取链路已经不再需要运行时 dump、调试启动或进程附加；原始 EXE 提供 bres 资源和 salt，BOOTSTRAP 提供随机 DLL，DLL 配置表提供 bootstrap suffix 和 archive unique key，最终由 `FilterManagerDerive` 在离线进程中复现运行时密钥派生。

## 自动化脚本

脚本：

```text
src/static_extract/static_xp3_recover.py
```

默认输入：

| 输入 | 默认路径或来源 |
|------|----------------|
| 游戏 EXE | `F:\SteamLibrary\steamapps\common\sanoba witch\SabbatOfTheWitch.exe` |
| bres salt | 优先 `.\salt_F44A00.bin`；不存在时从 EXE `PE RVA 0x2E4A00` 读取 |
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
| `BOOTSTRAP.rcdata.bin` | PE 资源中的加密 BOOTSTRAP |
| `BOOTSTRAP.dec` | 解密后的 BOOTSTRAP 载荷 |
| `1ae7153ed25d.dll` | BOOTSTRAP 解包出的随机 DLL |
| `PLUGIN.rcdata.bin` | 可选插件资源备份 |
| `static_recover.summary.json` | 静态流程摘要 |
| `sanoba.static.drip_program.json` | 给 `src/common/xp3_inspect.py` 使用的解密状态 |

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
digest = SHA3-384(path_key.encode("utf-16le") + salt_F44A00)

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

从 `STARTUP.TJS.dec` 的 DATA chunk 字符串池取到：

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
1ae7153ed25d.dll
```

### 5. 读取 DLL 配置表

随机 DLL 配置表位于 RVA `0x80E38`，脚本读取 label-length-value 结构。

关键字段：

```text
UNIQUE  = {NENeMEGURuTSUMUGiTOUKoWAKANa}
WARNING = Warning! Extracting this game data may infringe on author's rights.
```

### 6. 静态确定最终 bootstrap 字符串

`1ae7153ed25d.dll` 中的 `System_bootStrap_callback` 会把脚本传入的第一个参数和 DLL 配置表中的 `WARNING` 拼接后传给核心派生函数。

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
  --dll data\static_recover\1ae7153ed25d.dll `
  --out data\static_recover\sanoba.static.drip_program.json `
  --bootstrap-prefix "Sabbat_of_the_Witch (C)YUZUSOFT/JUNOS INC. All Rights Reserved." `
  --archive-text "{NENeMEGURuTSUMUGiTOUKoWAKANa}"
```

`--bootstrap-prefix` 表示脚本级 `System.bootStrap` 第一个参数。`FilterManagerDerive` 会读取 DLL 中的 `WARNING` 并追加，因此不需要手工传完整字符串。

`--archive-text` 用于模拟 archive key update：

```text
sub_100157D0(manager + 8, archive_text_utf16le, byte_len, archive_seed)
```

它不是 bootstrap 密码，而是归档级过滤状态更新输入。Sanoba 中应使用 DLL 配置表 `UNIQUE`：

```text
{NENeMEGURuTSUMUGiTOUKoWAKANa}
```

## salt 的边界

`salt_F44A00.bin` 是 8192 字节 bres salt。IDA 中它对应脱壳镜像 `.rdata` 的 `g_bres_salt_F44A00`，但它同时也以明文形式存在于原始 Steam EXE 的同一 PE RVA 映射位置。

已新增自动提取脚本：

```text
src/static_extract/recover_bres_salt.py
```

该脚本的自动化逻辑是：

1. 从原始游戏 EXE 的 PE Resources 读取加密 `STARTUP.TJS` 和 `TEXT/127` 中的 bres root key。
2. 从原始 EXE 或指定 source 的 PE RVA / 文件偏移读取 8192 字节候选 salt。
3. 用候选 salt 解密 `STARTUP.TJS`。
4. 只有解密结果以 `TJS2100\0` 开头时，才写出 `salt_F44A00.bin`。

默认即可从原始游戏 EXE 自动提取：

```powershell
python src\static_extract\recover_bres_salt.py --out salt_F44A00.bin
```

等价显式命令：

```powershell
python src\static_extract\recover_bres_salt.py `
  --source "F:\SteamLibrary\steamapps\common\sanoba witch\SabbatOfTheWitch.exe" `
  --pe-rva 0x2E4A00 `
  --out salt_F44A00.bin
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
  --source path\to\flat_memory_dump.bin `
  --image-base 0xC60000 `
  --va 0xF44A00 `
  --out salt_F44A00.bin
```

如果已知文件偏移，也可以直接指定：

```powershell
python src\static_extract\recover_bres_salt.py `
  --source "F:\SteamLibrary\steamapps\common\sanoba witch\SabbatOfTheWitch.exe" `
  --file-offset 0x2E3200 `
  --out salt_F44A00.bin
```

还可以对未知镜像做对齐扫描：

```powershell
python src\static_extract\recover_bres_salt.py `
  --source path\to\unpacked_main.bin `
  --scan `
  --scan-alignment 0x1000 `
  --out salt_F44A00.bin
```

当前主流程脚本默认优先读取：

```text
.\salt_F44A00.bin
```

只有该文件不存在时才回退：

```text
--salt-rva 0x2E4A00
```

此前失败的原因是使用了错误 RVA `0x344A00`：

```powershell
python src\static_extract\recover_bres_salt.py --pe-rva 0x344A00 --out data\static_recover\salt_test.bin
```

```text
PE RVA 0x344a00 did not verify
no valid salt recovered
```

修正为 `0x2E4A00` 后，原始 packed EXE 可以直接恢复 salt，不需要先脱壳。

## 与 LiveDump 流程的差异

| 项目 | 静态流程 |
|------|----------|
| 游戏进程 | 不启动 |
| debugger | 不使用 |
| bootstrap 字符串 | STARTUP.TJS 常量池 + DLL `WARNING` |
| context | 离线调用 DLL 内部派生函数生成 |
| DLL | 从 EXE `RCDATA/BOOTSTRAP` 解密解包 |
| 主要风险 | 需要使用正确 salt PE RVA `0x2E4A00`，以及 x86 dotnet 能加载目标 DLL |
