# bres/BOOTSTRAP/Hxv4 XP3 资源静态提取分析

本仓库存储 **Sabbat of the Witch for Steam** 以及使用 *类似加密* 的 XP3 资源保护分析文档与提取工具；当前静态脚本已整理为面向同一类 bres/BOOTSTRAP/Hxv4 加密的恢复流程。

当前项目保留两条路线：

| 路线 | 状态 | 用途 |
| ------ | ------ | ------ |
| 纯静态分析与提取 | 当前推荐 | 不启动游戏、不附加调试器，直接从原始 EXE 和 XP3 文件恢复解密状态 |
| 动态 dump / 运行时抓取 | 已弃用 | 通过运行时 dump 或断点抓参取得 FilterManager 状态 |

满足相同加密密钥（或者说同一款游戏）的样本可以走纯静态流程得到可用的 `drip_program.json`，不再需要运行时 dump。该流程已用于 Sanoba Witch 和 CafeStella 静态适配；不同游戏通常只需要确认 EXE 路径、salt 位置、DLL 配置表 RVA 和小范围 XP3 验证结果。

## 纯静态分析与提取

完整数据流请首先参考 [Flowchart](./Flowchart.md)。

静态流程入口：

```powershell
python src\static_extract\static_xp3_recover.py --exe path\to\game.exe
```

该流程完成的工作：

1. 从目标 EXE 的 PE Resources 提取 `STARTUP.TJS`、`BOOTSTRAP`、可选 `PLUGIN` 和 `TEXT/127`。
2. 默认先扫描目标 EXE 汇编中的 `salt_ptr` / `0x2000` 初始化赋值；若原始 packed EXE 没有可见 xref，则回退到 `forcedataxp3` / `TEXT` / `V2Link` 数据邻域定位 0x2000 字节 bres salt，并用 `STARTUP.TJS -> TJS2100\0` 校验；也可显式传 `--salt-rva` / `--salt-file` / `--salt-file-offset`。
3. 用 `SHA3-384(path_key_utf16le + salt) + ChaCha8` 解密 bres:// 资源。
4. 解析 `STARTUP.TJS` 的 TJS2 常量池，取得 BOOTSTRAP URL 和脚本级 `System.bootStrap` 参数。
5. 解密 `BOOTSTRAP`，跳过 8 字节 header 后 zlib 解压出随机加密 DLL。
6. 读取 DLL 配置表中的 `UNIQUE` 和 `WARNING`。
7. 按 DLL 内 `System_bootStrap_callback` 的真实逻辑拼出最终 bootstrap 字符串。
8. 调用 `FilterManagerDerive` 离线加载 DLL，执行内部派生函数，生成 `data/static_recover/drip_program.json`。
9. 使用该 JSON 验证或提取 XP3。

验证 `scn.xp3`：

```powershell
python src\static_extract\static_xp3_recover.py `
  --exe "F:\SteamLibrary\steamapps\common\sanoba witch\SabbatOfTheWitch.exe" `
  --xp3 "F:\SteamLibrary\steamapps\common\sanoba witch\scn.xp3" `
  --verify
```

已验证结果：

```text
scn.xp3: checked=26 failed=0 unresolved_filter=0
hxv4_key    = e4dc1d99d9d9fb1ae5f7529ee70f841bfadb13d12f4d22b99170d6cc6a62bc54
hxv4_nonce0 = d99230e02623f4a0c4f2857682b4de6dfefe820b57060e50
hxv4_nonce1 = b96f89630850dd23a13810c7718ad003936d1d4a3ae00890
```

适配其他游戏时，建议把所有中间产物写到目标游戏目录的 `temp` 下，并先做有限验证：

```powershell
$game = "F:\SteamLibrary\steamapps\common\CafeStella"

python src\static_extract\static_xp3_recover.py `
  --exe "$game\CafeStella.exe" `
  --work-dir "$game\temp\static_recover" `
  --debug

python src\common\xp3_inspect.py verify `
  "$game\main.xp3" "$game\scn.xp3" "$game\data.xp3" `
  --filter recovered `
  --drip-program "$game\temp\static_recover\drip_program.json" `
  --max-entries 20 `
  --verbose
```

详细文档：

- [纯静态 FilterManager 派生流程](docs/static/DeriveFilterManager_Static.md)
- [不同游戏的静态流程适配](docs/static/Porting_Static_Flow.md)
- [XP3 容器结构解析](docs/core/XP3Extract.md)
- [Hxv4 / DripValue / FilterRuntimeState 分析](docs/core/Hxv4Ripped.md)

## 动态 Dump / 运行时抓取 [Deprecated]

动态流程是早期路线，用于在最终 bootstrap 字符串尚未静态确认时，从运行时对象中获得正确状态。

该流程完成的工作：

1. 正常启动或附加游戏进程。
2. 监控 `%TEMP%\krkr_...\<random>.dll` 随机插件加载。
3. 在随机 DLL 的 `System_bootStrap_callback` 内部调用前后抓取参数，或等待 FilterManager 初始化完成后 dump 进程内存。
4. 从 full-memory minidump 导出 `context_u32`、`lanes`、`holder_words`。
5. 将 live dump 的 context 与已确认的 Hxv4 key/nonce 合并为 `data/sanoba_complete.drip_program.json`。
6. 用 `src\common\xp3_inspect.py` 验证或提取 XP3。

主要脚本：

```text
src/dynamic_capture/capture_bootstrap_args.py
src/dynamic_capture/watch_random_plugin_dump.py
src/dynamic_capture/inspect_manager_dump.py
src/dynamic_capture/minidump_process.py
```

详细文档：

- [LiveDump 版 FilterManager 派生流程](docs/live_dump/DeriveFilterManager_LiveDump.md)
- [从零复现操作记录](docs/usage/TryItOut.md)
- [总体逆向分析流程](docs/core/Reverse.md)
- [DLL 配置差异分析](docs/diff/DllDiff.md)

## 代码结构

```plain
src/
├── static_extract/                 # 纯静态提取闭环
│   ├── static_xp3_recover.py       # 静态恢复 bres 资源、DLL 和 drip_program.json
│   ├── bres_bootstrap.py           # bres/BOOTSTRAP 派生共用逻辑
│   └── recover_bres_salt.py        # 从原始 EXE 提取并校验 bres salt
│
├── dynamic_capture/                # 动态 dump / 运行时抓取
│   ├── capture_bootstrap_args.py   # 抓取 System.bootStrap 参数
│   ├── watch_random_plugin_dump.py # 监控随机 DLL 并创建 dump
│   ├── inspect_manager_dump.py     # 从 dump 导出 FilterManager 状态
│   ├── filter_manager_dump.py      # FilterManager/Drip 状态导出逻辑
│   ├── minidump_reader.py          # full-memory minidump 读取
│   └── minidump_process.py         # 创建 full-memory minidump
│
└── common/                         # 两条路线共用代码
    ├── pe_image.py                 # PE section/resource 读取
    ├── xp3_inspect.py              # XP3 验证 / 提取 / Hxv4 解析主入口
    ├── decrypt_bres_resource.py    # bres:// SHA3-384 + ChaCha8 解密
    ├── tjs2_inspect.py             # TJS2100 字节码检查
    └── parse_dialogue.py           # KAG 对话解析

tools/
└── FilterManagerDerive/            # x86 .NET 离线派生 FilterManager 状态
    ├── FilterManagerDerive.cs      # 派生逻辑实现
    └── FilterManagerDerive.sln
```

## 文档结构

```plain
docs/
├── static/
│   ├── DeriveFilterManager_Static.md      # 当前推荐的纯静态闭环
│   └── Porting_Static_Flow.md             # 不同游戏的静态流程适配
├── live_dump/
│   └── DeriveFilterManager_LiveDump.md    # 早期动态 dump 闭环
├── core/
│   ├── Reverse.md                         # 总体逆向分析流程
│   ├── XP3Extract.md                      # XP3 容器格式
│   └── Hxv4Ripped.md                      # Hxv4 / DripValue / FilterRuntimeState
├── diff/
│   └── DllDiff.md                         # 不同随机 DLL 配置差异
└── usage/
    └── TryItOut.md                        # 历史复现命令和实验记录
```

## 常用命令

生成静态 `drip_program.json`：

```powershell
python src\static_extract\static_xp3_recover.py --exe path\to\game.exe
```

显式指定 salt PE RVA：

```powershell
python src\static_extract\static_xp3_recover.py `
  --exe path\to\game.exe `
  --salt-rva 0x........
```

指定 salt 文件偏移：

```powershell
python src\static_extract\static_xp3_recover.py `
  --exe path\to\game.exe `
  --salt-file-offset 0x2E3200
```

单独恢复 bres salt：

```powershell
python src\static_extract\recover_bres_salt.py --exe path\to\game.exe --out bres_salt.bin
```

验证 XP3：

```powershell
python src\common\xp3_inspect.py verify `
  --filter recovered `
  --drip-program data\static_recover\drip_program.json `
  "F:\SteamLibrary\steamapps\common\sanoba witch\scn.xp3"
```

有限验证 XP3：

```powershell
python src\common\xp3_inspect.py verify `
  --filter recovered `
  --drip-program data\static_recover\drip_program.json `
  --max-entries 20 `
  "F:\SteamLibrary\steamapps\common\CafeStella\main.xp3"
```

静态恢复时透传有限验证：

```powershell
python src\static_extract\static_xp3_recover.py `
  --exe "F:\SteamLibrary\steamapps\common\CafeStella\CafeStella.exe" `
  --work-dir "F:\SteamLibrary\steamapps\common\CafeStella\temp\static_recover" `
  --xp3 "F:\SteamLibrary\steamapps\common\CafeStella\main.xp3" `
  --verify `
  --verify-max-entries 20 `
  --debug
```

提取 XP3：

```powershell
python src\common\xp3_inspect.py extract-all out\scn `
  --filter recovered `
  --drip-program data\static_recover\drip_program.json `
  "F:\SteamLibrary\steamapps\common\sanoba witch\scn.xp3"
```

`tools/tjs2-decompiler` 用于把提取出的 `TJS2100` 字节码还原为可读的 TJS2 源码。本仓库在该工具相关能力上感恩 [crate-1556/tjs2-decompiler](https://github.com/crate-1556/tjs2-decompiler) 项目。

## 环境要求

- Python 3.9+
  - PyCryptodome 用于 SipHash 和 BLAKE2s 实现
  - Pillow 用于CG合成
- PyCryptodome
- .NET 8 x86 runtime / SDK，用于运行 `tools/FilterManagerDerive`
- Windows 环境；纯静态分析不需要启动游戏，动态 dump 工具需要 Windows 调试和进程读取 API

## 第三方项目

[crate-1556/tjs2-decompiler](https://github.com/crate-1556/tjs2-decompiler) 是面向 Kirikiri / 吉里吉里引擎的 TJS2（TJS2100）字节码反编译器，可将编译后的 TJS2 字节码转换为可读、可分析的 TJS2 源码，并支持单文件、目录批量、递归目录、反汇编和文件信息查看等用法。本仓库曾使用 `tools/tjs2-decompiler` 作为脚本逻辑分析辅助工具。

[vn-tools/tlg2png](https://github.com/vn-tools/tlg2png) Converts TLG images to PNG. TLG images are used by games based on Kirikiri engine.

## AI 辅助创作、分析声明

本仓库的部分文档整理、代码注释、分析思路归纳和脚本实现过程可能使用 AI 工具辅助完成。AI 辅助内容均以人工审阅、验证和修订后的结果为准，不代表对相关游戏、引擎或第三方项目权利归属的声明或变更。

## 许可说明

本项目仅用于逆向工程研究和已合法购买资源的格式分析。仓库中的脚本和文档基于静态/动态分析独立编写，不包含游戏原始代码或资源文件。
