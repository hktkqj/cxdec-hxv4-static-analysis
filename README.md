# Sanoba Witch XP3 资源逆向分析

本仓库记录 **Sabbat of the Witch for Steam / Sanoba Witch** 的 XP3 资源保护分析与提取工具。

当前项目保留两条路线：

| 路线 | 状态 | 用途 |
|------|------|------|
| 纯静态分析与提取 | 当前推荐 | 不启动游戏、不附加调试器，直接从原始 EXE 和 XP3 文件恢复解密状态 |
| 动态 dump / 运行时抓取 | 历史流程与交叉验证 | 在静态流程未打通前，通过运行时 dump 或断点抓参取得 FilterManager 状态 |

核心结论：Sanoba 当前样本已经可以走纯静态流程得到可用的 `drip_program.json`，不再需要运行时 dump。

## 纯静态分析与提取

静态流程入口：

```powershell
python src\static_extract\static_xp3_recover.py
```

该流程完成的工作：

1. 从原始 `SabbatOfTheWitch.exe` 的 PE Resources 提取 `STARTUP.TJS`、`BOOTSTRAP`、`PLUGIN` 和 `TEXT/127`。
2. 从原始 EXE `PE RVA 0x2E4A00` 读取 0x2000 字节 bres salt，并用 `STARTUP.TJS -> TJS2100\0` 校验。
3. 用 `SHA3-384(path_key_utf16le + salt) + ChaCha8` 解密 bres:// 资源。
4. 解析 `STARTUP.TJS` 的 TJS2 常量池，取得 BOOTSTRAP URL 和脚本级 `System.bootStrap` 参数。
5. 解密 `BOOTSTRAP`，跳过 8 字节 header 后 zlib 解压出随机加密 DLL。
6. 读取 DLL 配置表中的 `UNIQUE` 和 `WARNING`。
7. 按 DLL 内 `System_bootStrap_callback` 的真实逻辑拼出最终 bootstrap 字符串。
8. 调用 `FilterManagerDerive` 离线加载 DLL，执行内部派生函数，生成 `data/static_recover/sanoba.static.drip_program.json`。
9. 使用该 JSON 验证或提取 XP3。

验证 `scn.xp3`：

```powershell
python src\static_extract\static_xp3_recover.py `
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

详细文档：

- [纯静态 FilterManager 派生流程](docs/static/DeriveFilterManager_Static.md)
- [XP3 容器结构解析](docs/core/XP3Extract.md)
- [Hxv4 / DripValue / FilterRuntimeState 分析](docs/core/Hxv4Ripped.md)

## 动态 Dump / 运行时抓取

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
src/dynamic_capture/build_complete_drip.py
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
│   └── recover_bres_salt.py        # 从原始 EXE 提取并校验 bres salt
│
├── dynamic_capture/                # 动态 dump / 运行时抓取
│   ├── capture_bootstrap_args.py   # 抓取 System.bootStrap 参数
│   ├── watch_random_plugin_dump.py # 监控随机 DLL 并创建 dump
│   ├── inspect_manager_dump.py     # 从 dump 导出 FilterManager 状态
│   ├── minidump_process.py         # 创建 full-memory minidump
│   └── build_complete_drip.py      # 合并 live dump context 与 Hxv4 参数
│
└── common/                         # 两条路线共用代码
    ├── xp3_inspect.py              # XP3 验证 / 提取 / Hxv4 解析主入口
    ├── decrypt_bres_resource.py    # bres:// SHA3-384 + ChaCha8 解密
    ├── tjs2_inspect.py             # TJS2100 字节码检查
    ├── parse_dialogue.py           # KAG 对话解析
    ├── read_dll_config.py          # DLL 配置表读取
    ├── compare_drip.py             # drip_program 对比
    ├── disasm_bootstrap.py         # BOOTSTRAP DLL 辅助反汇编
    └── ida_tvp_xp3_labels.py       # IDA 标签辅助
```

## 文档结构

```plain
docs/
├── static/
│   └── DeriveFilterManager_Static.md      # 当前推荐的纯静态闭环
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
python src\static_extract\static_xp3_recover.py
```

指定 salt 来源程序和 PE RVA：

```powershell
python src\static_extract\static_xp3_recover.py `
  --runtime-exe "F:\SteamLibrary\steamapps\common\sanoba witch\SabbatOfTheWitch.exe" `
  --salt-rva 0x2E4A00
```

指定 salt 来源程序和文件偏移：

```powershell
python src\static_extract\static_xp3_recover.py `
  --runtime-exe "F:\SteamLibrary\steamapps\common\sanoba witch\SabbatOfTheWitch.exe" `
  --salt-file-offset 0x2E3200
```

单独恢复 bres salt：

```powershell
python src\static_extract\recover_bres_salt.py --out salt_F44A00.bin
```

验证 XP3：

```powershell
python src\common\xp3_inspect.py verify `
  --filter recovered `
  --drip-program data\static_recover\sanoba.static.drip_program.json `
  "F:\SteamLibrary\steamapps\common\sanoba witch\scn.xp3"
```

提取 XP3：

```powershell
python src\common\xp3_inspect.py extract-all out\scn `
  --filter recovered `
  --drip-program data\static_recover\sanoba.static.drip_program.json `
  "F:\SteamLibrary\steamapps\common\sanoba witch\scn.xp3"
```

## 环境要求

- Python 3.9+
- PyCryptodome
- .NET 8 x86 runtime / SDK，用于运行 `tools/FilterManagerDerive`
- Windows 环境；纯静态分析不需要启动游戏，动态 dump 工具需要 Windows 调试和进程读取 API

## 许可说明

本项目仅用于逆向工程研究和已合法购买资源的格式分析。仓库中的脚本和文档基于静态/动态分析独立编写，不包含游戏原始代码或资源文件。
