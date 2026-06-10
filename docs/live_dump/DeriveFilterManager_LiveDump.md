# DeriveFilterManager LiveDump Flow

本文保留早期 LiveDump 版本的流程和结论。该流程在静态 bootstrap 字符串尚未确认时使用，依赖运行时 dump 或运行时抓参取得正确的 `context_u32`，再补齐 Hxv4 参数生成可用的 `drip_program.json`。

当前推荐流程已迁移到：

```text
docs/static/DeriveFilterManager_Static.md
```

## 适用场景

LiveDump 流程适用于以下情况：

| 场景 | 原因 |
|------|------|
| 未静态确认最终 bootstrap 字符串 | `sub_10015630` 输入错误会导致 `context_u32` 大量不同 |
| 未能静态解包 BOOTSTRAP DLL | 只能从运行时临时 DLL 或内存镜像取得模块 |
| 需要对比运行时对象状态 | `holder_words`、`context_u32`、`lanes` 可直接从 dump 校验 |

## 早期目标

目标是避免手写 DripValue/FilterManager 逻辑，而是复用 DLL 内部函数生成结构：

1. 加载随机加密 DLL。
2. 调用 `FilterManager` 构造函数。
3. 用真实 `System.bootStrap` 参数调用 `sub_10015630`。
4. 用 archive unique key 调用 `sub_100157D0`。
5. 导出 `hxv4_key`、`hxv4_nonce0`、`hxv4_nonce1`、`holder_words`、`context_u32`、`lanes`。

已验证样本对应 DLL：

```text
1ae7153ed25d.dll
```

已验证样本对应 UNIQUE：

```text
{NENeMEGURuTSUMUGiTOUKoWAKANa}
```

## 运行时抓参脚本

早期新增脚本：

```text
src/dynamic_capture/capture_bootstrap_args.py
```

用途：启动或附加游戏，抓取 DLL 内 `sub_10015630` 调用前的 32 位栈参数。

断点：

```text
random_dll_base + 0xF269
```

命中时读取：

```text
[esp]       bootstrap UTF-16LE 字符串指针
[esp+4]     bootstrap 字节长度
[esp+8]     PARAMS 指针
[esp+0xC]   PARAMS 字节长度
```

输出字段：

```text
bootstrap_text
bootstrap_utf16le_hex
params_hex
module_base
module_path
breakpoint_addr
breakpoint_rva
```

默认 late-attach 模式：

```powershell
python src\dynamic_capture\capture_bootstrap_args.py `
  --exe "D:\Games\TargetGame\TargetGame.exe" `
  --out data\bootstrap_capture.json
```

如果游戏已正常启动，可手动附加：

```powershell
Get-Process -Name TargetGame | Select-Object Id

python src\dynamic_capture\capture_bootstrap_args.py `
  --pid <PID> `
  --out data\bootstrap_capture.json `
  --keep-running
```

## 运行时问题

直接 debugger 启动游戏时会报错退出，因此脚本改为 late-attach：

1. 普通方式启动游戏。
2. 轮询模块列表。
3. 发现 `%TEMP%\krkr_...\<12hex>.dll` 后再 `DebugActiveProcess`。
4. 设置断点并抓取参数。

在 64-bit Python 枚举 32-bit WOW64 模块时，`CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32)` 可能返回 `ERROR_PARTIAL_COPY (299)`；脚本已加入重试。

## 早期合并方案

当时发现：

```text
FilterManagerDerive 离线 lanes records 与 live dump 一致
context_u32 大量不一致
```

原因是 bootstrap-text 未确认，导致 `sub_10015630` 写入的上下文不同。

因此采用临时合并方案：

1. 从 `manager_ready.drip_program.json` 保留 live dump 的 `context_u32` 和 `lanes`。
2. 补入已确认的 Hxv4 参数。
3. 输出 `data/target_complete.drip_program.json`。

Hxv4 参数：

```text
hxv4_key    = e4dc1d99d9d9fb1ae5f7529ee70f841bfadb13d12f4d22b99170d6cc6a62bc54
hxv4_nonce0 = d99230e02623f4a0c4f2857682b4de6dfefe820b57060e50
hxv4_nonce1 = b96f89630850dd23a13810c7718ad003936d1d4a3ae00890
```

验证结果：

```powershell
python src\common\xp3_inspect.py verify sample\scn.xp3 `
  --filter recovered `
  --drip-program data\target_complete.drip_program.json `
  --verbose
```

```text
scn.xp3: checked=26 failed=0 unresolved_filter=0
```

## 与静态流程的差异

| 项目 | LiveDump 流程 |
|------|---------------|
| 游戏进程 | 需要启动，或需要已有 dump |
| debugger | 可能需要 late attach |
| bootstrap 字符串 | 运行时抓参或 dump 反推 |
| context | 来自运行时 `manager_ready.drip_program.json` |
| DLL | 可来自运行时临时 DLL、dump 或手工 BOOTSTRAP 解包 |
| 主要输出 | `data/target_complete.drip_program.json` |

## 当前状态

LiveDump 流程仍可作为交叉验证路径保留，但不再是当前静态流程的必要步骤。

静态流程已经确认最终 bootstrap 字符串为：

```text
Sabbat_of_the_Witch (C)YUZUSOFT/JUNOS INC. All Rights Reserved.Warning! Extracting this game data may infringe on author's rights.
```

因此 `context_u32` 可以由 `FilterManagerDerive` 离线正确派生，不再需要 live dump。
