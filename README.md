# Sanoba Witch XP3 资源逆向分析

本仓库记录 **Sabbat of the Witch for Steam（サノバウィッチ / Sanoba Witch）** XP3 资源包的自定义加密层逆向分析与离线还原工具。

---

## 概述

游戏使用 Kirikiri/TVP 引擎的 `.xp3` 容器打包资源，但在此基础上增加了 **自定义加密层**（运行时随机 DLL + Hxv4 映射表 + DripValue VM 密钥派生 + 四层 Stream XOR Filter），使得标准 XP3 工具（如 GarBro、krkrz 等）无法直接解包。

本项目完全离线移植了上述加密逻辑到 Python，实现了：

- **10 个 XP3 包** 的完整解析与索引恢复
- **Hxv4 映射表** 的 XChaCha20-Poly1305 解密与 TJS Variant 解析
- **DripValue VM**（20 个操作码）的纯 Python 解释器
- **FilterRuntimeState** 四层 XOR 变换的静态应用

---

## 仓库结构

```plain
sanobawitchi_xp3analysis/
├── README.md                              # 本文件 — 仓库总览
├── Reverse.md                             # 逆向分析文档（全流程 + 详细链接）
├── XP3Extract.md                          # XP3 格式解析文档
├── Hxv4Ripped.md                          # Hxv4 加密体系解析文档
├── TryItOut.md                            # 复现操作文档（从零开始）
│
├── src/                                   # Python 脚本源码
│   ├── xp3_inspect.py                     #   主入口：XP3 解析 / 提取 / 验证
│   ├── inspect_manager_dump.py            #   运行时 minidump 状态导出
│   ├── watch_random_plugin_dump.py        #   运行时监控 dump 捕获
│   ├── minidump_process.py                #   全内存 minidump 创建工具
│   ├── tjs2_inspect.py                    #   TJS2100 字节码检查器
│   ├── ida_tvp_xp3_labels.py              #   IDA Pro 标签辅助脚本
│   └── parse_dialogue.py                  #   编译后 KAG 脚本对话解析器
│
├── data/                                  # 参考数据文件
│   ├── manager_ready.drip_program.json    #   DripValue VM 核心状态（离线提取必需）
│   ├── scn.hxv4.json                      #   scn.xp3 的 Hxv4 映射表（全量 27 条记录）
│   └── scn.filter_states.json             #   scn.xp3 的 per-entry filter state
│
├── sample/                                # 文件格式样本（以 scn.xp3 为样例）
│   ├── scn.xp3                            #   完整 scn.xp3 文件 (2.2 MB, 26 entry)
│   ├── xp3_header.bin                     #   XP3 文件头 (64 bytes)
│   ├── scn_index_decompressed.bin         #   解压后的 XP3 index (2888 bytes)
│   ├── scn_hxv4_descriptor.bin            #   Hxv4 chunk descriptor (14 bytes)
│   ├── scn_hxv4_encrypted_payload.bin     #   Hxv4 加密 payload (1335 bytes)
│   └── scn.filter_states.json             #   scn.xp3 的 filter state 样例
│
└── output/                                # 完整提取结果（以 scn.xp3 为例）
    └── scn/
        ├── manifest.jsonl                 #   提取清单（26 条，含 Adler32 校验）
        └── scn/
            ├── entry_00001_5001.bin       #   提取的二进制文件（mdf 容器，zlib 压缩）
            ├── entry_00002_5002.bin       #
            ├── ...                        #   共 26 个 bin 文件，全部 Adler32 校验通过
            └── entry_00026_501a.bin       #
```

---

## 提取结果

| 包文件 | 条目数 | 状态 | 典型内容 |
| -------- | -------- | ------ | ---------- |
| `allage.xp3` | 91 | 全部成功 | 全年龄版资源 |
| `bgimage.xp3` | 108 | 全部成功 | 背景图像 |
| `bgm.xp3` | 93 | 全部成功 | 背景音乐 (OGG) |
| `data.xp3` | 4,087 | 全部成功 | 游戏核心数据 |
| `evimage.xp3` | 319 | 全部成功 | 事件图像 |
| `fgimage.xp3` | 1,554 | 全部成功 | 前景图像 |
| **`scn.xp3`** | **26** | **全部成功（见 output/）** | **场景脚本 (KAG)** |
| `steam.xp3` | 3 | 全部成功 | Steam 集成数据 |
| `video.xp3` | 12 | 全部成功 | 视频文件 |
| `voice.xp3` | 28,988 | 全部成功 | 语音文件 |

---

## 核心技术栈

| 层次 | 组件 | 算法/技术 |
| ------ | ------ | ----------- |
| 容器 | XP3 Archive | 自定义 index offset (0x20 qword) |
| 索引 | zlib compressed index | 标准 XP3 File/info/segm/adlr chunk |
| 映射 | Hxv4 Table | **XChaCha20-Poly1305** + zlib + TJS Variant |
| 派生 | DripValue VM | 128 条 lane × N 条 record，20 个操作码 |
| 过滤 | FilterRuntimeState | 四层 XOR（Bulk / Split Boundary / Rotated Dword / Boundary Byte） |
| 校验 | Adler32 | 标准 XP3 adlr chunk 校验 |

---

## 快速开始（使用仓库内 scn.xp3 样本）

```powershell
# 1. 验证 scn.xp3 的 filter 正确性
python src/xp3_inspect.py verify ./sample/scn.xp3 \
  --filter recovered --drip-program ./data/manager_ready.drip_program.json

# 2. 提取 scn.xp3 全部内容
python src/xp3_inspect.py extract-all ./output_test/scn ./sample/scn.xp3 \
  --filter recovered --drip-program ./data/manager_ready.drip_program.json

# 3. 查看 Hxv4 映射表
python src/xp3_inspect.py hxv4 ./sample/scn.xp3 --samples 30 \
  --drip-program ./data/manager_ready.drip_program.json
```

提取结果（26/26 成功，filter_applied=true，adler_ok=true）已预置于 [output/scn/](output/scn/)。

---

## 文档导航

- **[Reverse.md](Reverse.md)** — 逆向分析全流程，包含代码引用链接
- **[XP3Extract.md](XP3Extract.md)** — XP3 容器格式详解
- **[Hxv4Ripped.md](Hxv4Ripped.md)** — Hxv4 加密体系完整分析
- **[TryItOut.md](TryItOut.md)** — 一步步复现操作指南

---

## 环境要求

- Python 3.9+
- PyCryptodome (`pip install pycryptodome`)
- Windows 环境（运行时 dump 捕获需要；离线提取可跨平台）

---

## 许可说明

本项目为逆向工程研究目的创建，仅应用于已合法购买的游戏资源备份与格式分析。仓库中的脚本和分析文档均基于对游戏程序的静态/动态分析独立编写，不包含游戏的原始代码或资源文件。
