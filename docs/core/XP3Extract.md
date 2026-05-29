# XP3 格式解析文档

本文档详细描述 `SabbatOfTheWitch` 使用的 XP3 容器格式，包括标准结构与游戏自定义变体。

---

## 一、XP3 文件格式概述

XP3 是 Kirikiri/TVP 引擎使用的资源归档格式。一个 XP3 文件由以下部分组成：

```
+------------------+
| XP3 Header       |  固定头部，包含 magic 和索引位置
+------------------+
| File Data        |  实际文件数据（可能经 zlib 压缩）
+------------------+
| Index            |  文件索引（可能经 zlib 压缩）
+------------------+
```

---

## 二、Header 结构

### 2.1 标准 XP3 头部

```
Offset  Size  Field
------  ----  -----
0x00    11    magic: "XP3\r\n \n\x1a\x8bg\x01"
0x0B    8     index_offset (uint64, little-endian)
```

标准 XP3 中，`index_offset` 直接指向 Index 区域的起始位置。

### 2.2 游戏自定义变体

本游戏修改了 index offset 存储方式：

```
Offset  Size  Field
------  ----  -----
0x00    11    magic: "XP3\r\n \n\x1a\x8bg\x01"
0x0B    8     index_offset = 0x17 (假值)
0x13    ...   (未使用 / 附加数据)
0x20    8     真实 index_offset (uint64, little-endian)  ← 游戏自定义
```

**检测逻辑**（[src/common/xp3_inspect.py:501](../../src/common/xp3_inspect.py#L501)）：

```python
def resolve_index_offset(blob: bytes) -> int:
    header_offset = _read_u64(blob, 11)
    if header_offset == 0x17 and len(blob) >= 0x28:
        candidate = _read_u64(blob, 0x20)
        if 0 < candidate < len(blob):
            return candidate
    return header_offset
```

---

## 三、Index 解析

### 3.1 Index Header

位于 `resolve_index_offset()` 返回的偏移处：

```
Offset  Size  Field
------  ----  -----
+0x00   1     flag: 0 = 未压缩, 1 = zlib 压缩
```

**flag = 0 时**：
```
+0x01   8     index_size (uint64)
+0x09   N     原始 index 数据
```

**flag = 1 时**：
```
+0x01   8     compressed_size (uint64)
+0x09   8     original_size (uint64)
+0x11   N     zlib 压缩的 index 数据
```

### 3.2 Index 内部结构

Index 由连续的 chunk 组成，每个 chunk：

```
Offset  Size  Field
------  ----  -----
+0x00   4     tag (4-char 标识符)
+0x04   8     chunk_size (uint64, 不含 tag 和 size 字段)
+0x0C   N     chunk body
```

#### 3.2.1 File Chunk

Tag: `File`。每个文件条目由以下子 chunk 组成：

**info 子 chunk**（tag: `info`）：
```
Offset  Size  Field
------  ----  -----
+0x00   4     flags (bit 31 = encrypted/protected)
+0x04   8     original_size (uint64)
+0x0C   8     archived_size (uint64)
+0x14   2     name_length (uint16, 字符数)
+0x16   N     name (UTF-16LE, name_length * 2 bytes)
```

**segm 子 chunk**（tag: `segm`）：
```
每条 segment 记录 (28 bytes):
+0x00   4     flags (bit 0 = compressed)
+0x04   8     archive_offset (uint64, 在 XP3 文件中的物理偏移)
+0x0C   8     original_size (uint64)
+0x14   8     archived_size (uint64)
```

段读取流程：
```
iter_entry_chunks():
  for each segment:
    raw = blob[archive_offset : archive_offset + archived_size]
    if compressed:
      raw = zlib.decompress(raw)
    yield logical_offset, raw
```

**adlr 子 chunk**（tag: `adlr`）：
```
+0x00   4     adler32 (uint32) — 完整明文数据的 Adler32 校验值
```

### 3.3 自定义顶层 Chunk：Hxv4

除标准 chunk 外，本游戏在每个 XP3 的 index 中嵌入了一个 `Hxv4` 自定义 chunk：

```
Hxv4 descriptor (14 bytes):
+0x00   8     payload_offset (uint64, 在 XP3 中的物理偏移)
+0x08   4     payload_size (uint32)
+0x0C   2     flags (uint16)
```

Hxv4 的详细解析见 [Hxv4Ripped.md](Hxv4Ripped.md)。

---

## 四、Entry 映射规则

### 4.1 Warning Entry

部分包的第 0 个 entry 是 placeholder/warning entry：

```
index = 0
flags = 0
original_size == archived_size (通常 ~910 bytes)
```

`extract-all` 默认跳过此 entry（可通过 `--include-warning` 包含）。

### 4.2 Hxv4 → XP3 Entry 映射

Hxv4 record 通过 `filter_flag` 和 `archive_slot` 映射到物理 XP3 entry：

```
entry_base = 1 if entries[1].name == "startup.tjs" else 0
xp3_entry_index = filter_flag + entry_base  (仅当 archive_slot == 0)
```

示例：

| 包 | 有 startup.tjs? | entry_base | 映射规则 |
|----|:---:|:---:|---|
| `data.xp3` | 是 | 1 | `xp3_index = filter_flag + 1` |
| `bgm.xp3` | 否 | 0 | `xp3_index = filter_flag` |
| `evimage.xp3` | 否 | 0 | `xp3_index = filter_flag` |
| `voice.xp3` | 否 | 0 | `xp3_index = filter_flag` |

---

## 五、Entry 文件名

### 5.1 Unicode 顺序名

多数 protected entry 的文件名是短 Unicode 顺序字符：

```
data.xp3:  倁, 倂, 倃, ...
bgm.xp3:   Ｖ, Ｗ, Ｘ, ...
```

这些不是资源语义名，而是生成的名字。

### 5.2 输出文件命名策略

提取时使用稳定编号命名（[src/common/xp3_inspect.py:931](../../src/common/xp3_inspect.py#L931)）：

```
entry_<物理index>_<前几个Unicode codepoint>.bin

示例:
  entry_00001_5001.bin
  entry_00002_5002.bin
  entry_00093_505d.bin
```

---

## 六、Adler32 校验

XP3 文件在每个 `File` entry 的 `adlr` 子 chunk 中存储了明文数据的 Adler32 校验值。

```python
def calc_adler32(data: bytes) -> int:
    return zlib.adler32(data) & 0xFFFFFFFF
```

提取后对比 `actual_adler32` 与 `expected_adler32`：
- **匹配**：提取数据与原始明文一致
- **不匹配**：可能缺少过滤器（filter needed）或数据损坏

---

## 七、端到端解析流程图

```
XP3 文件 (raw bytes)
  │
  ├─ resolve_index_offset()
  │    ├─ 读取 +0x0B: header_index_offset (假值 0x17)
  │    └─ 读取 +0x20: 真实 index offset
  │
  ├─ load_index()
  │    ├─ 读取 flag (1 byte)
  │    ├─ flag==0 → 直接读取 index
  │    └─ flag==1 → zlib.decompress(index)
  │
  ├─ parse_entries()
  │    ├─ 遍历顶层 chunk
  │    ├─ File chunk:
  │    │    ├─ info → name, flags, sizes
  │    │    ├─ segm → [archive_offset, original_size, archived_size, compressed]
  │    │    └─ adlr → adler32
  │    └─ Hxv4 chunk → 加密映射表 (见 Hxv4Ripped.md)
  │
  ├─ parse_hxv4_table()
  │    → Hxv4Ripped.md
  │
  ├─ build_filter_state_map()
  │    → Hxv4Ripped.md
  │
  └─ extract_entry()
       ├─ iter_entry_chunks() → decompress segments
       ├─ FilterRuntimeState.apply() → 四层 XOR
       └─ calc_adler32() → 校验
```

---

## 附录 A — 脱壳流程

本游戏使用 `.bind` 段自加密保护主程序代码。

### A.1 手动脱壳步骤（x32dbg）

1. 使用 **x32dbg**（32-bit 版本）打开 `SabbatOfTheWitch.exe`
2. 在 `0x8E433B` 设断点 — `bind_unpack_loader` 返回后，EAX 包含计算后的 OEP
3. 确认 `EAX == 0x00639653`（预期 OEP）
4. 运行到 `0x8E4346`，单步一次进入解包后的入口
5. 使用 Scylla 修复 IAT 并 dump

### A.2 关键地址

| 地址 | 名称 | 描述 |
|------|------|------|
| `0x8E4310` | `.bind` entry stub | 调用 bind_unpack_loader，重写返回地址 |
| `0x8E4390` | `bind_unpack_loader` | 解密/装载真实 PE，重建导入表 |
| `0x639653` | 预期 OEP | 解包后程序入口 |

### A.3 主程序关键函数（固定 dump，image base `0xC60000`）

| 地址 | 函数 |
|------|------|
| `0xC95CD0` | `tTVPXP3Archive_ctor_parse_index` |
| `0xC95990` | `XP3_find_archive_header` |
| `0xC967D0` | `XP3_find_chunk` |
| `0xC966E0` | `tTVPXP3Archive_CreateStreamByIndex` |
| `0xC96D90` | `tTVPXP3ArchiveStream_ctor` |
| `0xC96F40` | `tTVPXP3ArchiveStream_prepare_segment` |
| `0xC972E0` | `tTVPXP3ArchiveStream_Read_impl` |
| `0xDE68C0` | `zlib_uncompress_wrapper` |
| `0xC9A5B0` | `tTVPStorageMedia_CreateCryptoFilterForPath` |

---

## 附录 B — 其他 Plugin DLL 分析

### PackinOne.dll

位于 `plugin/PackinOne.dll`，注册 `ProxyStorage` 和 `BasicCryptFilter<ChaCha>`，提供独立 proxy/archive storage 层。**不包含当前 protected XP3 的内容过滤逻辑**。

### yuzuex.dll（内嵌 proxyfs.dll）

位于 `plugin/yuzuex.dll`，注册 `ProxyStorage` media，参与 storage-name redirection。**不包含最终 XP3 内容解密逻辑**。

### 结论

真正的加密内容过滤层仅在运行时释放的随机 DLL 中实现。
