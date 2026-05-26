# Hxv4 加密体系解析文档

本文档完整描述 `SabbatOfTheWitch` 的 Hxv4 加密资源保护体系，包括映射表解密、DripValue VM 密钥派生、Stream Filter 四层 XOR 变换。

---

## 一、Hxv4 映射表结构

### 1.1 Chunk 位置

Hxv4 是嵌入在每个 XP3 index 中的自定义顶层 chunk：

```
XP3 Index
  ├── File chunk (标准)
  ├── File chunk (标准)
  ├── ...
  └── Hxv4 chunk (游戏自定义)
```

### 1.2 Descriptor 格式 (14 bytes)

```
+0x00  payload_offset (uint64)  — 加密表在 XP3 文件中的物理偏移
+0x08  payload_size (uint32)    — 加密表的大小
+0x0C  flags (uint16)           — bit 0 = open_flag
```

### 1.3 Payload 解密层

```
┌─────────────────────────────────────────┐
│ Hxv4 Payload (加密)                      │
│  +0x00  Poly1305 tag (16 bytes)          │
│  +0x10  XChaCha20 ciphertext             │
└─────────────────────────────────────────┘
                    │
                    ▼
         XChaCha20-Poly1305
         key   = HXV4_KEY (32 bytes)
         nonce = HXV4_NONCES[flags & 1] (24 bytes)
                    │
                    ▼
┌─────────────────────────────────────────┐
│ Hxv4 Payload (解密后)                     │
│  +0x00  uncompressed_size (uint32)       │
│  +0x04  zlib 压缩的 TJS Variant 数据       │
└─────────────────────────────────────────┘
                    │
                    ▼
              zlib.decompress
                    │
                    ▼
         big-endian TJS binary Variant
```

`HXV4_KEY` 和 `HXV4_NONCES` 从运行时 `FilterManager` 状态导出。

### 1.4 TJS Variant 格式

解密后的数据为 **big-endian** TJS binary Variant，由 `TJSBinaryReader` 解析（[src/xp3_inspect.py:582](src/xp3_inspect.py#L582)）：

| Tag | 类型 | 编码 |
|-----|------|------|
| 0/1 | null | 无额外数据 |
| 2 | string | int32 长度 + UTF-16BE 字符 |
| 3 | octet | int32 长度 + 原始字节 |
| 4 | int64 | 8 bytes big-endian |
| 5 | float64 | 8 bytes big-endian |
| -127 | array | int32 长度 + N 个值 |
| -63 | dict | int32 长度 + N 对 key-value |

### 1.5 Record 结构

每条 Hxv4 record 包含：

```
domain_hash[8]   — 域标识 (hex)
file_hash[32]    — 文件标识 (hex)
packed (uint32)  — 高 16 位 = archive_slot, 低 16 位 = filter_flag
key (uint64)     — 唯一密钥，用于 filter 派生
```

### 1.6 Entry 映射规则

```python
archive_slot = (packed >> 16) & 0xFFFF
filter_flag  = packed & 0xFFFF

# 确定 entry 偏移基数
entry_base = 1 if entries[1].name == "startup.tjs" else 0

# 映射（仅 archive_slot == 0 时有效）
xp3_entry_index = filter_flag + entry_base
```

**open_flag 规则**（重要）：

```python
open_flag = Hxv4 descriptor.flags & 1   # ✓ 正确
# 不要使用: record.filter_flag & 1       # ✗ 错误！会导致 Adler 不匹配
```

---

## 二、DripValue VM 密钥派生

### 2.1 入口函数

```
DripValueImpl_get64_from_u32 (RVA 0x19070):
  lane = value & 0x7F
  seed = value >> 7
  lo = DripValueLane_eval(lane, seed)
  hi = DripValueLane_eval(lane, ~seed)
  return (hi << 32) | lo
```

### 2.2 VM 架构

- **128 条 lane**，每条 lane 包含一段 record 程序
- 每条 record 格式：`[param (uint32), opcode_rva (uint32)]`
- 支持嵌套递归调用（`DRIP_OP_RECURSE`）
- 全局 context u32 数组（3106 个 dword）

### 2.3 操作码全集（20 种）

| 常量 | RVA | 操作 | Python 实现 |
|------|-----|------|-------------|
| `DRIP_OP_STOP` | `0x51D90` | 停止执行 | `break` |
| `DRIP_OP_ADD_IMM` | `0x17C50` | `result += param` | `result = result + param` |
| `DRIP_OP_RECURSE` | `0x17C60` | 递归子程序 | `self._eval_records(records, pc, result, nested_state)` |
| `DRIP_OP_ADD_SCRATCH` | `0x17CB0` | `result += scratch` | `result = result + scratch` |
| `DRIP_OP_MUL_SCRATCH` | `0x17CD0` | `result *= scratch` | `result = result * scratch` |
| `DRIP_OP_SCRATCH_MINUS_RESULT` | `0x17CF0` | `result = scratch - result` | `result = scratch - result` |
| `DRIP_OP_SHL_SCRATCH` | `0x17D10` | `result <<= scratch & 0xF` | `result = result << (scratch & 0xF)` |
| `DRIP_OP_SHR_SCRATCH` | `0x17D30` | `result >>= scratch & 0xF` | `result = _u32(result) >> (scratch & 0xF)` |
| `DRIP_OP_SUB_SCRATCH` | `0x17D50` | `result -= scratch` | `result = result - scratch` |
| `DRIP_OP_BIT_SHUFFLE` | `0x17D70` | bit shuffle | `result = (2 * (result & ~param)) \| ((param >> 1) & (result >> 1))` |
| `DRIP_OP_SET_IMM` | `0x17DA0` | `result = param` | `result = param` |
| `DRIP_OP_SET_SEED` | `0x17DB0` | `result = seed` | `result = seed` |
| `DRIP_OP_DEC` | `0x17DD0` | `--result` | `result = result - 1` |
| `DRIP_OP_INC` | `0x17DE0` | `++result` | `result = result + 1` |
| `DRIP_OP_NEG` | `0x17DF0` | `result = -result` | `result = -result` |
| `DRIP_OP_NOT` | `0x17E00` | `result = ~result` | `result = ~result` |
| `DRIP_OP_TABLE_IMM` | `0x17E10` | `result = context[param]` | `result = self._context_value(param)` |
| `DRIP_OP_TABLE_MASKED` | `0x17E30` | `result = context[param & result]` | `result = self._context_value(param & _u32(result))` |
| `DRIP_OP_SUB_IMM` | `0x17E50` | `result -= param` | `result = result - param` |
| `DRIP_OP_STORE_SCRATCH` | `0x17E60` | `scratch = result` | `scratch = _u32(result)` |
| `DRIP_OP_XOR_IMM` | `0x17E80` | `result ^= param` | `result = _u32(result) ^ param` |

所有算术按 **32-bit unsigned wrap** (`& 0xFFFFFFFF`)，右移为**逻辑右移**。

### 2.4 DripProgram 实现

核心类 — [src/xp3_inspect.py:173](src/xp3_inspect.py#L173)：

```python
class DripProgram:
    holder_words: tuple[int, ...]    # 6 个 uint32
    context_u32: tuple[int, ...]     # 全局 context 表 (3106 dwords)
    lanes: tuple[tuple[...], ...]    # 128 条 lane 程序

    def eval_lane(self, lane_index: int, seed: int) -> int: ...
    def get64_from_u32(self, value: int) -> int: ...
    def build_filter_state(self, key: int, open_flag: int) -> bytes: ...
```

---

## 三、BuildFilterStateFromUniqueKey

从 Hxv4 record 的 64-bit key 生成 48 字节 filter seed state。

### 3.1 算法流程

```
BuildFilterStateFromUniqueKey(state48, key64, open_flag):

  1. key 预处理:
     key_lo = key64 & 0xFFFFFFFF
     key_hi = key64 >> 32
     if open_flag == 0:          # XOR holder 常量
       key_lo ^= holder_words[2]
       key_hi ^= holder_words[3]

  2. 生成 boundary seeds:
     state[0x00:0x08] = drip_get64(key_lo)    # boundary_seed_0
     state[0x08:0x10] = drip_get64(key_hi)    # boundary_seed_1

  3. 生成 split_offset:
     bulk_offset = holder[5] + (holder[4] & (key64 >> 16))
     state[0x10:0x14] = bulk_offset

  4. 生成 bulk_key (16 bytes):
     通过反复调用 drip_get64(~key64_low) 生成 16 字节

  5. 标记位:
     state[0x2C] = 1    # has_drip
     state[0x2D] = 0    # null_mode
```

### 3.2 48-byte Seed State 布局

```
Offset  Size  Field
------  ----  -----
0x00    8     boundary_seed_0 (qword)
0x08    8     boundary_seed_1 (qword)
0x10    4     split_offset (dword)
0x14    4     reserved (zero)
0x18    16    bulk_key (16 bytes)
0x28    4     (padding / unused)
0x2C    1     has_drip = 1
0x2D    1     null_mode = 0
0x2E    2     (padding)
```

---

## 四、FilterImpl — Stream XOR Transform

### 4.1 FilterBoundary 初始化

`FilterImpl_InitState` (RVA `0x1000E240`) 将 boundary seed 初始化为 FilterBoundary 结构：

```
从 boundary seed (uint64) 提取:
  pos0 = (value >> 48) & 0xFFFF     # 高 16 位
  pos1 = (value >> 32) & 0xFFFF     # 次 16 位
  if pos0 == pos1: pos1 += 1
  key_byte = value & 0xFF
  byte0 = (value >> 8) & 0xFF
  byte1 = (value >> 16) & 0xFF
  if key_byte == 0: key_byte = 0xA5 (或 0, 取决于 null_mode)
  key = key_byte * 0x01010101        # dword key
```

### 4.2 四层 XOR 变换

`FilterRuntimeState.apply(data, offset)` — [src/xp3_inspect.py:441](src/xp3_inspect.py#L441)

#### Layer 1: Bulk XOR

```
作用范围: logical offset [0, 16)
Key:       16-byte bulk_key

for i in overlap_range:
  data[i] ^= bulk_key[logical_offset + i]
```

#### Layer 2: Split Boundary 分段

```
按 split_offset 将当前 read range 分段:

  read_start < split_offset:
    left_part  [read_start, split)      → boundary0
    right_part [split, read_end)        → boundary1
  else:
    all [read_start, read_end)          → boundary1
```

#### Layer 3: Rotated Dword Key XOR

```
对于每个 boundary range:
  for index in range(size):
    shift = ((logical_start + index) & 3) * 8
    xor_byte = (boundary_key >> shift) & 0xFF
    data[index] ^= xor_byte
```

即按文件逻辑偏移对齐位置，选择 dword key 的对应字节：

```
logical offset % 4 == 0 → key byte 0
logical offset % 4 == 1 → key byte 1
logical offset % 4 == 2 → key byte 2
logical offset % 4 == 3 → key byte 3
```

#### Layer 4: Boundary Byte XOR

```
若当前 read range 覆盖 pos0 或 pos1:
  data[pos0 - read_start] ^= byte0
  data[pos1 - read_start] ^= byte1
```

仅当 `byte0` / `byte1` 非零时才执行。

### 4.3 完整 apply() 流程

```python
def apply(self, data: bytearray, offset: int) -> bool:
    size = len(data)
    end = offset + size

    # Layer 1: Bulk XOR
    if self.bulk_key and offset < len(self.bulk_key):
        for logical in range(overlap_start, overlap_end):
            data[logical - offset] ^= self.bulk_key[logical]

    # Layer 2: Split
    split = self.split_offset
    if split <= offset:
        # Layer 3+4: all boundary1
        self._apply_boundary(data, self.boundary1, ...)
    elif split < end:
        # Layer 3+4: left → boundary0, right → boundary1
        self._apply_boundary(data, self.boundary0, ..., first_size)
        self._apply_boundary(data, self.boundary1, ..., end - split)
    else:
        # Layer 3+4: all boundary0
        self._apply_boundary(data, self.boundary0, ...)

    return True
```

---

## 五、FilterManager 运行时状态

### 5.1 结构

```
FilterManager:
  +0x00  manager[0] wrapper  → 非空时表示就绪
  +0x04  manager[1]
  +0x08  DripValueImpl*       → DripValue VM 实例指针
  +0x0C  holder_words[0]
  +0x10  holder_words[1]
  +0x14  holder_words[2]
  +0x18  holder_words[3]
  +0x1C  holder_words[4]
  +0x20  holder_words[5]
  ...    (更多状态数据)
```

### 5.2 DripValueImpl

```
DripValueImpl:
  +0x00  vtable
  +0x04  lanes[128]           → 每条 lane 0x10 bytes:
           +0x00  begin (record 起始 VA)
           +0x04  end (record 结束 VA)
           +0x08  current
           +0x0C  context 指针 (所有 lane 共享)
```

### 5.3 状态导出

通过 `inspect_manager_dump.py` 从运行时 full-memory minidump 导出（[src/inspect_manager_dump.py](src/inspect_manager_dump.py)）：

```
minidump → 解析模块列表 → 找到随机 DLL
  → 读取 g_FilterManager (RVA 0xAC9AC)
  → 遍历 128 条 Drip lane
  → 导出 context u32 表 (3106 dwords)
  → 导出 holder_words (6 x uint32)
  → 生成 drip_program.json
```

导出的 `drip_program.json` 包含：

```json
{
  "version": 1,
  "source_module": "4b048db14c27.dll",
  "source_module_base": 1903427584,
  "holder_words": [2969312960, 3765254233, 876361130, 2698729434, 920, 456],
  "context_u32": [...3106 dwords...],
  "lanes": [
    {
      "index": 0,
      "records": [[param1, op_rva1], [param2, op_rva2], ...]
    },
    ...128 lanes
  ]
}
```

此文件是**所有离线提取操作的核心依赖**。

---

## 六、Stream Filter 运行时读路径

随机 DLL 中的完整 stream read 调用链：

```
CryptoFilterStream_Read_filter_after_read  (0x10010C80)
  → wrapped IStream::Read
  → FilterImpl_Apply_vfunc(buffer, bytes_read, offset_low, offset_high)
     → FilterImpl_ApplyToReadRange  (0x1000EAE0)
        → FilterChunk_ApplyBulkXor  (0x10014B20)
        → FilterChunk_ApplyBoundaryXor  (0x1000EA20)
           → XorRangeWithRotatedDwordKey  (0x10015B80)
```

这说明内容过滤发生在**普通 IStream 读出之后**，不是在 XP3 index 解析阶段。

---

## 七、关键常量

```python
# XChaCha20-Poly1305 密钥 (从 FilterManager block 0 恢复)
HXV4_KEY = bytes.fromhex(
    "e4dc1d99d9d9fb1ae5f7529ee70f841b"
    "fadb13d12f4d22b99170d6cc6a62bc54"
)

# XChaCha20-Poly1305 Nonces (从 FilterManager block 1/2 恢复)
HXV4_NONCES = {
    0: bytes.fromhex("d99230e02623f4a0c4f2857682b4de6d"  # 前 24 字节
                     "fefe820b57060e50b7cc2580db04d993")[:24],
    1: bytes.fromhex("b96f89630850dd23a13810c7718ad003"  # 前 24 字节
                     "936d1d4a3ae008909be93eee7ac8fc3e")[:24],
}
```

---

## 八、验证结果

全包 Adler32 验证（使用 recovered filter）：

| 包文件 | 校验条目 | 失败 | 未解析 filter |
|--------|---------|------|--------------|
| allage.xp3 | 91 | 0 | 0 |
| bgimage.xp3 | 108 | 0 | 0 |
| bgm.xp3 | 93 | 0 | 0 |
| data.xp3 | 4,087 | 0 | 0 |
| evimage.xp3 | 319 | 0 | 0 |
| fgimage.xp3 | 1,554 | 0 | 0 |
| scn.xp3 | 26 | 0 | 0 |
| steam.xp3 | 3 | 0 | 0 |
| video.xp3 | 12 | 0 | 0 |
| voice.xp3 | 28,988 | 0 | 0 |

**全部 35,281 个条目校验通过，零失败**，证明离线 Python 实现与运行时过滤逻辑完全一致。

---

## 九、FileHash 算法逆向分析（2026-05-26）

### 9.1 分析目标

DLL（`1ae7153ed25d.dll`）中的 `FileHashCompute_10016900` 函数。

### 9.2 调用链

```
FileHashCompute_10016900   (0x10016900)
├── sub_1000E070(32, key_ptr, key_len)     → BLAKE2s 上下文初始化（带 key）
│   ├── sub_10014140(ctx)                  → 写入标准 SHA-256 IV（实为 BLAKE2s IV）
│   ├── sub_10014260(ctx, param_block)     → 用 key 材料 XOR 初始状态 H0-H7
│   └── sub_100159F0(ctx, key_padded, 64)  → 处理 64 字节 key block
├── sub_100159F0(ctx, file_data, size)     → 主数据更新
├── sub_100159F0(ctx, extra_utf16, len)    → 可选附加数据（文件名 UTF-16LE）
└── sub_10016B00(out_param)                → finalize，输出 32 字节
    └── sub_10013DF0(ctx, buf, 0x20)       → padding + 最终压缩 + 大端序输出
```

### 9.3 核心算法：BLAKE2s-256（Keyed Mode）

压缩函数 `sub_10012500` 通过以下特征确认为标准 BLAKE2s-256：

- 初始化常数完全匹配 BLAKE2s IV（即 SHA-256 IV）：
  `6A09E667 BB67AE85 3C6EF372 A54FF53A 510E527F 9B05688C 1F83D9AB 5BE0CD19`
- 汇编中出现 `rol ebx, 10h`（G 函数第一个旋转 = 16位），`rol ebx, 0Ch`（12位），与 BLAKE2s G 函数完全吻合
- 64 字节消息块，32 字节输出，有 counter 和 finalization flag 字段

初始化时，若有 key，使用 `sub_10014260` 将 key 材料 XOR 进 IV H0-H7，这正是 BLAKE2s keyed mode 的参数块处理方式。

### 9.4 FileHashCompute 三个关键输入参数

| 参数 | 来源 | 内容说明 |
|------|------|---------|
| **Key** | `this+4 / this+8`（DripValueImpl 衍生） | 32 字节 BLAKE2s key。由启动时 `System.bootStrap` 传入的密码 + 嵌入常量 `{NENeMEGURuTSUMUGiTOUKoWAKANa}` + `PARAMS` 块共同派生，无法在不知道密码的情况下独立重建 |
| **Data** | `a2`（TJS octet 变量） | XP3 文件条目的原始内容字节，长度为 `Size` |
| **Extra** | `a5`（可选 TJS 字符串） | 文件路径/名称的 UTF-16LE 编码（若非零则追加入哈希，贡献 `2 × char_count` 字节） |

### 9.5 DLL 内嵌常量表（起始地址 0x10080e38）

`sub_10010380` 实现了一个线性扫描的 key-value 表，包含以下三项：

| 键 | 长度 | 内容 |
|----|------|------|
| `PARAMS` | 22 字节 | 结构化配置参数：`04 06 02 00 07 01 03 05 03 00 05 04 02 01 01 02 00 80 26 02 C8 01` |
| `UNIQUE` | 60 字节 | UTF-16LE 宽字符串：`{NENeMEGURuTSUMUGiTOUKoWAKANa}`（游戏专属标识符，来自角色名） |
| `PUBKEY` | 248 字节 | PEM 格式 RSA-1024 公钥（`-----BEGIN PUBLIC KEY-----\nMIGJ...`） |
| `WARNING` | 67 字节 | ASCII 警告文本（`Warning! Extracting this game da...`） |

### 9.6 Key 派生流程（System_bootStrap_callback，0x1000EEB0）

```
TJS 脚本调用：
  System.bootStrap(password_str, pubkey_octet, params_octet, ...)
                     │                │               │
                     ▼                ▼               ▼
  v57 = password_wstr + UNIQUE宽字符串      Block = PARAMS(22B)
  v37 = c_str(v57)                          v54 = 22
  v39 = v57.length()

  sub_10015630(v37, 2*v39, Block, v54)
  → sub_100141C0(ctx, 0x20, params, 22)
    → sub_10010550(...)
      → BLAKE2s(拼接宽字符串 + PARAMS) → 32字节 DripValue key
  → g_FilterManager+8 存储此 key
```

然后 `FileHashCompute` 从 `this+4/+8` 读取这个已派生的 32 字节 key。

### 9.7 与标准算法差异对比

| 特性 | 标准 SHA-256 | 标准 HMAC-SHA256 | 此实现 |
|------|-------------|----------------|--------|
| 算法基础 | SHA-256 | SHA-256 | BLAKE2s-256 |
| Key 处理 | 无 | ipad/opad 填充 | BLAKE2s 参数块（标准 keyed） |
| Padding | `0x80` + 消息长度 | 同 SHA-256 | BLAKE2s 标准 padding |
| 输出大小 | 32 字节 | 32 字节 | 32 字节 |

**结论**：这是标准 BLAKE2s-256 keyed mode。可直接用 Python `hashlib.blake2s(data, key=key, digest_size=32)` 复现。复现脚本见 `analysis/blake2s_hash.py`。

### 9.8 相关文件

- `analysis/blake2s_hash.py`：Python 复现脚本，支持命令行和库调用
- `plugin/PackinOne.dll.i64`、`yuzuex.dll.i64`：待确认是否也包含 FileHash 调用
- DLL `1ae7153ed25d.dll.i64`：本节分析的主文件
