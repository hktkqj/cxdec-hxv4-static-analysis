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

```plain
+0x00  payload_offset (uint64)  — 加密表在 XP3 文件中的物理偏移
+0x08  payload_size (uint32)    — 加密表的大小
+0x0C  flags (uint16)           — bit 0 = open_flag
```

### 1.3 Payload 解密层

```plain
┌─────────────────────────────────────────┐
│ Hxv4 Payload (加密)                     │
│  +0x00  Poly1305 tag (16 bytes)         │
│  +0x10  XChaCha20 ciphertext            │
└─────────────────────────────────────────┘
                    │
                    ▼
         XChaCha20-Poly1305
         key   = HXV4_KEY (32 bytes)
         nonce = HXV4_NONCES[flags & 1] (24 bytes)
                    │
                    ▼
┌─────────────────────────────────────────┐
│ Hxv4 Payload (解密后)                   │
│  +0x00  uncompressed_size (uint32)      │
│  +0x04  zlib 压缩的 TJS Variant 数据    │
└─────────────────────────────────────────┘
                    │
                    ▼
              zlib.decompress
                    │
                    ▼
         big-endian TJS binary Variant
```

`HXV4_KEY` 和 `HXV4_NONCES` 从运行时 `FilterManager` 状态导出。

### 1.4 Record 结构

每条 Hxv4 record 包含：

```plain
domain_hash[8]   — 域标识 (hex)
file_hash[32]    — 文件标识 (hex)
packed (uint32)  — 高 16 位 = archive_slot, 低 16 位 = filter_flag
key (uint64)     — 唯一密钥，用于 filter 派生
```

### 1.5 Entry 映射规则

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

```plain
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
| ------ | ----- | ------ | ------------- |
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

核心类 — [src/common/xp3_inspect.py:173](../../src/common/xp3_inspect.py#L173)：

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

```plain
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

```plain
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

```plain
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

`FilterRuntimeState.apply(data, offset)` — [src/common/xp3_inspect.py:441](../../src/common/xp3_inspect.py#L441)

#### Layer 1: Bulk XOR

```plain
作用范围: logical offset [0, 16)
Key:       16-byte bulk_key

for i in overlap_range:
  data[i] ^= bulk_key[logical_offset + i]
```

#### Layer 2: Split Boundary 分段

```plain
按 split_offset 将当前 read range 分段:

  read_start < split_offset:
    left_part  [read_start, split)      → boundary0
    right_part [split, read_end)        → boundary1
  else:
    all [read_start, read_end)          → boundary1
```

#### Layer 3: Rotated Dword Key XOR

```plain
对于每个 boundary range:
  for index in range(size):
    shift = ((logical_start + index) & 3) * 8
    xor_byte = (boundary_key >> shift) & 0xFF
    data[index] ^= xor_byte
```

即按文件逻辑偏移对齐位置，选择 dword key 的对应字节：

```plain
logical offset % 4 == 0 → key byte 0
logical offset % 4 == 1 → key byte 1
logical offset % 4 == 2 → key byte 2
logical offset % 4 == 3 → key byte 3
```

#### Layer 4: Boundary Byte XOR

```plain
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

```plain
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

```plain
DripValueImpl:
  +0x00  vtable
  +0x04  lanes[128]           → 每条 lane 0x10 bytes:
           +0x00  begin (record 起始 VA)
           +0x04  end (record 结束 VA)
           +0x08  current
           +0x0C  context 指针 (所有 lane 共享)
```

### 5.3 状态导出

通过 `inspect_manager_dump.py` 从运行时 full-memory minidump 导出（[src/dynamic_capture/inspect_manager_dump.py](../../src/dynamic_capture/inspect_manager_dump.py)）：

```plain
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
  "hxv4_key": "e4dc1d99...",
  "hxv4_nonce0": "d99230e0...",
  "hxv4_nonce1": "b96f8963...",
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

### 5.4 离线解密时的使用方式

`xp3_inspect.py --filter recovered --drip-program drip_program.json` 会把 `drip_program.json` 还原为 `DripProgram` 对象（[src/common/xp3_inspect.py:196](../../src/common/xp3_inspect.py#L196)）。其中：

| JSON 字段 | 离线解密用途 |
| ----------- | -------------- |
| `hxv4_key` | 解密 XP3 内 Hxv4 payload 的 XChaCha20-Poly1305 key |
| `hxv4_nonce0` / `hxv4_nonce1` | 按 `descriptor.flags & 1` 选择 Hxv4 payload nonce |
| `holder_words` | 参与每个资源 key 的预处理、split offset 和 bulk key 派生 |
| `context_u32` | DripValue VM 的全局查表数据 |
| `lanes[].records` | DripValue VM 的 128 条 lane 程序，用来复现 `get64_from_u32()` |

完整离线流程如下：

```plain
XP3 archive
  → 读取 XP3 index
  → 找到 Hxv4 descriptor
  → 用 drip_program.hxv4_key + hxv4_nonce[flags & 1] 解密 Hxv4 payload
  → zlib 解压 Hxv4 table
  → 解析每条 Hxv4 record，得到 xp3_entry_index 和 64-bit resource key
  → 对每条 record 调用 drip_program.build_filter_state(key, open_flag)
  → 将 48-byte seed state 初始化为 FilterRuntimeState
  → XP3 entry 读取、zlib 解压后，对数据执行 FilterRuntimeState.apply()
  → 用 XP3 adlr 校验最终明文
```

关键实现对应关系：

- Hxv4 payload 解密：`decrypt_hxv4_payload()` 使用 JSON 中的 `hxv4_key` / `hxv4_nonce*`，否则才回退到代码内置常量（[src/common/xp3_inspect.py:577](../../src/common/xp3_inspect.py#L577)）。
- Hxv4 table 解析：`parse_hxv4_table()` 解密 payload、zlib 解压并解析 record（[src/common/xp3_inspect.py:658](../../src/common/xp3_inspect.py#L658)）。
- entry → filter state 映射：`build_filter_state_map()` 对每条 Hxv4 record 调用 `build_filter_state(record.key, open_flag)`，生成按 XP3 entry index 索引的 filter state 表（[src/common/xp3_inspect.py:729](../../src/common/xp3_inspect.py#L729)）。
- 条目内容还原：`extract_entry()` 先按 XP3 segment 读取并 zlib 解压，再在 `--filter recovered` 模式下对每个 chunk 调用 recovered filter，最后以 adler32 判断是否还原成功（[src/common/xp3_inspect.py:883](../../src/common/xp3_inspect.py#L883)）。

`drip_program.json` 保存了两层材料：第一层用于打开 Hxv4 映射表，第二层用于复现运行时 DripValue VM，并按每个 Hxv4 record 的 resource key 动态派生实际的 stream filter state。

---

## 六、Stream Filter 运行时读路径

随机 DLL 中的完整 stream read 调用链：

```plain
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
| -------- | --------- | ------ | -------------- |
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

## 九、FileHash 算法逆向分析

### 9.1 分析目标

本节分析 `CompoundStorageMedia` 如何把运行时逻辑资源名映射到 Hxv4 record：

```plain
逻辑 domain/path name  → pathHash  → Hxv4 record.domain_hash
逻辑 file name         → fileHash  → Hxv4 record.file_hash
```

相关函数位于 BOOTSTRAP 解包出的随机 DLL：

| 功能 | 函数 |
| ---- | ---- |
| `System.bootStrap` 回调 | `System_bootStrap_callback` / `0x1000EEB0` |
| 生成 `System.bootStrap` 返回 octet | `sub_100148B0` |
| 初始化 `CompoundStorageMedia` hashers | `sub_1000A3D0` |
| `pathHash` TJS 方法 | `sub_10009CE0` |
| `fileHash` TJS 方法 | `sub_10008F60` |
| 统一调用 hasher | `sub_10005FE0` |
| 文件名 hash trait | `FileHashCompute_10016900` |
| 路径 hash trait | `sub_100169F0` |

### 9.2 startup.tjs 中的运行时对象关系

反编译后的 `Temp/sanoba_static_auto/startup.tjs` 给出了最关键的 TJS 层调用：

```tjs
var hashKeyOctet = System.bootStrap(bootstrapPrefix, autoPathCallback);
var mediaName = (string(bootstrapPrefix)).split(":").count > 1
    ? (string(bootstrapPrefix)).split(":")[0]
    : "xp3hnp";

var media = new Storages.CompoundStorageMedia("arc", mediaName, hashKeyOctet);
autoPathCallback._.zpath = media.pathHash("");
```

Sanoba 的实际值为：

```plain
bootstrapPrefix = "Sabbat_of_the_Witch (C)YUZUSOFT/JUNOS INC. All Rights Reserved."
mediaName       = "xp3hnp"
```

`System.bootStrap(...)` 返回的 32 字节 octet 仍然会传给 `CompoundStorageMedia`，但这不等价于后续 `pathHash/fileHash` 的有效 key。见 9.4。

### 9.3 pathHash / fileHash 调用链

TJS 方法 `pathHash` 和 `fileHash` 都会进入 `sub_10005FE0`：

```plain
sub_10009CE0(pathHash)
  → sub_100064C0
    → sub_10005FE0(this, out_octet, path_hasher, input_tjs_string)

sub_10008F60(fileHash)
  → sub_10005FB0
    → sub_10005FE0(this, out_octet, file_hasher, input_tjs_string)
```

`sub_10005FE0` 会把 `CompoundStorageMedia` 构造时保存的 media name 作为 `extra` 传给 hasher：

```plain
input = TJS 方法参数
extra = this + 0x10   # startup.tjs 中的 "xp3hnp"，若为空则不传

hasher.compute(input, extra)
```

因此 hash 输入不是裸文件名，而是两个连续 update：

```plain
Update(UTF-16LE(input))
Update(UTF-16LE(extra))    # extra="xp3hnp"
Final()
```

字节流效果等价于：

```plain
UTF-16LE(input) || UTF-16LE("xp3hnp")
```

中间没有分隔符，也没有额外长度字段。

### 9.4 hash_key 的真实作用：被复制，但 key_len 为 0

此前容易误判的一点是：`System.bootStrap` 返回的 32 字节 `hash_key` 并没有作为有效 keyed hash key 使用。

构造函数链路：

```plain
new CompoundStorageMedia("arc", "xp3hnp", hash_key)
  → sub_1000A3D0(...)
    → sub_10016890(hash_key_variant)  # PathNameHashTrait
      → sub_10016680
    → sub_10016820(hash_key_variant)  # FileNameHashTrait
      → sub_10016580
```

`sub_10016680` / `sub_10016580` 的行为：

```plain
this+4 = pointer_to_internal_key_buffer
this+8 = 0
memmove(this+0x0c, hash_key_octet, min(len, 16 or 32))
```

也就是说，它们确实复制了 octet 字节，但没有把 `this+8` 设置成 `16` 或 `32`。后续计算时读取的是：

```plain
key_ptr = this+4
key_len = this+8  # 实际保持 0
```

所以本作中实际 hasher 是：

```plain
pathHash = SipHash-2-4 with 16-byte zero key
fileHash = unkeyed BLAKE2s-256
```

`hash_key` 仍然是 `System.bootStrap` 返回值，可用于确认运行时初始化流程是否正确，但它不是本作 Hxv4 lookup hash 的有效 keyed hash key。

### 9.5 pathHash：domain_hash 的计算

路径 hash trait 位于 `sub_100169F0`。其特征：

- 初始化常数为 SipHash 标准 IV：
  `somepseudorandomlygeneratedbytes`
- key 长度实际为 `0`，因此使用全零 16 字节 key 初始化
- 对输入 TJS 字符串按 UTF-16LE 字节更新
- 若 `extra` 非空，再对 `extra` 的 UTF-16LE 字节做第二次 update
- finalize 输出 8 字节，按小端显示为 Hxv4 `domain_hash`

Python 复现：

```python
domain_hash = siphash24(
    pathname.encode("utf-16le") + "xp3hnp".encode("utf-16le"),
    bytes(16),
).hex()
```

结合 `startup.tjs`，初始归档挂载时 `setupArchiveData` 的上下文是：

```tjs
incontextof [autoPathCallback, System.exePath + "data.xp3", "", 1]
```

因此初始 domain/path 参数是空字符串，而不是物理 XP3 文件名。实测：

```plain
pathHash("", extra="xp3hnp")
= 94d4a97c61498621
```

这正好命中 `bgm.xp3` Hxv4 表中所有 record 的 `domain_hash`。而：

```plain
pathHash("bgm", extra="xp3hnp")
= 384eb6c2e716927a
```

不会命中该表。结论：`pathname` 是 `Storages` 自动挂载逻辑传入的逻辑 domain/path，不是 XP3 文件名。

### 9.6 fileHash：file_hash 的计算

压缩函数 `sub_10012500` 通过以下特征确认为标准 BLAKE2s-256：

- 初始化常数完全匹配 BLAKE2s IV（即 SHA-256 IV）：
  `6A09E667 BB67AE85 3C6EF372 A54FF53A 510E527F 9B05688C 1F83D9AB 5BE0CD19`
- 汇编中出现 `rol ebx, 10h`（G 函数第一个旋转 = 16位），`rol ebx, 0Ch`（12位），与 BLAKE2s G 函数完全吻合
- 64 字节消息块，32 字节输出，有 counter 和 finalization flag 字段

但本作 `key_len == 0`，所以 `FileHashCompute_10016900` 实际走的是 unkeyed BLAKE2s-256：

```plain
BLAKE2s_Init(digest_size=32, key_len=0)
Update(UTF-16LE(filename))
Update(UTF-16LE("xp3hnp"))
Final()
```

Python 复现：

```python
file_hash = hashlib.blake2s(
    filename.encode("utf-16le") + "xp3hnp".encode("utf-16le"),
    digest_size=32,
).hexdigest()
```

注意，`filename` 必须是运行时传给 `CompoundStorageMedia.fileHash()` 的规范化逻辑文件名。裸字符串不一定可用。实测：

```plain
fileHash("bgm01", extra="xp3hnp")
= 19ffc3f9c3848e74fe7f94850554ffa7579dbeaf7e83509703cc44c3a23f3f08
```

该值没有命中 `bgm.xp3` 的 Hxv4 表，说明真实逻辑文件名并非裸 `bgm01`。后续应通过以下方式确认：

1. hook `sub_10008F60` 或 `FileHashCompute_10016900`，记录传入 TJS 字符串；
2. 或在 TJS 层追踪 `Storages` 请求 BGM 时传入 `arc://./...` 后的规范化 storage name；
3. 再使用同一算法计算 `file_hash`，与 Hxv4 表按 `(domain_hash, file_hash)` 二元组匹配。

### 9.7 Hxv4 record 定位流程

离线定位一个逻辑资源名时，按以下顺序处理：

```plain
1. 解析 XP3 index，解密并解压 Hxv4 table。
2. 从 startup.tjs 确认 CompoundStorageMedia mediaName，本作为 "xp3hnp"。
3. 确认运行时 domain/path：
   - 初始 archive domain 通常是 ""；
   - 自动挂载时使用 autopath(arg0, arg1, arg2) 中的 arg1.toLowerCase()。
4. domain_hash = pathHash(domain_path, extra=mediaName)。
5. 确认运行时规范化 filename。
6. file_hash = fileHash(filename, extra=mediaName)。
7. 在 Hxv4 records 中查找同时满足：
   record.domain_hash == domain_hash
   record.file_hash   == file_hash
8. 命中 record 后：
   - packed 低 16 位映射到 XP3 entry index；
   - record.key 用于后续 stream filter state 派生。
```

重要区分：

| 名称 | 用途 |
| ---- | ---- |
| `hxv4_key` / `hxv4_nonce*` | 解密 Hxv4 payload |
| `System.bootStrap` 返回 octet / `hash_key` | 被传给 `CompoundStorageMedia`，本作中因 key_len 为 0 不作为有效 hash key |
| `domain_hash` / `file_hash` | Hxv4 table lookup key |
| `record.key` | 命中 record 后用于内容 stream filter 派生 |

### 9.8 不同资源类型的 filename 补全规则

主程序侧目前看到的 storage 打开链路是：

```plain
TJS / KAG / 资源管理器请求
  -> TVPCreateBinaryStreamForStorageName (0xC615D0)
  -> storage media vtable
  -> CompoundStorageMediaFS_Open
  -> CompoundStorageMediaFS_MapNameToFileKey
  -> pathHash / fileHash + Hxv4 lookup
```

`TVPCreateBinaryStreamForStorageName` 和 `Scripts_execStorage_or_evalStorage_core`
负责把已经给出的 storage name 打开为 stream；在这条主程序通用路径中没有看到
“按资源类型统一补扩展名”的表。因此，Hxv4 中参与 `fileHash()` 的
`filename` 应理解为：**脚本层或资源管理器完成类型补全之后，传入 storage 层的
相对逻辑文件名**，而不是用户脚本里最初写出的裸资源名。

对当前样本已确认的形式如下：

| 资源类型 | 裸逻辑名示例 | 参与 `fileHash()` 的 filename | 证据 |
| -------- | ------------ | ----------------------------- | ---- |
| BGM 音频 | `bgm01` | `bgm01.opus` | 命中 `bgm.xp3` record 1 / XP3 entry 1 |
| BGM loop sidecar | `bgm01` | `bgm01.opus.sli` | 命中 `bgm.xp3` record 2 / XP3 entry 2；主程序 `sub_CC6520` 解析 `.sli` 文本中的 `LoopStart=` / `LoopLength=` |
| 背景图 | `学院_廊下モブa` | `学院_廊下モブa.png` | 命中 `bgimage.xp3` record 77 / XP3 entry 77 |
| 启动脚本 | `startup` / 显式 storage | `startup.tjs` | `Scripts.execStorage` 直接打开完成后的 storage name |
| 数据文件 | 显式 storage | 例如 `!cglist.csv` | 显式扩展名参与 hash |

几个容易踩错的点：

1. `filename` 不包含 `arc://./`、物理 XP3 路径或 archive 名；
2. 当前已确认的 BGM / 背景图都不带 `bgm/`、`bgimage/` 这类目录前缀；
3. `pathname` 仍来自 `startup.tjs` 的 `autopath(archivePath, domainPath, mounting)`，
   初始自动挂载域为 `""`，所以这些命中的 `domain_hash` 是
   `pathHash("", extra="xp3hnp") = 94d4a97c61498621`；
4. 图像解码器本身支持 TLG/PNG/JPEG 等格式，但主程序图像解码路径只是识别并解码
   已打开 stream，没有在当前主程序层确认到一个全局“无扩展名自动尝试
   `.tlg/.png/.jpg`”列表；具体资源管理器若隐藏扩展名，需要继续从对应 TJS/KAG
   脚本或运行时 hook 验证。

已验证 hash 示例：

```plain
fileHash("bgm01.opus", extra="xp3hnp")
= 0774d654ab8ff21a41fbd3acd81950ce8d6e3af115a1c01c954c34d4f7339433

fileHash("bgm01.opus.sli", extra="xp3hnp")
= 307ee30f554ffe810089261afcea357522842784c661116feb9db63ac0f88172

fileHash("学院_廊下モブa.png", extra="xp3hnp")
= ffa82b41844a4ac29f0e1b6b8fc1103c9f4a9127179cdf228386050de79e61df
```

后续定位未知类型时，应优先 hook 主程序 `TVPCreateBinaryStreamForStorageName`
观察完成后的 storage name；若要直接看 hash 输入，则 hook BOOTSTRAP DLL 中的
`CompoundStorageMediaFS_MapNameToFileKey` 或 `FileHashCompute_10016900`。
离线分析时可按 archive 类型枚举候选后缀，并用 `(domain_hash, file_hash)` 反查 Hxv4。

### 9.9 DLL 内嵌常量表（起始地址 0x10080e38）

`sub_10010380` 实现了一个线性扫描的 key-value 表，包含以下四项：

| 键 | 长度 | 内容 |
| ---- | ------ | ------ |
| `PARAMS` | 22 字节 | 结构化配置参数：`04 06 02 00 07 01 03 05 03 00 05 04 02 01 01 02 00 80 26 02 C8 01` |
| `UNIQUE` | 60 字节 | UTF-16LE 宽字符串：`{NENeMEGURuTSUMUGiTOUKoWAKANa}`（游戏专属标识符，来自角色名） |
| `PUBKEY` | 248 字节 | PEM 格式 RSA-1024 公钥（`-----BEGIN PUBLIC KEY-----\nMIGJ...`） |
| `WARNING` | 67 字节 | ASCII 警告文本（`Warning! Extracting this game da...`） |

### 9.10 System.bootStrap 返回 octet 的派生流程

```plain
TJS 脚本调用：
  System.bootStrap(bootstrapPrefix, autoPathCallback)

DLL 内：
  final_bootstrap = bootstrapPrefix + WARNING
  params          = PARAMS

  sub_10015630(
      manager + 8,
      final_bootstrap_utf16le,
      PARAMS
  )

  sub_100148B0(manager)
    → sub_10010410(out32, 0x20, manager+0x3040, 0x40, -1)
    → 返回 32 字节 TJS octet
```

该返回 octet 当前由 `tools/FilterManagerDerive` 导出为 `hash_key`，用于调试启动链路。再次强调：本作 `pathHash/fileHash` 实际 key_len 为 0。

### 9.11 与标准算法差异对比

| 项目 | pathHash | fileHash |
| ---- | -------- | -------- |
| 标准算法 | SipHash-2-4 | BLAKE2s-256 |
| 有效 key | 16 字节全零 | 无 key |
| 主输入 | UTF-16LE pathname | UTF-16LE filename |
| 附加输入 | UTF-16LE mediaName | UTF-16LE mediaName |
| 输出 | 8 字节 | 32 字节 |
| Hxv4 字段 | `domain_hash` | `file_hash` |

### 9.12 相关文件

- `src/common/resource_hash.py`：Python 复现 `pathHash/fileHash`
- `src/static_extract/compute_resource_hash.py`：从 EXE 静态恢复 bootstrap 材料并计算可选 pathname/filename hash
- `tools/FilterManagerDerive/Program.cs`：离线加载 BOOTSTRAP DLL，导出 `hash_key` / Hxv4 key / nonce
- DLL `1ae7153ed25d.dll.i64`：本节分析的主文件
