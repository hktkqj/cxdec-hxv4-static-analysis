# 逆向分析文档 — Sanoba Witch XP3 资源保护体系

本文档提供对本游戏 XP3 资源保护体系的**完整逆向分析流程**概述，并以链接形式指向详细文档的对应章节。

---

## 一、总体架构

```plain
SabbatOfTheWitch.exe (TVP/Kirikiri 引擎)
  ├── .bind 段 → 运行时自解密脱壳 → OEP 0x639653
  ├── 主程序 TVP Storage 层 → XP3 Archive → Archive Stream
  ├── Plugin 系统 → 运行时加载随机 DLL（加密过滤层）
  └── 随机 DLL
       ├── FilterManager → 管理加密过滤器
       ├── Hxv4 映射表解密 → XChaCha20-Poly1305
       ├── DripValueImpl → 64-bit 密钥派生 VM
       └── FilterImpl → 四层 XOR Stream 变换
```

---

## 二、逆向分析全流程

### Step 1: 程序脱壳

游戏主程序 `SabbatOfTheWitch.exe` 使用 `.bind` 段自加密。入口点 `0x8E4310` 调用 `bind_unpack_loader (0x8E4390)` 解密/装载真实 PE，重建导入表后跳转到 OEP `0x639653`。

> **详细文档**：见 [XP3Extract.md](XP3Extract.md#附录-a—脱壳流程) 附录 A

关键步骤：

1. 使用 x32dbg 在 `0x8E433B` 设断点（EAX 包含计算后的 OEP）
2. 在 `0x8E4346` 处单步进入解包后的入口
3. 用 Scylla 重建 IAT，dump 修复后的 PE

辅助脚本：[src/minidump_process.py](src/minidump_process.py) — 全内存 minidump 创建工具

---

### Step 2: XP3 文件结构解析

游戏使用标准 XP3 容器，但 **index offset 字段被设为假值 `0x17`**，真正的 zlib index offset 存放在文件偏移 `0x20` 的 qword 中。

```plain
XP3 Header:
  +0x00  magic "XP3\r\n \n\x1a\x8bg\x01" (11 bytes)
  +0x0B  index_offset (qword, 假值 0x17)
  ...
  +0x20  真实 index_offset (qword)  ← 游戏自定义
```

> **详细文档**：[XP3Extract.md](XP3Extract.md) — XP3 容器格式完整解析

关键实现：`resolve_index_offset()` — [src/xp3_inspect.py:501](src/xp3_inspect.py#L501)

---

### Step 3: Index 解压与 Entry 解析

从真实 offset 读取 index 数据：

- `flag=0`：未压缩 index
- `flag=1`：**zlib 压缩** index → 解压得到标准 XP3 chunk 列表

Index 中包含标准 chunk：`File` / `info` / `segm` / `adlr`，以及游戏自定义 chunk `Hxv4`。

> **详细文档**：[XP3Extract.md](XP3Extract.md#32-index-解析)

关键实现：

- `load_index()` — [src/xp3_inspect.py:523](src/xp3_inspect.py#L523)
- `parse_entries()` — [src/xp3_inspect.py:732](src/xp3_inspect.py#L732)

---

### Step 4: 随机 DLL 加载机制

运行时从压缩 PE payload 中释放并加载随机文件名 DLL：

```text
Plugins.linkZ
  → 读取压缩 PE payload (zlib)
  → 写入 %TEMP%\krkr_<random>_<tick>_<pid>\<12 hex>.dll
  → LoadLibraryW
  → GetProcAddress("V2Link")
  → V2Link(TVPGetFunctionExporter())
```

随机 DLL 关键函数（RVA，image base `0x10000000`）：

| 函数 | RVA | 作用 |
| ------ | ----- | ------ |
| `CryptoFilterStream_Read_filter_after_read` | `0x10C80` | 过滤流读入口 |
| `FilterManager_OpenFilteredIStream` | `0x13CF0` | 打开过滤流 |
| `FilterManager_CreateFilterImpl` | `0x13C60` | 创建过滤器实例 |
| `BuildFilterStateFromUniqueKey` | `0x14790` | 从 key 构建 48-byte seed |
| `FilterImpl_InitState` | `0x0E240` | 初始化过滤状态 |
| `DripValueImpl_get64_from_u32` | `0x19070` | 64-bit 密钥派生 |
| `DripValueLane_eval` | `0x19300` | Lane 程序评估 |
| `g_FilterManager` | `0xAC9AC` | 全局 FilterManager 指针 |

---

### Step 5: Hxv4 映射表解密（XChaCha20-Poly1305）

每个 XP3 的 index 中包含 `Hxv4` 自定义顶层 chunk，其 payload 经加密：

```text
Hxv4 descriptor (14 bytes):
  +0x00  payload_offset (qword)
  +0x08  payload_size (uint32)
  +0x0C  flags (uint16, bit 0 = open_flag)

加密层:
  XChaCha20-Poly1305
    key = recovered manager block 0 (32 bytes)
    nonce = block 1 或 block 2 (24 bytes, 由 flags & 1 决定)
    tag = payload[0:16]
    ciphertext = payload[16:]

解密后:
  uint32 uncompressed_size
  zlib stream → big-endian TJS binary Variant
```

> **详细文档**：[Hxv4Ripped.md](Hxv4Ripped.md#一hxv4-映射表结构)

关键实现：

- `decrypt_hxv4_payload()` — [src/xp3_inspect.py:566](src/xp3_inspect.py#L566)
- `TJSBinaryReader` — [src/xp3_inspect.py:582](src/xp3_inspect.py#L582)
- `parse_hxv4_table()` — [src/xp3_inspect.py:645](src/xp3_inspect.py#L645)

---

### Step 6: DripValue 64-bit 密钥派生 VM

随机 DLL 中实现了一个小型 VM 用于密钥派生：

```text
DripValueImpl_get64_from_u32(value):
  lane = value & 0x7F
  seed = value >> 7
  lo = DripValueLane_eval(lane, seed)
  hi = DripValueLane_eval(lane, ~seed)
  return (hi << 32) | lo
```

每条 lane 是一段 record 程序 `[param, opcode_rva]`，支持 20 种操作码：

| Opcode | 操作 | RVA |
| -------- | ------ | ----- |
| ADD_IMM | `result += param` | 0x17C50 |
| RECURSE | 递归子程序 | 0x17C60 |
| ADD_SCRATCH | `result += scratch` | 0x17CB0 |
| MUL_SCRATCH | `result *= scratch` | 0x17CD0 |
| SCRATCH_MINUS_RESULT | `result = scratch - result` | 0x17CF0 |
| SHL_SCRATCH | `result <<= scratch & 0xf` | 0x17D10 |
| SHR_SCRATCH | `result >>= scratch & 0xf` | 0x17D30 |
| SUB_SCRATCH | `result -= scratch` | 0x17D50 |
| BIT_SHUFFLE | bit shuffle | 0x17D70 |
| SET_IMM | `result = param` | 0x17DA0 |
| SET_SEED | `result = seed` | 0x17DB0 |
| DEC | `--result` | 0x17DD0 |
| INC | `++result` | 0x17DE0 |
| NEG | `result = -result` | 0x17DF0 |
| NOT | `result = ~result` | 0x17E00 |
| TABLE_IMM | `result = context[param]` | 0x17E10 |
| TABLE_MASKED | `result = context[param & result]` | 0x17E30 |
| SUB_IMM | `result -= param` | 0x17E50 |
| STORE_SCRATCH | `scratch = result` | 0x17E60 |
| XOR_IMM | `result ^= param` | 0x17E80 |
| **STOP** | 停止 | 0x51D90 |

所有算术按 32-bit unsigned wrap，右移为逻辑右移。

> **详细文档**：[Hxv4Ripped.md](Hxv4Ripped.md#二dripvalue-vm-密钥派生)

关键实现：

- `DripProgram` 类 — [src/xp3_inspect.py:173](src/xp3_inspect.py#L173)
- `_eval_records()` — [src/xp3_inspect.py:221](src/xp3_inspect.py#L221)
- `get64_from_u32()` — [src/xp3_inspect.py:299](src/xp3_inspect.py#L299)

---

### Step 7: BuildFilterStateFromUniqueKey — 48-byte Filter Seed

`FilterManager_CreateFilterImpl` 为每条 Hxv4 record 的 64-bit key 生成 48 字节 filter seed state：

```text
BuildFilterStateFromUniqueKey(state48, key64, open_flag):
  if open_flag == 0:
    key_lo ^= holder_words[2]
    key_hi ^= holder_words[3]

  48-byte seed state:
    +0x00  boundary_seed_0 = drip_get64(key_lo)
    +0x08  boundary_seed_1 = drip_get64(key_hi)
    +0x10  split_offset = holder[5] + (holder[4] & (key64 >> 16))
    +0x14  reserved (zero)
    +0x18  bulk_key (16 bytes, via repeated drip_get64)
    +0x2C  has_drip = 1
    +0x2D  null_mode = 0
```

> **详细文档**：[Hxv4Ripped.md](Hxv4Ripped.md#三buildfilterstatefromuniquekey)

关键实现：

- `build_filter_state()` — [src/xp3_inspect.py:307](src/xp3_inspect.py#L307)
- `build_filter_state_map()` — [src/xp3_inspect.py:711](src/xp3_inspect.py#L711)

---

### Step 8: FilterImpl — 四层 Stream XOR Transform

`FilterRuntimeState.apply(data, offset)` 对每个 segment buffer 施加三部分 XOR：

#### 8a. Bulk XOR

范围：logical offset `[0, 16)`，逐字节异或 16 字节 `bulk_key`。

#### 8b. Split Boundary XOR

按 `split_offset` 将读取范围切为两段，左段用 boundary0，右段用 boundary1。

#### 8c. Rotated Dword Key XOR

对每个 boundary range，按 `(logical_offset & 3) * 8` 选择 dword key 的对应字节异或。

#### 8d. Boundary Byte XOR

若读取范围覆盖 `pos0` 或 `pos1` 位置，额外单字节异或 `byte0` / `byte1`。

> **详细文档**：[Hxv4Ripped.md](Hxv4Ripped.md#四filterimpl—stream-xor-transform)

关键实现：

- `FilterRuntimeState` 类 — [src/xp3_inspect.py:349](src/xp3_inspect.py#L349)
- `apply()` — [src/xp3_inspect.py:441](src/xp3_inspect.py#L441)

---

### Step 9: 运行时 Dump 捕获与 Drip Program 导出

从运行时 full-memory minidump 中导出 `DripValueImpl` 状态：

```text
dump 捕获:
  watch_random_plugin_dump.py
    → 轮询随机 DLL 加载
    → 检查 g_FilterManager 非空
    → MiniDumpWriteDump (full memory)

状态导出:
  inspect_manager_dump.py
    → 解析 minidump 流
    → 遍历 128 条 Drip lane
    → 导出 context u32 表 + holder_words
    → 生成 drip_program.json
```

> **详细文档**：[TryItOut.md](TryItOut.md#步骤-a从运行时-dump-导出-drip-program)

关键脚本：

- [src/watch_random_plugin_dump.py](src/watch_random_plugin_dump.py) — 运行时监控与 dump
- [src/inspect_manager_dump.py](src/inspect_manager_dump.py) — FilterManager 状态导出

---

### Step 10: 端到端离线提取

将上述所有步骤串联为完整的离线提取管道：

```text
XP3 文件 (raw bytes)
  ├─ resolve_index_offset()       → 真实 index offset
  ├─ load_index()                 → zlib 解压 index
  ├─ parse_entries()              → list[Entry]
  ├─ parse_hxv4_table()
  │    ├─ find_hxv4_descriptor()  → Hxv4 位置
  │    ├─ decrypt_hxv4_payload()  → XChaCha20-Poly1305
  │    ├─ zlib.decompress()       → TJS blob
  │    └─ TJSBinaryReader         → list[Hxv4Record]
  ├─ build_filter_state_map()
  │    └─ for each record:
  │         ├─ drip_program.build_filter_state(key, open_flag)
  │         │    ├─ get64_from_u32()  → 64-bit 派生值
  │         │    │    ├─ eval_lane()
  │         │    │    └─ _eval_records() → DripValue VM
  │         │    └─ 组装 48-byte seed state
  │         └─ FilterRuntimeState(seed_state)
  └─ extract_entry()
       ├─ iter_entry_chunks()     → yield logical_offset, raw_bytes
       ├─ FilterRuntimeState.apply(data, offset)
       │    ├─ Bulk XOR
       │    ├─ Split Boundary XOR
       │    ├─ Rotated Dword Key XOR
       │    └─ Boundary Byte XOR
       └─ calc_adler32(data)      → Adler32 校验
  → 原始明文资源 ✓
```

> **完整命令参考**：[TryItOut.md](TryItOut.md#步骤-c离线提取)

---

## 三、关键发现总结

1. **Index offset 欺骗**：标准 XP3 header 的 index_offset 字段被设为 `0x17`，真值在 `0x20`
2. **随机 DLL 架构**：真正的加密逻辑不在主程序中，而在运行时释放的随机文件名 DLL
3. **双层加密**：XChaCha20-Poly1305 保护映射表 + 四层 XOR 保护内容
4. **内嵌 VM**：DripValue 是一个完整的 128-lane 可编程 VM，用于密钥派生
5. **open_flag 的关键性**：错误使用 `record.filter_flag & 1` 而非 `Hxv4.descriptor.flags & 1` 会导致 Adler 校验失败
6. **startup.tjs 偏移规则**：有 `startup.tjs` 的包需要 `entry_base = 1`

---

## 四、常见陷阱

| 陷阱 | 正确做法 |
| ------ | ---------- |
| 把随机 DLL 文件名当稳定标识 | 按 RVA 和函数逻辑识别 |
| 用 `record.filter_flag & 1` 当 open flag | 使用 `Hxv4 descriptor flags & 1` |
| 所有包都用 `filter_flag + 1` 映射 entry | 有 `startup.tjs` 时才 `+1` |
| 对 raw Adler 已匹配的文件仍套 filter | 先检查 raw Adler，已匹配则跳过 |
| `0xC74B30` 是通用 XP3 filter | 它是高层文本处理，非通用解密步骤 |

---

## 五、后续方向

1. **文件类型识别**：对提取文件做 magic 扫描，自动识别 OGG/PNG/JPEG/TLG/TJS 格式
2. **真实资源名恢复**：追踪 TJS 运行时请求名与 Hxv4 hash 的映射关系
3. **TJS2 字节码解析**：扩展 [src/tjs2_inspect.py](src/tjs2_inspect.py) 以解析 object block 和 constant pool
4. **脚本逻辑反编译**：将 TJS bytecode 反编译为可读的 TJS 脚本

---

## 六、相关资源

- [Kirikiri/TVP 引擎文档](http://krkrz.github.io/)
- [XP3 格式规范 (krkrz)](https://github.com/krkrz/krkrz)
- [FreeMote Toolkit](https://github.com/UlyssesWu/FreeMote) — PSB/EMT 资源工具
- [PyCryptodome](https://www.pycryptodome.org/) — XChaCha20-Poly1305 实现
