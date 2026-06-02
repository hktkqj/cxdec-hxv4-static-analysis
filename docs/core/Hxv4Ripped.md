# Hxv4 加密体系解析文档

本文档完整描述 `SabbatOfTheWitch` 的 Hxv4 加密资源保护体系。文档按 DLL 内部数据处理管线组织——从密钥初始化、映射表解密、资源定位、VM 派生、到流过滤——形成一条有向无环的分析链路。

---

## 一、Hxv4 映射表结构

Hxv4 是嵌入在每个 XP3 index 中的自定义顶层 chunk，其 payload 经过 XChaCha20-Poly1305 加密。解密后的内容是一个资源映射表，每条 record 将逻辑资源名（domain_hash + file_hash）绑定到一个 XP3 entry index 和一个 64-bit unique key。

### 1.1 Chunk 位置

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

`HXV4_KEY` 和 `HXV4_NONCES` 来自 FilterManager 初始化流程，其完整派生过程见[第二节](#二bootstrap-初始化与密钥派生)。

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

> 第一节描述了 Hxv4 映射表的结构和解密方式。解密所需的 `HXV4_KEY` 和 `HXV4_NONCES` 在游戏启动时由 `System.bootStrap()` 调用链生成。下一节将详细分析这个初始化过程。

## 二、Bootstrap 初始化与密钥派生

> 本节所有反编译输出来自 `mcp__ida-pro-mcp__decompile` 对 `1ae7153ed25d.dll.i64` 的实时 Hex-Rays 分析。

`sub_10015630` (RVA `0x15630`) 是 FilterManager 的核心初始化派生函数。它接收两个输入——`final_bootstrap`（UTF-16LE 编码的脚本前缀 + WARNING 字符串）和 `PARAMS`（22 字节结构化配置参数）——并在 FilterManager 内部状态块中生成所有后续解密所需的密钥材料。

### 2.1 入口与调用上下文

```plain
TJS 层调用:
  System.bootStrap(bootstrapPrefix, autoPathCallback)

DLL 内 System_bootStrap_callback (0x1000EEB0):
  final_bootstrap = bootstrapPrefix + WARNING
  PARAMS          = ConfigTable["PARAMS"]

  sub_10015630(manager + 8, final_bootstrap_utf16le, PARAMS)
    → 写入 hxv4_key、hxv4_nonce1、DripValueImpl VM 状态、holder_words、context_u32

  sub_100157D0(manager + 8, UNIQUE_utf16le, archive_seed)
    → 写入 hxv4_nonce0、更新 holder_words

  sub_100148B0(manager)
    → 返回 32 字节 TJS octet (hash_key)
```

### 2.2 FilterManager 内存布局

FilterManager 总大小为 `0x30B0` 字节。所有偏移量相对于 `manager+0x08`（FilterManagerCore 起始）：

```plain
manager+0x0000  wrapper[0]          uint32 — 非空时表示已初始化
manager+0x0004  wrapper[1]          uint32
manager+0x0008  — FilterManagerCore (this 指针) —
  +0x0000       drip_impl_ptr       uint32 — DripValueImpl* (独立分配，0x804 字节)
  +0x0004       holder_words[0]     uint32
  +0x0008       holder_words[1]     uint32
  +0x000C       holder_words[2]     uint32
  +0x0010       holder_words[3]     uint32
  +0x0014       holder_words[4]     uint32
  +0x0018       holder_words[5]     uint32
  +0x001C..     (scratch/padding)
  +0x0020       — Keccak 海绵状态 (0x2000 bytes, sub_10010550 管理) —
  +0x2020       — XOR 混合状态块 (0x1000 bytes, sub_1000F620 管理) —
  +0x3038       hxv4_key 区域 (32 bytes)  = context_u32[3078..3085]
  +0x3058       hxv4_nonce1 区域 (32 bytes) = context_u32[3086..3093]
  +0x3078       hxv4_nonce0 区域 (24 bytes) = context_u32[3094..3099]
  +0x3040       hash_key 中间状态 (0x40 bytes)
  +0x3098       派生标志 (uint32) — bit0=bootstrap完成, bit1=params完成, bit2=archive完成
  +0x30A0..0x30A4  hash_key 完成标志 (uint32×2)
manager+0x30B0  — 结束 —
```

### 2.3 sub_10015630 反编译

```c
char __fastcall sub_10015630(
    int a1,                    // this = FilterManagerCore* (manager+8)
    int a2,                    // (未使用)
    unsigned __int8 *a3,       // bootstrap UTF-16LE 字节
    size_t a4,                 // bootstrap 长度
    unsigned __int8 *a5,       // PARAMS 字节
    size_t a6)                 // PARAMS 长度
{
    int v15[8];                // 32-byte scratch 缓冲区
    __int64 v16;               // 8-byte hash_key 局部变量

    memset(v15, 0, sizeof(v15));  // 清零 scratch

    // [1] 联合密钥派生 + DripValue 初始化
    if (!sub_100141C0(v15, 0x20u, a3, a4, a5, a6))
        return 0;  // 失败

    // [2] seed=0: bootstrap → hxv4_key 组件 A
    sub_10010410((void *)(a1 + 12344), 0x20u, a3, a4, 0);
    *(a1 + 12440) |= 1u;  // bit0: bootstrap derivation done

    // [3] seed=1: params → hxv4_nonce1 组件 A
    sub_10010410((void *)(a1 + 12376), 0x20u, a5, a6, 1);
    *(a1 + 12440) |= 2u;  // bit1: params derivation done

    // [4] XOR scratch (2-of-2 秘密共享)
    //   hxv4_key 区域 (8 dwords @ a1+12344..a1+12372)
    *(a1 + 12344) ^= v15[0];   // +0x3038
    *(a1 + 12348) ^= v15[1];   // +0x303C
    *(a1 + 12352) ^= v15[2];   // +0x3040
    *(a1 + 12356) ^= v15[3];   // +0x3044 (QWORD covers v15[3..4])
    *(a1 + 12364) ^= v15[5];   // +0x304C
    *(a1 + 12368) ^= v15[6];   // +0x3050
    *(a1 + 12372) ^= v15[7];   // +0x3054
    //   context 尾部 (8 dwords @ context[3094..3101])
    v10[3094] ^= v15[0];
    v10[3095] ^= v15[1];
    v10[3096] ^= v15[2];
    v10[3097] ^= v15[3];
    v10[3098] ^= v15[4];
    v10[3099] ^= v15[5];
    v10[3100] ^= v15[6];
    v10[3101] ^= v15[7];

    // [5] hash_key 最终化
    v16 = 0;
    sub_10010410(&v16, 8u, (a1 + 12344), 0x40u, -1);
    *(a1 + 12448) ^= v16;         // +0x30A0
    *(a1 + 12452) ^= HIDWORD(v16); // +0x30A4
    return 1;
}
```

**关键观察**：
- **v15[8]** 是 sub_100141C0 输出的 32-byte scratch
- **a1+12344** = a1+0x3038（hxv4_key 区域），**a1+12376** = a1+0x3058（hxv4_nonce1 区域）
- XOR 作用域覆盖 hxv4_key 和 hxv4_nonce1 的全部 32 bytes，同时复制到 context_u32 尾部

### 2.4 调用链与密码原语

**sub_100141C0** — 联合密钥派生 + DripValue 初始化：

```c
char __thiscall sub_100141C0(_QWORD *this, int a2, size_t Size,
                              int a4, int a5, int a6, int a7)
{
    v8 = sub_100119D0(a6, a7);  // 验证 PARAMS (22 bytes)
    if (v8 >= 0 && sub_10010550(a2, Size, a4, a5, a6, a7)) {
        memmove_0(this + 1028, this + 4, 0x1000u);  // 状态块复制
        *((_DWORD *)this + 7) = 0;
        sub_1000F620(v8 + 1);                        // XOR 状态混洗
        if (*this)
            (***(void (__thiscall ****)(_DWORD, int))this)(*(_DWORD *)this, 1);
        *this = DripValueImpl_new_seeded(
            (int)(this + 4),                           // holder_words 区域
            (int)(this + 1540),                        // Keccak 状态块内部偏移
            *((_BYTE *)this + 24));                    // PARAMS[17] >> 7
        return 1;
    }
    DripHolder_reset(this);
    return 0;
}
```

**sub_100119D0** — PARAMS 22-byte 结构解析：

```plain
PARAMS[0:8]   → 置换表前 8 bytes  (例: 04 06 02 00 07 01 03 05)
PARAMS[8:16]  → 置换表后 8 bytes  (例: 03 00 05 04 02 01 01 02)
PARAMS[16]    → 附加参数 byte
PARAMS[17]    → bit0=子模式选择, bit7=flags 高位
PARAMS[18:20] → uint16 参数1
PARAMS[20:22] → uint16 参数2
```

**sub_10010550** — 核心 KDF：Keccak 海绵 + SHA3-512 派生：

```c
// 简化流程：
//   sub_1000D980: 分配 0x2000 byte Keccak 海绵状态
//   sub_10015AB0(params): 海绵吸收 PARAMS
//   sub_10013FC0(iv, 16): 海绵挤出 16B IV → 内部调用 Keccak-f[1600]
//   sub_1001E5E0 → sub_1001E610: SHA3-512 多流 KDF(bootstrap, IV)
//   sub_10015AB0(sha3_out, 64): 海绵吸收 SHA3 输出
//   sub_10013FC0(manager+0x20, 0x2000): 挤出完整海绵状态
```

**sub_10010410** — FNV-1a 混合 + BLAKE2s 哈希：

```c
int __cdecl sub_10010410(void *a1, size_t Size,
                          unsigned __int8 *a3, size_t a4, int a5)
{
    memset(a1, 0, Size);

    // 阶段 1: FNV-1a 键控混合
    v6 = 16777619 * (a5 ^ 0x811C9DC5);  // FNV_PRIME * (seed ^ FNV_OFFSET)
    for (v7 = 0; v7 < a4; ++v7) {
        // 3-常数 MurmurHash3-style 乘法混合
        v8 = 830770091 * ((-1404298415 * ((-312814405
             * (a3[v7] ^ v6 ^ ((a3[v7] ^ v6) >> 17)))
             ^ ([...] >> 11))) ^ ([...] >> 15));
        v6 = (v8 >> 14) ^ v8;
        *((_DWORD *)a1 + v7 % (Size >> 2)) ^= v6;
    }

    // 阶段 2-4: BLAKE2s 包装
    BLAKE2s_Init(digest_size=Size);
    BLAKE2s_Update(a3, a4);        // input_data
    BLAKE2s_Update(a1, Size);      // FNV_mixed_output
    return BLAKE2s_Final(a1, Size);
}
```

**seed 参数语义**：

| seed | FNV 初始状态 | 输出大小 | 用途 |
|------|-------------|----------|------|
| `0` | `0x01000193 * (0 ^ 0x811C9DC5)` = 0x4B9B54C1 | 32 bytes | hxv4_key 组件 A |
| `1` | `0x01000193 * (1 ^ 0x811C9DC5)` = 0x4B9B5554 | 32 bytes | hxv4_nonce1 组件 A |
| `-1` (=0xFFFFFFFF) | `0x01000193 * (0xFFFFFFFF ^ 0x811C9DC5)` = 0xD79B08DB | 8 bytes | hash_key 完成标志 |
| `2` | `0x01000193 * (2 ^ 0x811C9DC5)` = 0x4B9B56E7 | 32 bytes | sub_100157D0: UNIQUE 派生 |

### 2.5 sub_100157D0 — Archive Key Update

此函数在 `sub_10015630` 之后调用，生成 `hxv4_nonce0`：

```c
int __thiscall FilterManager_UpdateGlobalKeyFromArchiveName(
    _DWORD *this, int a2, size_t a3, int *a4)
{
    v9[0] = 749726414;   // 0x2CAFEACE (默认值，当 a4=NULL)
    v9[1] = -559038737;  // 0xDEADBEEF
    if (a4) v6 = a4;

    // [A] 从 UNIQUE + seed=2 派生 32 bytes
    sub_10010410(this + 3102, 0x20u, a2, a3, 2);
    this[3110] |= 4u;

    // [B] 从 archive seed 派生 32 bytes → XOR 到 nonce0
    sub_10010410(v10, 0x20u, v6, 8u, *v6);
    *(this + 3102) ^= v10[0];
    // ... (完整 XOR 覆盖 8 个 dword)

    // [C] 更新 holder_words[0..1]
    this[2] = *(this + 3102);
    this[3] = *(this + 3103);
}
```

实际运行时 archive seed 由 DLL 内嵌 8-byte 常量 @ RVA `0x81758` 提供（Sanoba: `A4 E0 8D 9B 7E 4B 96 DD`）。

### 2.6 sub_100148B0 — System.bootStrap 返回 Octet

```c
int __thiscall sub_100148B0(int this, int a2)
{
    if ((*(this + 12448) & 3) == 3)  // bootstrap + params 均完成
        sub_10010410(&v5, 0x20u, (this + 12352), 0x40u, -1);
    TVPCreateOctet(&v5, a2, 32);     // 创建 TJS Octet
    return a2;
}
```

### 2.7 2-of-2 秘密共享设计

最终的 `hxv4_key` 和 `hxv4_nonce1` 由两个独立分量 XOR 合成：

```plain
最终_hxv4_key    = sub_10010410(bootstrap, seed=0) ⊕ sub_100141C0_scratch
                   ├─ FNV-1a(0) → BLAKE2s(bootstrap ∥ fnv_mix)
                   └─ Keccak 海绵 + SHA3-512 KDF( bootstrap ∥ params )

最终_hxv4_nonce1 = sub_10010410(params, seed=1) ⊕ sub_100141C0_scratch
                   ├─ FNV-1a(1) → BLAKE2s(params ∥ fnv_mix)
                   └─ 同一个 32-byte scratch（同一份 Keccak 海绵输出）

最终_hxv4_nonce0 = sub_10010410(UNIQUE, seed=2) ⊕ sub_10010410(archive_seed)
```

两个分量使用**完全不同的密码原语**（Keccak/SHA3 vs BLAKE2s），防止代数攻击。

### 2.8 密码原语总览

| 算法 | 函数 | 角色 |
|------|------|------|
| **Keccak-f[1600]** (SHA-3 核心置换) | `sub_10011C10` | 海绵排列：Theta/Rho/Pi/Chi/Iota, 24轮 |
| **自定义 SHA3-512 多流 KDF** | `sub_1001E610` | 4 流吸收 → SHA3-512 → 1024B 展开 |
| **海绵 absorb** | `sub_10014950` | 8 字节 LE XOR 入 Keccak 状态 |
| **海绵 squeeze** | `sub_10013BC0` | 8 字节 LE 读 Keccak 状态 |
| **海绵管道** | `sub_10013FC0` | absorb→Keccak-f→squeeze 循环 |
| **BLAKE2s-256** | `sub_100159F0` / `sub_10012500` / `sub_10013DF0` | Update / Compress(G函数) / Final |
| **FNV-1a + MurmurHash3-style 混合** | `sub_10010410` 内联 | 键控种子扩张 + BLAKE2s 包装 |
| **64-bit xorshift PRNG** | `sub_100190B0` | 128 条 DripValue lane 初始化 |
| **XOR 状态混洗** | `sub_1000F620` | 两个 0x1000 块间的 XOR 交换 |

### 2.9 三阶段初始化状态机

```plain
阶段 0: ManagerCtor (sub_1000E2D0)
  → 分配 0x30B0 字节，零初始化
  → wrapper[0] = 0

阶段 1: BootstrapDerive (sub_10015630)
  → Keccak 海绵 + SHA3-512 KDF → scratch + 0x2000 状态块
  → xorshift PRNG → 128 lanes + 3106 context_u32
  → FNV+BLAKE2s(seed=0) → hxv4_key 组件 A
  → FNV+BLAKE2s(seed=1) → hxv4_nonce1 组件 A
  → XOR scratch → 最终 hxv4_key、hxv4_nonce1
  → wrapper[0] = 非零 (就绪)

阶段 2: ArchiveDerive (sub_100157D0)
  → FNV+BLAKE2s(seed=2, UNIQUE) → hxv4_nonce0 组件 A
  → FNV+BLAKE2s(seed, archive_seed) → XOR → 最终 hxv4_nonce0
  → holder_words[0..1] ← 从 hxv4_nonce0 复制
```

---

> 第二节生成了 `HXV4_KEY` 和 `HXV4_NONCES`，使第一节的 Hxv4 payload 得以解密，得到 record 表。下一步是通过逻辑资源名（domain/path + filename）在 record 表中定位具体条目。第三节分析这个哈希映射过程。

## 三、FileHash / PathHash 算法

### 3.1 分析目标

`CompoundStorageMedia` 如何把运行时逻辑资源名映射到 Hxv4 record：

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

### 3.2 startup.tjs 中的运行时对象关系

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

`System.bootStrap(...)` 返回的 32 字节 octet 仍然会传给 `CompoundStorageMedia`，但这不等价于后续 `pathHash/fileHash` 的有效 key。见 3.4。

### 3.3 pathHash / fileHash 调用链

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

字节流效果等价于 `UTF-16LE(input) || UTF-16LE("xp3hnp")`，中间没有分隔符，也没有额外长度字段。

### 3.4 hash_key 的真实作用：被复制，但 key_len 为 0

`System.bootStrap` 返回的 32 字节 `hash_key` 并没有作为有效 keyed hash key 使用。

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

它们确实复制了 octet 字节，但没有把 `this+8` 设置成有效长度。后续计算时 `key_len = this+8 = 0`。所以本作中实际 hasher 是：

```plain
pathHash = SipHash-2-4 with 16-byte zero key
fileHash = unkeyed BLAKE2s-256
```

`hash_key` 仍然是 `System.bootStrap` 返回值，可用于确认运行时初始化流程是否正确，但它不是本作 Hxv4 lookup hash 的有效 keyed hash key。

### 3.5 pathHash：domain_hash 的计算

路径 hash trait 位于 `sub_100169F0`。其特征：

- 初始化常数为 SipHash 标准 IV：`somepseudorandomlygeneratedbytes`
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

因此初始 domain/path 参数是空字符串。实测 `pathHash("", extra="xp3hnp") = 94d4a97c61498621`，正好命中 `bgm.xp3` Hxv4 表中所有 record 的 `domain_hash`。

### 3.6 fileHash：file_hash 的计算

压缩函数 `sub_10012500` 通过以下特征确认为标准 BLAKE2s-256：

- 初始化常数完全匹配 BLAKE2s IV（即 SHA-256 IV）：`6A09E667 BB67AE85 3C6EF372 A54FF53A …`
- 汇编中出现 `rol ebx, 10h`、`rol ebx, 0Ch`，与 BLAKE2s G 函数完全吻合
- 64 字节消息块，32 字节输出，有 counter 和 finalization flag 字段

但本作 `key_len == 0`，所以走的是 unkeyed BLAKE2s-256：

```python
file_hash = hashlib.blake2s(
    filename.encode("utf-16le") + "xp3hnp".encode("utf-16le"),
    digest_size=32,
).hexdigest()
```

注意 `filename` 必须是运行时传给 `CompoundStorageMedia.fileHash()` 的规范化逻辑文件名（含扩展名），裸字符串不可直接使用。

### 3.7 Hxv4 record 定位流程

离线定位一个逻辑资源名时，按以下顺序处理：

```plain
1. 解析 XP3 index，解密并解压 Hxv4 table。
2. 从 startup.tjs 确认 CompoundStorageMedia mediaName，本作为 "xp3hnp"。
3. 确认运行时 domain/path（初始 archive domain 通常是 ""）。
4. domain_hash = pathHash(domain_path, extra=mediaName)。
5. 确认运行时规范化 filename（含扩展名）。
6. file_hash = fileHash(filename, extra=mediaName)。
7. 在 Hxv4 records 中查找同时满足 domain_hash 和 file_hash 的 record。
8. 命中后：packed 低 16 位 → XP3 entry index；record.key → stream filter 派生。
```

重要区分：

| 名称 | 用途 |
| ---- | ---- |
| `hxv4_key` / `hxv4_nonce*` | 解密 Hxv4 payload |
| `System.bootStrap` 返回 octet / `hash_key` | 传给 `CompoundStorageMedia`，本作中 key_len=0 |
| `domain_hash` / `file_hash` | Hxv4 table lookup key |
| `record.key` | 命中 record 后用于内容 stream filter 派生 |

### 3.8 不同资源类型的 filename 补全规则

主程序侧 storage 打开链路：

```plain
TJS / KAG / 资源管理器请求
  -> TVPCreateBinaryStreamForStorageName
  -> CompoundStorageMediaFS_Open
  -> CompoundStorageMediaFS_MapNameToFileKey
  -> pathHash / fileHash + Hxv4 lookup
```

Hxv4 中参与 `fileHash()` 的 `filename` 是**脚本层或资源管理器完成类型补全之后，传入 storage 层的相对逻辑文件名**。

| 资源类型 | 裸逻辑名示例 | 参与 `fileHash()` 的 filename | 证据 |
| -------- | ------------ | ----------------------------- | ---- |
| BGM 音频 | `bgm01` | `bgm01.opus` | 命中 `bgm.xp3` record 1 |
| BGM loop sidecar | `bgm01` | `bgm01.opus.sli` | 命中 `bgm.xp3` record 2 |
| 背景图 | `学院_廊下モブa` | `学院_廊下モブa.png` | 命中 `bgimage.xp3` record 77 |
| 启动脚本 | `startup` | `startup.tjs` | `Scripts.execStorage` |
| 数据文件 | 显式 storage | 例如 `cglist.csv` | 显式扩展名参与 hash |

### 3.9 DLL 内嵌常量表（起始地址 0x10080e38）

`sub_10010380` 实现了一个线性扫描的 key-value 表，包含以下四项：

| 键 | 长度 | 内容 |
| ---- | ------ | ------ |
| `PARAMS` | 22 字节 | 结构化配置参数：`04 06 02 00 07 01 03 05 03 00 05 04 02 01 01 02 00 80 26 02 C8 01` |
| `UNIQUE` | 60 字节 | UTF-16LE 宽字符串：`{NENeMEGURuTSUMUGiTOUKoWAKANa}` |
| `PUBKEY` | 248 字节 | PEM 格式 RSA-1024 公钥 |
| `WARNING` | 67 字节 | ASCII 警告文本 |

### 3.10 与标准算法差异对比

| 项目 | pathHash | fileHash |
| ---- | -------- | -------- |
| 标准算法 | SipHash-2-4 | BLAKE2s-256 |
| 有效 key | 16 字节全零 | 无 key |
| 主输入 | UTF-16LE pathname | UTF-16LE filename |
| 附加输入 | UTF-16LE mediaName | UTF-16LE mediaName |
| 输出 | 8 字节 | 32 字节 |
| Hxv4 字段 | `domain_hash` | `file_hash` |

### 3.11 相关文件

- `src/common/resource_hash.py`：Python 复现 `pathHash/fileHash`
- `src/static_extract/compute_resource_hash.py`：从 EXE 静态恢复 bootstrap 材料并计算可选 pathname/filename hash
- `tools/FilterManagerDerive/Program.cs`：离线加载 BOOTSTRAP DLL，导出 `hash_key` / Hxv4 key / nonce

---

> 第三节完成了从逻辑资源名到 Hxv4 record 的定位。每条 record 包含一个 64-bit unique key，这个 key 需要经过 DripValue VM 派生为 filter 种子。下一节分析这个 VM 的架构和运行时语义。

## 四、DripValue VM 密钥派生

DripValue VM 是内嵌在 DLL 中的自定义 32-bit 字节码解释器，用于从 64-bit 资源密钥派生流过滤器的种子参数。类名 "DripValueImpl" 来自 DLL 的 RTTI 虚表符号。

### 4.1 入口函数

```plain
DripValueImpl_get64_from_u32 (RVA 0x19070):
  lane = value & 0x7F
  seed = value >> 7
  lo = DripValueLane_eval(lane, seed)
  hi = DripValueLane_eval(lane, ~seed)
  return (hi << 32) | lo
```

### 4.2 VM 架构

- **128 条 lane**，每条 lane 包含一段 record 程序
- 每条 record 格式：`[param (uint32), opcode_rva (uint32)]`
- 支持嵌套递归调用（`DRIP_OP_RECURSE`）
- 全局 context u32 数组（3106 个 dword）

解释器 `DripValueLane_eval` (RVA `0x19300`) 的核心循环：

```c
while (pc != lane->end) {
    record = *(pc);              // param (u32)
    opcode = *(pc + 4);          // 回调函数指针
    if (!opcode(&result, &state, record))
        break;                   // DRIP_OP_STOP 返回 false
    pc += 8;                     // 下一条 record
}
return result;
```

### 4.3 操作码全集（20 种）

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

### 4.4 DripProgram 实现

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

### 4.5 Lane 初始化 — sub_100190B0 (64-bit xorshift PRNG)

128 条 lane 的 record 序列在 FilterManager 初始化时由 `sub_100190B0` 构造（调用链：`sub_10017BB0` → `sub_100190B0` → `sub_10017E90`）。

```c
// sub_100190B0 反编译（来自 IDA Hex-Rays）
int __thiscall sub_100190B0(char *this, int a2, int a3, char a4)
{
    for (v4 = 0; v4 < 128; ++v4) {
        // 64-bit xorshift PRNG 生成每条 lane 的两个随机种子
        v6 = v4 + 2135587861;  // 0x7F4A7C55
        HIDWORD(v6) = ~v4 - 1640531527 + CF;  // 0x9E3779B9 (golden ratio φ)

        // 第一轮 xorshift
        t = 0xBF58476D1CE4E5B9 * (v6 ^ (v6 >> 30));
        v13 = (0x94D049BB133111EB * (t ^ (t >> 27))) ^ ([...] >> 31);

        // 第二轮 xorshift (用不同的初始值)
        t2 = 0xBF58476D1CE4E5B9 * ((v6 - 0x61C8864680B583EB) ^ ([...] >> 30));
        v14 = (0x94D049BB133111EB * (t2 ^ (t2 >> 27))) ^ ([...] >> 31);

        // 初始化 lane v4 的状态
        lane[v4].current = lane[v4].begin;   // 重置 PC
        lane[v4].context_ptr = a2;           // 全局 context 指针

        // 调用 sub_10017E90 为该 lane 生成 record 序列
        if (!sub_10017E90(&lane_init_params))
            return -1;
    }
    return 0;
}
```

`sub_10017E90` 内部写入的是硬编码字节序列（`"WVSRQ"`、`"ZY[^_]"`、`0x8B7C2418`），lane 的 opcode 序列不随 bootstrap/PARAMS 变化而改变。

**64-bit xorshift 常数**：

| 常数 | 值 | 作用 |
|------|-----|------|
| `0x7F4A7C55` | 2135587861 | 初始加数（lane 索引偏移） |
| `0x9E3779B9` | 黄金比例 φ | 高位字加数 |
| `0xBF58476D1CE4E5B9` | — | xorshift 乘数 M1 |
| `0x94D049BB133111EB` | — | xorshift 乘数 M2 |
| `0x61C8864680B583EB` | — | 第二轮减数 (轮换常数) |

---

> 第四节描述了 DripValue VM 的运行时执行模型和 lane 初始化过程。这个 VM 的主要调用者是下一节的 `BuildFilterStateFromUniqueKey`——它将 64-bit record key 转化为 48-byte filter seed state。

## 五、BuildFilterStateFromUniqueKey

从 Hxv4 record 的 64-bit key 生成 48 字节 filter seed state。

### 5.1 算法流程

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

### 5.2 48-byte Seed State 布局

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

> 第五节将 record.key 转化为了 48-byte seed state。这个 seed state 随后被 FilterImpl 消费，初始化为两个 FilterBoundary 并驱动实际的流解密。下一节展开四层 XOR 变换的完整细节。

## 六、FilterImpl — Stream XOR Transform

### 6.1 FilterBoundary 初始化

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

### 6.2 四层 XOR 变换

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

### 6.3 完整 apply() 流程

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
        self._apply_boundary(data, self.boundary1, ...)
    elif split < end:
        self._apply_boundary(data, self.boundary0, ..., first_size)
        self._apply_boundary(data, self.boundary1, ..., end - split)
    else:
        self._apply_boundary(data, self.boundary0, ...)

    return True
```

---

> 第六节覆盖了单个文件的流解密逻辑。所有这些组件——初始化、映射表、VM、filter——被下一节的 FilterManager 统一管理和编排。

## 七、FilterManager 运行时状态

### 7.1 结构

```plain
FilterManager (总大小 0x30B0):
  +0x00  manager[0] wrapper  → 非空时表示就绪
  +0x04  manager[1]
  +0x08  FilterManagerCore 起始
          +0x00  DripValueImpl*       → DripValue VM 实例指针 (独立分配 0x804 bytes)
          +0x04  holder_words[0]
          +0x08  holder_words[1]
          +0x0C  holder_words[2]
          +0x10  holder_words[3]
          +0x14  holder_words[4]
          +0x18  holder_words[5]
          +0x20  Keccak 海绵状态 (0x2000 bytes)
          +0x2020 XOR 混合状态块 (0x1000 bytes)
          +0x3038 hxv4_key (32 bytes)
          +0x3058 hxv4_nonce1 (24 bytes)
          +0x3078 hxv4_nonce0 (24 bytes)
          +0x3098 派生完成标志位

完整内存布局与初始化流程见第二节。
```

### 7.2 DripValueImpl

```plain
DripValueImpl:
  +0x00  vtable
  +0x04  lanes[128]           → 每条 lane 0x10 bytes:
           +0x00  begin (record 起始 VA)
           +0x04  end (record 结束 VA)
           +0x08  current
           +0x0C  context 指针 (所有 lane 共享)
```

### 7.3 状态导出

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

### 7.4 离线解密时的使用方式

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

- Hxv4 payload 解密：`decrypt_hxv4_payload()` 使用 JSON 中的 `hxv4_key` / `hxv4_nonce*`（[src/common/xp3_inspect.py:577](../../src/common/xp3_inspect.py#L577)）。
- Hxv4 table 解析：`parse_hxv4_table()` 解密 payload、zlib 解压并解析 record（[src/common/xp3_inspect.py:658](../../src/common/xp3_inspect.py#L658)）。
- entry → filter state 映射：`build_filter_state_map()` 对每条 Hxv4 record 调用 `build_filter_state(record.key, open_flag)`（[src/common/xp3_inspect.py:729](../../src/common/xp3_inspect.py#L729)）。
- 条目内容还原：`extract_entry()` 先按 XP3 segment 读取并 zlib 解压，再对每个 chunk 调用 recovered filter，最后以 adler32 判断是否还原成功（[src/common/xp3_inspect.py:883](../../src/common/xp3_inspect.py#L883)）。

`drip_program.json` 保存了两层材料：第一层用于打开 Hxv4 映射表，第二层用于复现运行时 DripValue VM，并按每个 Hxv4 record 的 resource key 动态派生实际的 stream filter state。

---

> 第七节给出了 FilterManager 的完整布局与离线导出流程。下一节展示运行时 DLL 内部的 stream read 调用链，以验证过滤逻辑的实际挂载点。

## 八、Stream Filter 运行时读路径

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

> 第八节确认了过滤逻辑在运行时的挂载点。下一节给出 Sanoba 样本中实际提取的密钥常量值。

## 九、关键常量

```python
# XChaCha20-Poly1305 密钥 (从 FilterManager block 0 恢复)
HXV4_KEY = bytes.fromhex(
    "e4dc1d99d9d9fb1ae5f7529ee70f841b"
    "fadb13d12f4d22b99170d6cc6a62bc54"
)

# XChaCha20-Poly1305 Nonces (从 FilterManager block 1/2 恢复)
HXV4_NONCES = {
    0: bytes.fromhex("d99230e02623f4a0c4f2857682b4de6d"
                     "fefe820b57060e50b7cc2580db04d993")[:24],
    1: bytes.fromhex("b96f89630850dd23a13810c7718ad003"
                     "936d1d4a3ae008909be93eee7ac8fc3e")[:24],
}
```

---

> 第九节给出了具体的 hex 常量。下一节的验证结果证明以上全链路分析与运行时行为完全一致。

## 十、验证结果

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
