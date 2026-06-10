# Bootstrap 初始化与密钥派生

[返回 Hxv4 加密体系总览](../Hxv4Ripped.md) | 上一篇：[Hxv4 映射表结构](01-hxv4-table.md) | 下一篇：[FileHash / PathHash 算法](03-resource-hash.md)


> 本节所有反编译输出来自 `mcp__ida-pro-mcp__decompile` 对 `1ae7153ed25d.dll.i64` 的实时 Hex-Rays 分析。

`sub_10015630` (RVA `0x15630`) 是 FilterManager 的核心初始化派生函数。它接收两个输入——`final_bootstrap`（UTF-16LE 编码的脚本前缀 + WARNING 字符串）和 `PARAMS`（22 字节结构化配置参数）——并在 FilterManager 内部状态块中生成所有后续解密所需的密钥材料。

### 2.1 入口与调用上下文

```plain
TJS 层调用:
  System.bootStrap(bootstrapPrefix, autoPathCallback)

DLL 内 System_bootStrap_callback (0x1000EEB0):
  final_bootstrap = bootstrapPrefix + WARNING
  PARAMS          = ConfigTable["PARAMS"]
  optional_seed   = 第 4 个参数为长度 >= 8 的 octet 时，经 SetArchiveSeedOctet 登记

  sub_10015630(manager + 8, final_bootstrap_utf16le, PARAMS)
    → 写入 hxv4_key、hxv4_nonce1、DripValueImpl VM 状态、holder_words、context_u32

  sub_100157D0(manager + 8, UNIQUE_utf16le, archive_seed_ptr_or_NULL)
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
/**
 * ============================================================================
 * sub_10010550 — 核心 KDF：Keccak 海绵 + SHA3-512 多流密钥派生
 *
 * RVA:  0x10010550
 * Size: 0x205 bytes (141 instructions)
 *
 * 这是 Hxv4 加密体系中最核心的密码学引擎。它完成两阶段操作：
 *   阶段 1: 海绵吸收 PARAMS → 挤出 IV → SHA3-512(bootstrap, IV) → 输出到调用者缓冲
 *   阶段 2: 海绵再吸收 SHA3 输出 → 挤出完整 0x2000 字节海绵状态
 *
 * 调用约定: __thiscall (this 指针通过 ecx 传入)
 * ============================================================================
 */

char __thiscall sub_10010550(
    char   *this,    // [ebp-0x1FC] ecx传入 → Keccak 海绵上下文指针
                     //   阶段 2 中 this+0x20 作为 0x2000 字节挤出的目标地址
    void   *a2,      // [ebp-0x204] arg_0 → 输出缓冲区（接收 SHA3-512 结果）
    size_t  Size,    // [ebp+0x22C] arg_4 → 输出长度，必须 ≤ 64 字节
                     //   调用者 sub_100141C0 传入 0x20（32 字节）
    int     a4,      // [ebp-0x200] arg_8 → 输入数据指针 #1（bootstrap UTF-16LE 字节）
    int     a5,      // [ebp+0x234] arg_C → 输入数据长度 #1（bootstrap 字节数）
    int     a6,      // [ebp-0x214] arg_10 → 输入数据指针 #2（PARAMS 22 字节配置参数）
    int     a7       // [ebp+0x23C] arg_14 → 输入数据长度 #2（PARAMS = 22）
)
{
    // ========================================================================
    // 栈变量布局
    // ========================================================================
    void    *Block[3];  // [ebp-0x210] 3 个指针（实际只用 Block[0]）
                        //   Block[0] = sub_1000D980 分配的 0x2000 字节海绵状态
    void    *v9;        // [ebp-0x204] ← a2 的副本（输出缓冲区）
    int      v10;       // [ebp-0x200] ← a4 的副本（bootstrap 指针）
    char    *v11;       // [ebp-0x1FC] ← this 的副本（Keccak 上下文指针）
    int      v12;       // [ebp-0x1F8] 海绵 rate 参数（每轮吸收/挤出前的字节数）
    int      v13;       // [ebp-0x1F4] 循环计数器（两次调用均置 0）
    _QWORD   v14[49];   // [ebp-0x1F0] 0xC0=192 字节工作区，两阶段均清零
    char     v15;       // [ebp-0x61]  海绵定界符字节（padding delimiter）
                        //   0x06 = SHA-3 函数族
                        //   0x1F = SHAKE 可扩展输出函数族
    _BYTE    Src[64];   // [ebp-0x60]  64 字节中间缓冲区
                        //   阶段 1: SHA3-512 输出写入此处，再 memmove 到 v9
                        //   阶段 2: 内容被 memset 清零
    __int128 v17;       // [ebp-0x20]  16 字节 IV 暂存区（__int128 = 16 bytes）
                        //   阶段 1: sub_10013FC0 挤出 16B IV 写入此处
                        //   阶段 2: 被 xorps 清零
    int      v18;       // [ebp-0x4]   异常处理 guard 变量

    // ========================================================================
    // 序言：保存参数、初始化
    // ========================================================================
    v11 = this;                              // 保存 Keccak 上下文指针
    v9  = a2;                                // 保存输出缓冲区指针
    v10 = a4;                                // 保存 bootstrap 数据指针
    memset(Src, 0, sizeof(Src));             // 清零 64 字节中间缓冲
    v17 = 0;                                 // 清零 16 字节 IV（xorps xmm0 + movq/mov）

    // 安全检查：输出不能超过 64 字节
    // 调用者 sub_100141C0 传入 Size=0x20 (32)，满足此约束
    if ( Size > 0x40 )
        return 0;

    // ========================================================================
    // 阶段 1: PARAMS 吸收 → IV 挤出 → SHA3-512 派生 → 结果输出
    // ========================================================================

    // --- 1a. 分配 0x2000 字节 Keccak 海绵状态块 ---
    memset(Block, 0, sizeof(Block));         // 清零 12 字节 Block[3]
    sub_1000D980((int *)Block, 0x2000u);    // 分配 0x2000 字节，Block[0] 指向该内存
    // 海绵状态的内部结构（200 bytes × 内部并行度）：
    //   Keccak-f[1600] 状态 = 1600 bits = 200 bytes = 25 lanes × 64 bits

    // --- 1b. 初始化海绵参数：SHA-3 模式 ---
    v12   = 144;                            // rate = 144 bytes = 1152 bits
                                            //   这是 cSHAKE 的安全速率参数
                                            //   容量 = 1600 - 1152 = 448 bits
    v15   = 6;                              // delimiter = 0x06
                                            //   在 SHA-3 标准中，0x06 表示 SHA3 哈希函数
    v14[0] = 0;
    qmemcpy(&v14[1], v14, 0xC0u);          // 将 v14[1..48] 全部清零（0xC0=192 字节）
    v18   = 0;                              // SEH guard 置零
    v13   = 0;                              // 循环计数器归零

    // --- 1c. 海绵吸收 PARAMS（22 字节） ---
    // sub_10015AB0 将数据按 8 字节 LE 块 XOR 入 Keccak 状态，满 rate 时触发
    // Keccak-f[1600] 排列（24 轮 Theta/Rho/Pi/Chi/Iota）
    sub_10015AB0(a6, a7);
    //   参数: a6 = PARAMS 指针, a7 = 22（PARAMS 长度）
    //   PARAMS 内容 (Sanoba):
    //     04 06 02 00 07 01 03 05  03 00 05 04 02 01 01 02  00 80 26 02 C8 01
    //     └─── 置换表前 8B ────┘  └─── 置换表后 8B ────┘  └附加┘└─u16─┘└─u16─┘

    // --- 1d. 海绵挤出 16 字节 IV ---
    // sub_10013FC0 从海绵中挤出指定字节数（读 8 字节 LE 块，必要时触发 Keccak-f）
    sub_10013FC0(&v17, 16);
    //   挤出 16 字节 → v17（__int128 在栈上 [ebp-0x20]）
    //   此 IV 将作为 SHA3-512 多流 KDF 的种子输入

    // --- 1e. SHA3-512 多流 KDF 核心变换 ---
    // sub_1001E5E0 → sub_1001E610 执行真正的 SHA3-512 哈希
    // 输入: bootstrap 数据 + 16 字节 IV
    // 输出: 64 字节 SHA3-512 摘要 → Src[64]
    sub_1001E5E0(
        (int)Src,       // 输出缓冲区（64 字节）
        64,             // 输出长度 = SHA3-512 digest size
        (int)Block[0],  // 海绵状态块（内部使用）
        8,              // (参数，含义见下文)
        3,              // 流数量 - 1 = 3 → 实际 4 条并行流
        v10,            // a4 = bootstrap 指针（UTF-16LE 字节）
        a5,             // bootstrap 数据长度
        (int)&v17,      // IV 指针（16 字节）
        16              // IV 长度
    );
    // sub_1001E5E0 内部流程:
    //   1. 将 bootstrap 数据分割为 4 条流（每条吸收不同前缀）
    //   2. 每条流独立执行 SHA3-512(prefix || bootstrap_chunk || IV)
    //   3. 合并 4 条流的输出 → 64 字节 Src
    //   这种多流设计防止长度扩展攻击，并增加密钥材料熵

    v17 = 0;                                 // 清除 IV（xorps 归零，防止栈残留）

    // --- 1f. 输出结果：复制到调用者缓冲区 ---
    memmove_0(v9, Src, Size);
    //   v9 = a2 = 调用者 sub_100141C0 传入的输出指针（即 v15[8] 栈缓冲）
    //   Size = 0x20 (32 字节)
    //   将 SHA3-512 前 32 字节复制给调用者
    //   这 32 字节后续在 sub_10015630 中用作 XOR scratch（2-of-2 秘密共享）

    // ========================================================================
    // 阶段 2: 吸收 SHA3 输出 → 挤出完整海绵状态 → 清理
    // ========================================================================

    // --- 2a. 切换海绵参数：SHAKE 模式（可扩展输出） ---
    v12   = 136;                            // rate = 136 bytes = 1088 bits
                                            //   这是 SHAKE256 的速率参数
                                            //   容量 = 1600 - 1088 = 512 bits
    v15   = 31;                             // delimiter = 0x1F
                                            //   在 SHA-3 标准中，0x1F 表示 SHAKE 可扩展输出
    v14[0] = 0;
    qmemcpy(&v14[1], v14, 0xC0u);          // 再次清零 v14[1..48]
    v13   = 0;                              // 循环计数器归零

    // --- 2b. 海绵再吸收：将 SHA3-512 输出回注海绵 ---
    sub_10015AB0(Src, 64);
    //   吸收 Src[0..63] = SHA3-512 的完整 64 字节输出
    //   目的：将 SHA3-512 的熵扩散到 Keccak-f[1600] 全状态中
    //   这样后续挤出的 0x2000 字节每个 bit 都依赖于完整的 SHA3 输出

    // --- 2c. 海绵挤出完整 0x2000 字节状态 ---
    sub_10013FC0(v11 + 32, 0x2000);
    //   v11 = this (ecx 传入的 Keccak 上下文指针)
    //   v11 + 32 = this + 0x20 = FilterManagerCore+0x20（Keccak 海绵状态存储区）
    //   挤出 0x2000 = 8192 字节到 FilterManagerCore+0x20..+0x201F
    //   这些字节后续被 sub_100141C0 传入 DripValueImpl_new_seeded 作为
    //   DripValue VM 的初始化种子和全局 context 表

    // --- 2d. 清理：清除敏感中间数据 ---
    memset(Src, 0, sizeof(Src));             // 擦除 64 字节中间缓冲
    if ( Block[0] )
        j__free_0(Block[0]);                 // 释放 0x2000 字节海绵状态块
    return 1;                                // 成功返回
}

/**
 * ============================================================================
 * 调用上下文（来自 sub_100141C0）:
 *
 *   sub_10010550(
 *       this = a2,        // Keccak 上下文（从 sub_100141C0 的 a2 参数传入）
 *       a2   = v15,       // 输出到调用者栈上的 32 字节 scratch
 *       Size = 0x20,      // 输出 32 字节
 *       a4   = bootstrap, // UTF-16LE 编码的版权字符串
 *       a5   = bootstrap_len,
 *       a6   = PARAMS,    // 22 字节配置参数
 *       a7   = 22
 *   );
 *
 * ============================================================================
 * 密码学原语映射:
 *
 *   函数            | 角色
 *   ----------------|---------------------------------------------------------
 *   sub_1000D980    | 分配 0x2000 字节 Keccak 海绵状态内存
 *   sub_10015AB0    | 海绵吸收: 8 字节 LE XOR 入状态，满 rate 时触发 Keccak-f
 *   sub_10013FC0    | 海绵挤出: 8 字节 LE 从状态读取，满 rate 时触发 Keccak-f
 *   sub_1001E5E0    | 外层包装: 调用 sub_1001E610 的 SHA3-512 多流 KDF
 *   sub_1001E610    | 内核: 4 条并行流的 SHA3-512 哈希
 *   sub_10011C10    | 底层: Keccak-f[1600] 24 轮排列 (Theta/Rho/Pi/Chi/Iota)
 *
 * ============================================================================
 * 两阶段海绵模式差异:
 *
 *   参数     | 阶段 1 (SHA-3)     | 阶段 2 (SHAKE)
 *   ---------|--------------------|--------------------
 *   rate     | 144 bytes (0x90)   | 136 bytes (0x88)
 *   capacity | 56 bytes (448 bit) | 64 bytes (512 bit)
 *   delimiter| 0x06               | 0x1F
 *   用途     | 定长哈希输出       | 可扩展输出 (XOF)
 *   吸收数据 | PARAMS (22B)       | SHA3-512 输出 (64B)
 *   挤出数据 | IV (16B)           | 完整状态 (0x2000B)
 *
 *   两阶段设计的意义:
 *   - 阶段 1: 用 SHA-3 模式从 PARAMS 派生 IV，保证 IV 是 PARAMS 的密码学承诺
 *   - 阶段 2: 用 SHAKE 可扩展输出将 SHA3-512(bootstrap, IV) 的熵扩散到
 *     0x2000 字节，为 DripValue VM 提供丰富的初始化材料
 *
 * ============================================================================
 */

```

**sub_10010410** — FNV-1a 混合 + BLAKE2s 哈希：

```c
int __cdecl sub_10010410(
    void *a1,              // 参数1: 输出缓冲区
    size_t Size,           // 参数2: 输出长度（同时也是 BLAKE2s digest_size）
    unsigned __int8 *a3,   // 参数3: 输入数据指针
    size_t a4,             // 参数4: 输入数据长度
    int a5                 // 参数5: FNV-1a 种子
)
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

`archive_seed` 的选择点不在 `sub_10010410`，而在传给 `sub_100157D0` 的第 4 个参数：

- 参数非空时，函数使用调用方提供的 8 字节 seed。`System_bootStrap_callback` 只在第 4 个 TJS 参数是长度至少 8 的 octet 时调用 `SetArchiveSeedOctet(seed)` 登记该指针。
- 参数为空时，函数使用局部默认 seed。默认 seed 的两个 dword 是 `0x2CAFEACE` 和 `0xDEADBEEF`，按小端字节序为 `ce ea af 2c ef be ad de`。
- 当前静态工具不模拟完整 TJS runtime callback，而是直接调用底层 DLL 函数；因此 `FilterManagerDerive` 的自动策略是：`--archive-seed-hex` 显式值优先；否则读取 DLL RVA `0x81758` 的 8 字节静态 seed；如果该位置全 0，则扫描 `sub_100157D0` 函数体恢复上述默认 seed 常量。

已验证样本中，Limelight 使用非零静态 seed `bf22368a48210206`；`枯れない世界と終わる花` 的 RVA `0x81758` 为全 0，因此应走默认 seed `ceeaaf2cefbeadde`。这也是 `nonce0` 是否能正确解密主包的关键差异。

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

最终_hxv4_nonce0 = sub_10010410(UNIQUE, seed=2)
                   ⊕ sub_10010410(resolved_archive_seed,
                                    seed=LE32(resolved_archive_seed[0:4]))
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
  → 选择 archive seed pointer；空指针时使用默认 ceeaaf2cefbeadde
  → FNV+BLAKE2s(seed=LE32(archive_seed[0:4]), archive_seed[0:8]) → XOR → 最终 hxv4_nonce0
  → holder_words[0..1] ← 从 hxv4_nonce0 复制
```

---

> 第二节生成了 `HXV4_KEY` 和 `HXV4_NONCES`，使第一节的 Hxv4 payload 得以解密，得到 record 表。下一步是通过逻辑资源名（domain/path + filename）在 record 表中定位具体条目。第三节分析这个哈希映射过程。

