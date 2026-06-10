# Hxv4 映射表结构

[返回 Hxv4 加密体系总览](../Hxv4Ripped.md) | 下一篇：[Bootstrap 初始化与密钥派生](02-bootstrap-kdf.md)


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

