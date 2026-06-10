# BuildFilterStateFromUniqueKey

[返回 Hxv4 加密体系总览](../Hxv4Ripped.md) | 上一篇：[DripValue VM 密钥派生](04-dripvalue-vm.md) | 下一篇：[FilterImpl - Stream XOR Transform](06-stream-filter.md)


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

