# FilterImpl - Stream XOR Transform

[返回 Hxv4 加密体系总览](../Hxv4Ripped.md) | 上一篇：[BuildFilterStateFromUniqueKey](05-filter-state.md) | 下一篇：[FilterManager 运行时状态](07-filter-manager-runtime.md)


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

`FilterRuntimeState.apply(data, offset)` — [src/common/xp3_inspect.py:441](../../../src/common/xp3_inspect.py#L441)

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

