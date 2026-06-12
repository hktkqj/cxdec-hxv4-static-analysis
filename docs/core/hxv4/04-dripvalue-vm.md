# DripValue VM 密钥派生

[返回 Hxv4 加密体系总览](../Hxv4Ripped.md) | 上一篇：[Resource Path Resolution and FileHash / PathHash](03-resource-hash.md) | 下一篇：[BuildFilterStateFromUniqueKey](05-filter-state.md)


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

核心类 — [src/common/xp3_inspect.py:173](../../../src/common/xp3_inspect.py#L173)：

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

