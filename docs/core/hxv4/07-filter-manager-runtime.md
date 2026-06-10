# FilterManager 运行时状态

[返回 Hxv4 加密体系总览](../Hxv4Ripped.md) | 上一篇：[FilterImpl - Stream XOR Transform](06-stream-filter.md) | 下一篇：[Stream Filter 运行时读路径](08-runtime-read-path.md)


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

通过 `inspect_manager_dump.py` 从运行时 full-memory minidump 导出（[src/dynamic_capture/inspect_manager_dump.py](../../../src/dynamic_capture/inspect_manager_dump.py)）：

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

`xp3_inspect.py --filter recovered --drip-program drip_program.json` 会把 `drip_program.json` 还原为 `DripProgram` 对象（[src/common/xp3_inspect.py:196](../../../src/common/xp3_inspect.py#L196)）。其中：

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

- Hxv4 payload 解密：`decrypt_hxv4_payload()` 使用 JSON 中的 `hxv4_key` / `hxv4_nonce*`（[src/common/xp3_inspect.py:577](../../../src/common/xp3_inspect.py#L577)）。
- Hxv4 table 解析：`parse_hxv4_table()` 解密 payload、zlib 解压并解析 record（[src/common/xp3_inspect.py:658](../../../src/common/xp3_inspect.py#L658)）。
- entry → filter state 映射：`build_filter_state_map()` 对每条 Hxv4 record 调用 `build_filter_state(record.key, open_flag)`（[src/common/xp3_inspect.py:729](../../../src/common/xp3_inspect.py#L729)）。
- 条目内容还原：`extract_entry()` 先按 XP3 segment 读取并 zlib 解压，再对每个 chunk 调用 recovered filter，最后以 adler32 判断是否还原成功（[src/common/xp3_inspect.py:883](../../../src/common/xp3_inspect.py#L883)）。

`drip_program.json` 保存了两层材料：第一层用于打开 Hxv4 映射表，第二层用于复现运行时 DripValue VM，并按每个 Hxv4 record 的 resource key 动态派生实际的 stream filter state。

---

> 第七节给出了 FilterManager 的完整布局与离线导出流程。下一节展示运行时 DLL 内部的 stream read 调用链，以验证过滤逻辑的实际挂载点。

