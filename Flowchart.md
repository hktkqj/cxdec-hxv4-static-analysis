# XP3 资源静态解密流程图

```mermaid
flowchart TD
    A["输入 1：程序文件 EXE<br/>提供 PE Resources、bres salt、BOOTSTRAP DLL 配置来源"] --> B["解析 PE 结构<br/>读取 section table 和 resource directory"]
    B --> B1["RCDATA/STARTUP.TJS<br/>bres 加密的 TJS2100 字节码<br/>用途：提供 BOOTSTRAP URL 和 System.bootStrap prefix"]
    B --> B2["RCDATA/BOOTSTRAP<br/>bres 加密的 bootstrap payload<br/>解密后包含 zlib 压缩 DLL"]
    B --> B3["TEXT/127<br/>UTF-16LE 文本<br/>形如 bres://./{startup_path_key}/"]
    B --> B4["可选 RCDATA/PLUGIN<br/>仅保存为诊断中间产物<br/>不参与主解密链路"]

    A --> C["读取 0x2000 字节 bres salt<br/>默认：从 EXE 自动检测并校验<br/>可覆盖：--salt-file / --salt-file-offset / --salt-rva"]
    B3 --> D["解析 STARTUP.TJS path key<br/>去掉 bres://./ 前缀和尾部 /<br/>得到 startup_key"]
    B1 --> E["解密 STARTUP.TJS<br/>key material = startup_key.encode(UTF-16LE) + salt<br/>digest = SHA3-384(key material)<br/>cipher = ChaCha8 stream"]
    C --> E
    D --> E
    E --> F{"校验 STARTUP.TJS 明文<br/>文件头是否为 TJS2100\\0"}
    F -- "否" --> F1["停止：STARTUP.TJS 解密失败<br/>检查 salt 位置、salt 长度、TEXT/127 path key、资源来源 EXE"]
    F -- "是" --> G["解析 TJS2 bytecode chunk<br/>读取 DATA chunk 字符串池<br/>并输出 STARTUP.TJS.dec"]
    G --> G1["反编译 STARTUP.TJS<br/>tools/tjs2-decompiler<br/>输出 work-dir/STARTUP.TJS"]

    G --> H["查找 BOOTSTRAP URL<br/>字符串满足 bres://./.../bootstrap"]
    H --> I["提取 BOOTSTRAP path key<br/>取 URL 中 bres://./ 后第一段"]
    G1 --> J["查找 System.bootStrap prefix<br/>优先解析源码 _bootStrap(\"...\") 第一参数<br/>失败时回退到常量池中包含 all 的字符串"]
    G --> J

    B2 --> K["解密 BOOTSTRAP<br/>算法同 bres：SHA3-384(path_key_utf16le + salt) + ChaCha8<br/>path_key = bootstrap_key"]
    C --> K
    I --> K
    K --> L["解析 BOOTSTRAP 明文封装<br/>默认跳过 8 字节 header<br/>可覆盖：--bootstrap-zlib-offset"]
    L --> M["zlib.decompress(payload)<br/>得到随机插件 DLL 字节"]
    M --> N{"DLL 校验<br/>解压结果是否以 MZ 开头"}
    N -- "否" --> N1["停止：BOOTSTRAP 解包失败<br/>检查 bootstrap_key、salt、zlib offset、资源是否匹配"]
    N -- "是" --> O["输出中间产物 bootstrap.dll<br/>写入 work-dir/bootstrap.dll"]

    O --> P["读取 bootstrap.dll 配置表<br/>默认 RVA 0x80E38<br/>格式：label\\0 + uint16 length + value"]
    P --> P1["UNIQUE<br/>UTF-16LE archive unique key<br/>参与归档级 key 派生"]
    P --> P2["WARNING<br/>ASCII bootstrap suffix<br/>DLL 内部会拼到 prefix 后"]
    P --> P3["PARAMS / PUBKEY 等配置<br/>用于 DLL 内部派生逻辑<br/>由 FilterManagerDerive 调用 DLL 处理"]

    J --> Q["构造最终 bootstrap 输入<br/>final_bootstrap = prefix + WARNING<br/>传给 DLL 内部 System_bootStrap 派生逻辑"]
    P2 --> Q
    O --> R["运行 FilterManagerDerive<br/>x86 .NET 工具离线加载 bootstrap.dll<br/>输入：bootstrap.dll、bootstrap_prefix、UNIQUE<br/>archive seed 由工具自动解析"]
    Q --> R
    P1 --> R
    P3 --> R
    R --> R1["解析 archive seed<br/>--archive-seed-hex 优先<br/>否则读取 DLL RVA 0x81758<br/>全 0 时扫描 ArchiveUpdate 默认常量"]
    R1 --> S["执行 DLL 内部派生函数<br/>复现运行时 FilterManager 初始化<br/>得到 DripValue VM 状态和 Hxv4 解密材料"]
    S --> T["生成 drip_program.json<br/>后续 XP3 解密的核心状态文件"]

    T --> T1["hxv4_key<br/>32 字节 XChaCha20-Poly1305 key<br/>用于打开 Hxv4 映射表"]
    T --> T2["hxv4_nonce0 / hxv4_nonce1<br/>24 字节 nonce<br/>按 Hxv4 descriptor.flags & 1 选择"]
    T --> T3["holder_words[0..5]<br/>FilterManager holder 常量<br/>用于 key 预处理、split_offset、bulk_key 派生"]
    T --> T4["context_u32[]<br/>DripValue 全局查表数据<br/>lane opcode 可读取该表"]
    T --> T5["lanes[128].records<br/>每条 record = [param, callback_rva]<br/>解释执行以复现 get64_from_u32()"]

    X["输入 2：XP3 文件<br/>如 main.xp3 / data.xp3 / scn.xp3"] --> Y["读取 XP3 header<br/>校验 XP3 magic<br/>解析 index offset"]
    Y --> Z["读取 XP3 index block<br/>支持普通 index 或 0x17 pointer block<br/>按 flag 判断是否 zlib 压缩"]
    Z --> Z1["解析 File chunks<br/>得到 entry 名称、flags、original_size、segments、adlr"]
    Z --> Z2["查找 Hxv4 chunk descriptor<br/>字段：payload_offset、payload_size、flags<br/>flags bit0 = open_flag"]

    Z2 --> AA["按 payload_offset / payload_size<br/>从 XP3 文件读取 Hxv4 encrypted payload<br/>格式：16 字节 Poly1305 tag + ciphertext"]
    T1 --> AB["解密 Hxv4 payload<br/>XChaCha20-Poly1305<br/>key = hxv4_key<br/>nonce = hxv4_nonce[flags & 1]"]
    T2 --> AB
    Z2 --> AB
    AA --> AB
    AB --> AC["解析 Hxv4 明文封装<br/>前 4 字节 = uncompressed_size<br/>后续 = zlib 压缩 TJS binary Variant"]
    AC --> AC1["zlib.decompress<br/>校验解压长度等于 uncompressed_size"]
    AC1 --> AD["解析 big-endian TJS Variant<br/>得到 Hxv4 records 数组"]
    AD --> AD1["xp3_entry_index<br/>archive_slot == 0 时：filter_flag + entry_base"]
    AD --> AD2["resource key uint64<br/>每个资源独立 key<br/>不是最终明文 key，需要进入 Drip 派生"]
    AD --> AD3["packed 字段<br/>高 16 位 archive_slot<br/>低 16 位 filter_flag"]

    AD2 --> AE["派生 48-byte filter seed state<br/>DripProgram.build_filter_state(key, open_flag)"]
    Z2 --> AE
    T3 --> AE
    T4 --> AE
    T5 --> AE
    AE --> AE1["key 预处理<br/>key_lo/key_hi 拆分<br/>open_flag == 0 时 XOR holder_words[2]/[3]"]
    AE1 --> AE2["生成 boundary seeds<br/>state[0:8] = get64_from_u32(key_lo)<br/>state[8:16] = get64_from_u32(key_hi)"]
    AE2 --> AE3["生成 split_offset<br/>holder_words[5] + (holder_words[4] & (key64 >> 16))"]
    AE3 --> AE4["生成 16 字节 bulk_key<br/>反复调用 get64_from_u32(~key64_low)"]
    AE4 --> AF["48-byte seed state<br/>boundary_seed_0、boundary_seed_1、split_offset、bulk_key、flags"]
    AF --> AG["初始化 FilterRuntimeState<br/>从 boundary seed 计算 pos0/pos1、boundary key、byte0/byte1"]

    Z1 --> AH["遍历 XP3 entries<br/>按 segment 描述读取每个资源的物理数据"]
    X --> AH
    AH --> AI["读取 segment bytes<br/>offset / archived_size 来自 XP3 index"]
    AI --> AJ{"segment flags 是否表示 zlib 压缩"}
    AJ -- "是" --> AK["zlib.decompress(segment)<br/>得到 XP3 层解压后的 entry chunk"]
    AJ -- "否" --> AL["直接使用 segment 原始 bytes"]
    AK --> AM["合并 entry chunks<br/>得到 original_size 长度的候选数据"]
    AL --> AM

    AD1 --> AN["建立 entry_index -> FilterRuntimeState 映射<br/>只有存在 Hxv4 record 的 entry 才有 recovered filter"]
    AG --> AN
    AM --> AO{"是否应用 recovered filter<br/>条件：--filter recovered<br/>且该 entry 有对应 FilterRuntimeState"}
    AN --> AO
    AO -- "否" --> AP["不应用运行时过滤<br/>直接进入 adlr 校验<br/>适用于未保护或原始 adlr 已匹配的 entry"]
    AO -- "是" --> AQ["FilterRuntimeState.apply(data, logical_offset)<br/>复现 DLL 在 IStream::Read 后的过滤逻辑"]
    AQ --> AR["Layer 1：Bulk XOR<br/>仅 logical offset [0,16) 范围<br/>data[i] ^= bulk_key[offset+i]"]
    AR --> AS["Layer 2：split_offset 分段<br/>split 前使用 boundary0<br/>split 后使用 boundary1"]
    AS --> AT["Layer 3：Rotated dword key XOR<br/>按 logical_offset % 4 选择 boundary key 字节"]
    AT --> AU["Layer 4：Boundary byte XOR<br/>若 read range 覆盖 pos0/pos1<br/>再 XOR byte0/byte1"]
    AU --> AV["得到过滤后的 entry 明文候选"]
    AP --> AW["计算 Adler32<br/>与 XP3 File chunk 的 adlr 比较"]
    AV --> AW
    Z1 --> AW

    AW --> AX{"adlr 是否匹配"}
    AX -- "否" --> AX1["失败或未还原<br/>检查 drip_program 是否匹配目标 EXE/DLL<br/>检查 open_flag、Hxv4 映射、salt、BOOTSTRAP prefix"]
    AX -- "是" --> AY["写出最终资源文件<br/>文件内容已通过 XP3 adlr 校验"]
```

## Hxv4 细节文档索引

Mermaid 图展示的是端到端主链路；各加密子层的详细说明已拆分到以下文档：

| 主题 | 文档 |
|------|------|
| Hxv4 chunk、descriptor、payload 解密和 record 映射 | [docs/core/hxv4/01-hxv4-table.md](docs/core/hxv4/01-hxv4-table.md) |
| BOOTSTRAP 初始化、FilterManager KDF 和 key/nonce 派生 | [docs/core/hxv4/02-bootstrap-kdf.md](docs/core/hxv4/02-bootstrap-kdf.md) |
| `domain_hash` / `file_hash` 与资源路径匹配 | [docs/core/hxv4/03-resource-hash.md](docs/core/hxv4/03-resource-hash.md) |
| DripValue VM、lane 和 opcode 语义 | [docs/core/hxv4/04-dripvalue-vm.md](docs/core/hxv4/04-dripvalue-vm.md) |
| `record.key` 到 48-byte filter seed state 的派生 | [docs/core/hxv4/05-filter-state.md](docs/core/hxv4/05-filter-state.md) |
| FilterImpl / Stream XOR 四层变换 | [docs/core/hxv4/06-stream-filter.md](docs/core/hxv4/06-stream-filter.md) |
| FilterManager 运行时状态和 `drip_program.json` 字段对应 | [docs/core/hxv4/07-filter-manager-runtime.md](docs/core/hxv4/07-filter-manager-runtime.md) |
| 运行时 stream read 调用链 | [docs/core/hxv4/08-runtime-read-path.md](docs/core/hxv4/08-runtime-read-path.md) |
| 样本 key/nonce 常量和验证结果 | [docs/core/hxv4/09-sample-constants.md](docs/core/hxv4/09-sample-constants.md)、[docs/core/hxv4/10-validation-results.md](docs/core/hxv4/10-validation-results.md) |

## 关键阶段说明

### 1. 程序文件侧：生成 `drip_program.json`

程序文件侧的目标不是直接解密 XP3，而是复现游戏启动时随机插件 DLL 初始化 `FilterManager` 的结果。流程从 EXE 的 PE Resources 中取出 `STARTUP.TJS`、`BOOTSTRAP` 和 `TEXT/127`，再用 0x2000 字节 bres salt 对 `STARTUP.TJS` 与 `BOOTSTRAP` 分别执行：

```text
digest = SHA3-384(path_key.encode("utf-16le") + bres_salt)
plaintext = ChaCha8(digest-derived stream) XOR ciphertext
```

`STARTUP.TJS` 解密后会保留两份中间产物：`STARTUP.TJS.dec` 是 TJS2 字节码，反编译后的 `STARTUP.TJS` 是源码文本。BOOTSTRAP URL 仍来自 TJS2 `DATA` chunk 字符串池；脚本级 `System.bootStrap` prefix 优先从源码中的 `_bootStrap("...")` 第一参数取得，反编译失败时才回退到常量池中包含 `all` 的字符串。`BOOTSTRAP` 解密后跳过 header 并 zlib 解压出 `bootstrap.dll`，随后读取 DLL 配置表中的 `UNIQUE`、`WARNING`、`PARAMS` 等数据。

`FilterManagerDerive` 离线加载 `bootstrap.dll`，传入 `bootstrap_prefix` 和 `UNIQUE`，让 DLL 自身执行底层派生逻辑。archive seed 在工具内自动确定：显式 `--archive-seed-hex` 优先，否则读取 DLL RVA `0x81758` 的 8 字节静态 seed；如果该位置全 0，则扫描 `FilterManager_ArchiveUpdate` 内的默认常量，得到默认 seed `ceeaaf2cefbeadde`。最终导出：

- `hxv4_key` / `hxv4_nonce0` / `hxv4_nonce1`
- `holder_words`
- `context_u32`
- `lanes[].records`

这些字段共同组成 `drip_program.json`。

### 2. XP3 侧：从 Hxv4 映射到每个资源的 filter state

XP3 index 中的 `Hxv4` chunk 不直接存明文映射表，而是把映射表放在 XP3 文件其他位置，并用 XChaCha20-Poly1305 加密。解密时使用：

```text
key   = drip_program.hxv4_key
nonce = drip_program.hxv4_nonce0  if descriptor.flags & 1 == 0
nonce = drip_program.hxv4_nonce1  if descriptor.flags & 1 == 1
```

解密后的 Hxv4 payload 还需要 zlib 解压，再按 big-endian TJS binary Variant 解析。每条 record 给出：

- `archive_slot`
- `filter_flag`
- `resource key uint64`
- 对应的 `xp3_entry_index`

其中 `resource key` 仍不是最终明文 key，而是输入 DripValue VM 的 per-resource seed。

### 3. 内容侧：运行时 filter 的离线复现

对每个 Hxv4 record，程序调用：

```text
seed_state = drip_program.build_filter_state(resource_key, open_flag)
filter_state = FilterRuntimeState(seed_state)
```

`build_filter_state()` 会使用 `holder_words`、`context_u32` 和 128 条 `lanes` 解释执行 DripValue VM，生成 48 字节 seed state。这个 state 再被拆成：

- 两个 boundary seed
- 一个 split offset
- 16 字节 bulk key
- has_drip/null_mode 标记

XP3 entry 的 segment 先按 XP3 标准流程读取并 zlib 解压，然后才应用 recovered filter。filter 包含四层 XOR：bulk XOR、按 split offset 分段、rotated dword key XOR、boundary byte XOR。最终结果用 XP3 `adlr` 校验，匹配时才写出最终资源文件。

### 4. 常见失败点

| 失败位置 | 常见原因 |
|----------|----------|
| `STARTUP.TJS` 不是 `TJS2100\0` | salt 位置错误、salt 长度错误、`TEXT/127` path key 不匹配、EXE 资源来源错误 |
| `BOOTSTRAP` 无法 zlib 解压 | BOOTSTRAP bres key 错误、`--bootstrap-zlib-offset` 错误、salt 错误 |
| DLL 配置表缺少 `UNIQUE` / `WARNING` | `--table-rva` 不匹配、BOOTSTRAP DLL 版本不匹配 |
| Hxv4 payload 解密失败 | `drip_program.json` 不属于该游戏/DLL、nonce 选择错误、XP3 文件不匹配 |
| entry adlr 不匹配 | filter state 派生错误、open_flag 错误、Hxv4 record 到 entry 的映射错误、XP3 与 EXE/DLL 不配套 |
