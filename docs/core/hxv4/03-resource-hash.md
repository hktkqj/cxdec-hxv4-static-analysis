# Resource Path Resolution and FileHash / PathHash

[返回 Hxv4 加密体系总览](../Hxv4Ripped.md) | 上一篇：[Bootstrap 初始化与密钥派生](02-bootstrap-kdf.md) | 下一篇：[DripValue VM 密钥派生](04-dripvalue-vm.md)

本文介绍资源路径解析、文件名补全、`pathHash` / `fileHash` 以及 Hxv4 record 查找的相关算法。

## 3.1 总体架构

```plain
TJS / KAG 脚本层
  资源请求与部分扩展名补全
  例: "bgm01.opus", "学院_廊下モブa.png", "startup.tjs"
    |
主程序 EXE 存储框架
  TVPCreateBinaryStreamForStorageName (0xC615D0)
  sub_C61740
  sub_C6EDB0: 存储媒体名称解析 + 缓存查找
    |
Bootstrap DLL / CompoundStorageMedia
  pathHash() / fileHash()
  domain_hash / file_hash -> Hxv4 record
  record.key -> stream filter
    |
XP3 archive -> Hxv4 -> 解密后的明文数据
```

`CompoundStorageMedia` 将运行时逻辑资源名映射到 Hxv4 record：

```plain
逻辑 domain/path name  -> pathHash  -> Hxv4 record.domain_hash
逻辑 file name         -> fileHash  -> Hxv4 record.file_hash
```

关键边界：

- 主程序 EXE 的存储层负责解析 storage URL、查找媒体对象、创建流。
- Bootstrap DLL 的 `CompoundStorageMedia` 负责对 domain/path 和 filename 做 Hxv4 lookup hash。
- `.opus` / `.png` / `.tlg` / `.tjs` 等常见资源扩展名不在主程序 EXE 的全局 C++ 表中统一补全；它们通常在 TJS/KAG 脚本层或 Bootstrap DLL / 资源管理器层进入存储层前已经确定。
- `.sli` 是已确认的主程序 C++ 端补全特例。

## 3.2 主程序存储名称解析

主程序内部使用若干单字符分隔符处理 storage name：

| 分隔符 | 字符 | 使用位置 | 作用 |
|--------|------|----------|------|
| `>` | `0x3E` | `sub_C6EDB0` / `word_FD0CDC` | 分离存储媒体名与文件标识符 |
| `o` | `0x6F` | `TVPCreateBinaryStreamForStorageName` / `0xC61636` | 定位数字文件键的起始位置 |
| `o` | `0x6F` | `sub_C61740` / `0xC617A0` | 同上 |
| `b` | `0x62` | `Array.saveStruct` / `sub_CDAA00` | 决定使用哪个流打开函数路径 |
| `b` | `0x62` | `Dictionary.saveStruct` / `sub_D05CB0` | 同上 |

`sub_C6EDB0` 的存储媒体解析流程：

```plain
1. 对传入 storage URL 查找 '>'。
2. 若找到 '>'，分割为 [media_prefix, file_identifier]。
3. 对 file_identifier 计算主程序内部缓存 hash：sub_C6BF30。
4. 以该 hash 查找或创建缓存的存储上下文。
5. 返回对应存储媒体对象。
```

`sub_C6BF30` 不是 Hxv4 的 `pathHash` / `fileHash`，只是主程序存储上下文缓存用的字符串 hash：

```python
hash_val = 0
for char in utf16_string:
    hash_val = ((1025 * (char + hash_val)) >> 6) ^ (1025 * (char + hash_val))

hash_val = 32769 * (((9 * hash_val) >> 11) ^ (9 * hash_val))
if hash_val == 0:
    hash_val = 0xFFFFFFFF
```

数字文件键提取由 `TVPCreateBinaryStreamForStorageName` 处理：

```plain
1. 在存储名称中查找 'o'。
2. 若找到，从 'o' 之后提取连续数字字符。
3. 转为整数 file_key。
4. 调用存储媒体 vtable[0](media, file_key, 0, 0) 创建流。
```

主程序存储流入口调用链：

```plain
TJS Scripts.execStorage()
  -> Scripts_execStorage_or_evalStorage_core (0xC68310)
    -> sub_C6ECB0()
    -> TVPCreateBinaryStreamForStorageName()
    -> TryLoadCompiledTJSBytecodeFromStream()
    -> 若失败：文本流 + compile/execute

TVPCreateBinaryStreamForStorageName (0xC615D0)
  -> sub_C6F040()
    -> sub_C6EDB0()
      -> sub_C6EA50()
        -> sub_C6BF30()
        -> sub_C71160()  # 64 槽 + 链表
```

`TVPCreateBinaryStreamForStorageName` 和 `sub_C61740` 逻辑接近；`sub_C61740` 在找不到 `o` 分隔符时直接使用 `sub_C6F040()` 返回默认媒体。

全局函数注册点：

```c
off_FD2C04 = TVPCreateBinaryStreamForStorageName;
off_FD2C00 = sub_C61740;
off_FD2C08 = sub_C75570;
off_FD2C0C = sub_C755F0;
```

## 3.3 startup.tjs 中的运行时对象关系

反编译后的 `STARTUP.TJS` 给出了关键 TJS 层调用：

```tjs
var hashKeyOctet = System.bootStrap(bootstrapPrefix, autoPathCallback);
var mediaName = (string(bootstrapPrefix)).split(":").count > 1
    ? (string(bootstrapPrefix)).split(":")[0]
    : "xp3hnp";

var media = new Storages.CompoundStorageMedia("arc", mediaName, hashKeyOctet);
autoPathCallback._.zpath = media.pathHash("");
```

已验证样本中的值形态：

```plain
bootstrapPrefix = "<prefix from STARTUP.TJS _bootStrap(...)>"
mediaName       = "xp3hnp"
```

`System.bootStrap(...)` 返回 32 字节 octet，并作为 `CompoundStorageMedia` 第三个参数传入。这个 octet 会被复制到 hasher 对象中，但在当前 DLL 中没有成为有效 keyed hash key。见 3.5。

## 3.4 Bootstrap DLL 中的 hash 调用链

相关函数位于 BOOTSTRAP 解包出的随机 DLL：

| 功能 | 函数 |
| ---- | ---- |
| `System.bootStrap` 回调 | `System_bootStrap_callback` / `0x1000EEB0` |
| 生成 `System.bootStrap` 返回 octet | `sub_100148B0` |
| 创建并注册 `CompoundStorageMedia` | `CompoundStorageMediaClass_CreateAndRegister` / `0x10005ACE` |
| 初始化 `CompoundStorageMedia` hashers | `sub_1000A3D0` |
| `pathHash` TJS 方法 | `sub_10009CE0` |
| `fileHash` TJS 方法 | `sub_10008F60` |
| 统一调用 hasher | `sub_10005FE0` |
| 路径 hash trait | `sub_100169F0` |
| 文件名 hash trait | `FileHashCompute_10016900` |

`pathHash` 和 `fileHash` 都进入 `sub_10005FE0`：

```plain
sub_10009CE0(pathHash)
  -> sub_100064C0
    -> sub_10005FE0(this, out_octet, path_hasher, input_tjs_string)
      -> PathNameHashTrait::compute / 0x100169F0

sub_10008F60(fileHash)
  -> sub_10005FB0
    -> sub_10005FE0(this, out_octet, file_hasher, input_tjs_string)
      -> FileNameHashTrait::compute / 0x10016900
```

`sub_10005FE0` 会把 `CompoundStorageMedia` 构造时保存的 media name 作为 `extra` 传给 hasher：

```plain
input = TJS 方法参数
extra = this + 0x10   # startup.tjs 中的 "xp3hnp"，若为空则不传

hasher.compute(input, extra)
```

hash 输入不是裸文件名，而是两个连续 update：

```plain
Update(UTF-16LE(input))
Update(UTF-16LE(extra))    # extra="xp3hnp"
Final()
```

字节流效果等价于 `UTF-16LE(input) || UTF-16LE("xp3hnp")`，中间没有分隔符，也没有额外长度字段。

## 3.5 hash_key 的真实作用：复制到 key buffer，但 key_len 为 0

IDA 重新核对后的结论：

```plain
new CompoundStorageMedia("arc", "xp3hnp", hash_key)
  -> CompoundStorageMediaClass_CreateAndRegister
    -> sub_1000A3D0
      -> this+0x10 = mediaName
      -> this+0x58 = sub_10016890(hash_key_variant)  # PathNameHashTrait
      -> this+0x5C = sub_10016820(hash_key_variant)  # FileNameHashTrait
```

两个 hasher 的对象布局：

```plain
DefaultCompoundHasher<T>
+0x00 vtable
+0x04 key_ptr
+0x08 key_len
+0x0C inline_key_buffer
```

PathNameHashTrait 构造路径：

```plain
sub_10016890 alloc 0x1C
  -> sub_10016680
     key_ptr = 0
     key_len = 0
     copy min(octet_len, 16) bytes to +0x0C
     key_ptr = this + 0x0C
```

FileNameHashTrait 构造路径：

```plain
sub_10016820 alloc 0x2C
  -> sub_10016580
     key_ptr = 0
     key_len = 0
     copy min(octet_len, 32) bytes to +0x0C
     key_ptr = this + 0x0C
```

因此 `System.bootStrap` 返回 octet 并不是完全没有进入对象。它确实被复制到了内部 key buffer，`key_ptr` 也指向该 buffer；但 `key_len` 没有被写成复制长度，仍保持 0。

后续计算端读取的是同一组字段：

```plain
0x100169F0 path hasher:
  push [ecx+8]  # key_len
  push [ecx+4]  # key_ptr
  call sub_100172E0

0x10016900 file hasher:
  push [ecx+8]  # key_len
  push [ecx+4]  # key_ptr
  call sub_1000E070
```

vtable 也确认虚调用落到上述计算函数：

```plain
PathNameHashTrait vtable 0x100819A0
  +4 = 0x100169F0

FileNameHashTrait vtable 0x100819AC
  +4 = 0x10016900
```

所以当前样本实际 hash 行为是：

```plain
pathHash = SipHash-2-4 with 16-byte zero key
fileHash = unkeyed BLAKE2s-256
```

这个字段状态更像是保留了 keyed-hash 设计但未启用，而不是运行时没有初始化到位：

- `CompoundStorageMedia` API 接收第三个 octet 参数。
- Path/File hasher 都有 `key_ptr` / `key_len` 布局。
- 构造函数确实读取 octet 长度并复制 key bytes。
- 计算函数确实把 `key_ptr` / `key_len` 传给 hash 初始化。
- 唯独没有 `key_len = copied_len` 这一步。

如果 `key_len` 被设置为非零，会出现以下变化：

| 场景 | 结果 |
| ---- | ---- |
| `pathHash.key_len = 16` | `domain_hash` 变成 keyed SipHash，使用 `hash_key[0:16]` |
| `fileHash.key_len = 32` | `file_hash` 变成 keyed BLAKE2s-256，使用 `hash_key[0:32]` |
| 只修改运行时 DLL，XP3 Hxv4 表仍为无 key hash | `(domain_hash, file_hash)` 全部失配，record lookup 失败 |
| 封包器和运行时同时使用非零 `key_len` | 资源查找可正常工作，但离线工具必须先恢复 `System.bootStrap` 返回 octet 才能计算 lookup hash |

注意这只影响 Hxv4 record lookup。`hxv4_key` / `hxv4_nonce*` 解密 Hxv4 payload，以及 `record.key -> DripValue -> 48-byte filter state` 的后续内容过滤链路不因此直接改变。

`hash_key` 仍是有价值的调试产物：它证明 `System.bootStrap` 初始化和 `sub_100148B0` 返回 octet 的路径正确；但在当前 DLL 中它不是 Hxv4 lookup 的有效 keyed hash key。

## 3.6 pathHash：domain_hash 的计算

路径 hash trait 位于 `sub_100169F0`。其特征：

- 初始化常数为 SipHash 标准 IV：`somepseudorandomlygeneratedbytes`
- key length 实际为 0，因此使用全零 16 字节 key 初始化
- 对输入 TJS 字符串按 UTF-16LE 字节 update
- 若 `extra` 非空，再对 `extra` 的 UTF-16LE 字节做第二次 update
- finalize 输出 8 字节，按小端字节序显示为 Hxv4 `domain_hash`

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

因此初始 domain/path 参数是空字符串。实测：

```plain
pathHash("", extra="xp3hnp") = 94d4a97c61498621
```

该值命中 `bgm.xp3` / `bgimage.xp3` 中已验证 record 的 `domain_hash`。

domain/path 不包含：

- `arc://./`
- 物理 XP3 路径
- archive 名前缀
- `bgm/`、`bgimage/` 等目录前缀

自动挂载流程使用 `autopath(arg0, arg1, arg2).toLowerCase()` 作为 domain；当前已验证的 `bgm.xp3` / `bgimage.xp3` 使用空 domain，其他 XP3 包仍应逐包验证。

## 3.7 fileHash：file_hash 的计算

文件名 hash trait 位于 `FileHashCompute_10016900`。压缩函数 `sub_10012500` 通过以下特征确认为标准 BLAKE2s-256：

- 初始化常数完全匹配 BLAKE2s IV，即 SHA-256 IV：`6A09E667 BB67AE85 3C6EF372 A54FF53A ...`
- 汇编中出现 `rol ebx, 10h`、`rol ebx, 0Ch`，与 BLAKE2s G 函数吻合
- 64 字节消息块，32 字节输出，有 counter 和 finalization flag 字段

当前样本 `key_len == 0`，所以走 unkeyed BLAKE2s-256：

```python
file_hash = hashlib.blake2s(
    filename.encode("utf-16le") + "xp3hnp".encode("utf-16le"),
    digest_size=32,
).hexdigest()
```

`filename` 必须是运行时传给 `CompoundStorageMedia.fileHash()` 的规范化逻辑文件名，通常已经包含扩展名。裸逻辑名不可直接使用。

## 3.8 filename 补全和资源类型规则

主程序侧 storage 打开链路：

```plain
TJS / KAG / 资源管理器请求
  -> TVPCreateBinaryStreamForStorageName
  -> CompoundStorageMediaFS_Open
  -> CompoundStorageMediaFS_MapNameToFileKey
  -> pathHash / fileHash + Hxv4 lookup
```

Hxv4 中参与 `fileHash()` 的 `filename` 是脚本层或资源管理器完成类型补全之后，传入 storage 层的相对逻辑文件名。

已确认样本：

| 资源类型 | 裸逻辑名示例 | 参与 `fileHash()` 的 filename | XP3 包 | 证据 |
| -------- | ------------ | ----------------------------- | ------ | ---- |
| BGM 音频 | `bgm01` | `bgm01.opus` | `bgm.xp3` | record 1 / entry 1 |
| BGM loop sidecar | `bgm01` | `bgm01.opus.sli` | `bgm.xp3` | record 2 / entry 2 |
| 背景图 | `学院_廊下モブa` | `学院_廊下モブa.png` | `bgimage.xp3` | record 77 / entry 77 |
| 启动脚本 | `startup` | `startup.tjs` | `data.xp3` | explicit |
| 数据文件 | 显式 storage | `cglist.csv` 等 | `data.xp3` | 显式扩展名 |

`.sli` 是唯一已确认在主程序 C++ 代码中硬编码追加的扩展名：

```plain
WaveSoundBuffer.open()
  -> sub_CC0750
    -> sub_CD1200
      -> sub_C66D10(aSli)        # 在音频文件名后追加 ".sli"
      -> sub_C6F040()
      -> IStream::Read
      -> sub_CC6520              # 解析 LoopStart= / LoopLength=
```

`sub_CC6520` 的 `.sli` 解析逻辑：

```plain
1. 第一字符为 '#' 时跳过注释行。
2. 搜索 link 或 label 标签。
3. 搜索 loopstart= 和 looplength=。
4. 解析等号后的数值。
```

主程序 EXE 中未找到以下全局补全机制：

- `.opus`、`.png`、`.tlg`、`.tjs` 等扩展名字符串
- 按资源类型统一补扩展名的 C++ 全局表
- 循环尝试多种扩展名的代码

因此这些扩展名的补全应发生在 TJS/KAG 脚本层、Bootstrap DLL 的 `CompoundStorageMedia` 实现或资源管理器层。具体位置可通过 hook `CompoundStorageMedia.fileHash()` 观察实际输入字符串进一步确认。

配置数据加载 `sub_CA2BC0` 是另一个主程序 C++ 端路径构造特例：

```plain
1. 读取 "datapath" 配置值。
2. sub_C6AE70(path, datapath_value)
3. sub_C6AE70(path, "cfu")
4. sub_C61740(path)
5. 读取 8 字节 magic header。
6. 验证并读取后续数据。
```

## 3.9 Hxv4 record 定位流程

离线定位一个逻辑资源名时，按以下顺序处理：

```plain
1. 解析 XP3 index，解密并解压 Hxv4 table。
2. 从 STARTUP.TJS 确认 CompoundStorageMedia mediaName，本作为 "xp3hnp"。
3. 确认运行时 domain/path，初始 archive domain 通常是 ""。
4. domain_hash = pathHash(domain_path, extra=mediaName)。
5. 确认运行时规范化 filename，通常含扩展名。
6. file_hash = fileHash(filename, extra=mediaName)。
7. 在 Hxv4 records 中查找同时满足 domain_hash 和 file_hash 的 record。
8. 命中后：packed 低 16 位 -> XP3 entry index；record.key -> stream filter 派生。
```

端到端资源读取流程：

```plain
1. TJS/KAG 脚本请求资源。
2. 脚本层或资源管理器层形成完整 filename。
3. 主程序存储层解析 storage name 并取得 CompoundStorageMedia。
4. Bootstrap DLL 对 pathname / filename 计算 Hxv4 lookup hash。
5. Hxv4 命中 record。
6. record.key 经 DripValue VM 派生 48-byte seed state。
7. XP3 segment 读取和 zlib 解压后应用 FilterRuntimeState。
8. Adler32 校验通过后返回明文。
```

重要区分：

| 名称 | 用途 |
| ---- | ---- |
| `hxv4_key` / `hxv4_nonce*` | 解密 Hxv4 payload |
| `System.bootStrap` 返回 octet / `hash_key` | 传给 `CompoundStorageMedia`，当前样本中被复制但 `key_len=0` |
| `mediaName` / `"xp3hnp"` | `pathHash` / `fileHash` 的额外 update 输入 |
| `domain_hash` / `file_hash` | Hxv4 table lookup key |
| `record.key` | 命中 record 后用于内容 stream filter 派生 |

## 3.10 DLL 内嵌常量表

`sub_10010380` 实现线性扫描的 key-value 表，起始地址为 `0x10080E38`。格式为：

```plain
ascii label + NUL
uint16 length
raw value[length]
```

关键项：

| 键 | 长度 | 内容 |
| ---- | ---- | ---- |
| `PARAMS` | 22 字节 | 结构化配置参数：`04 06 02 00 07 01 03 05 03 00 05 04 02 01 01 02 00 80 26 02 C8 01` |
| `UNIQUE` | 变长 | UTF-16LE archive unique key |
| `PUBKEY` | 248 字节 | PEM 格式 RSA-1024 公钥 |
| `WARNING` | 67 字节 | ASCII 警告文本 |

## 3.11 与标准算法差异对比

| 项目 | pathHash | fileHash |
| ---- | -------- | -------- |
| 标准算法 | SipHash-2-4 | BLAKE2s-256 |
| 当前有效 key | 16 字节全零 | 无 key |
| 保留的 key buffer | `hash_key[0:16]` 被复制但 `key_len=0` | `hash_key[0:32]` 被复制但 `key_len=0` |
| 主输入 | UTF-16LE pathname | UTF-16LE filename |
| 附加输入 | UTF-16LE mediaName | UTF-16LE mediaName |
| 输出 | 8 字节 | 32 字节 |
| Hxv4 字段 | `domain_hash` | `file_hash` |

## 3.12 待确认事项

1. Bootstrap DLL 或 TJS/KAG 脚本中是否存在更多扩展名补全规则，仍需通过 hook `CompoundStorageMedia.fileHash()` 或更完整的 TJS2 反编译确认。
2. 当前已确认 `bgm.xp3` / `bgimage.xp3` 使用 domain `""`；其他 XP3 包的 domain 应逐包验证。
3. 如果后续样本修正 `key_len`，则 `src/common/resource_hash.py` 和 `compute_resource_hash.py` 需要启用 keyed 模式并使用 `System.bootStrap` 返回 octet 计算 lookup hash。
4. KAG 插件 DLL 可能也参与资源名规范化，需要结合具体游戏模块继续确认。

## 3.13 相关文件

- `src/common/resource_hash.py`：Python 复现 `pathHash` / `fileHash`。
- `src/static_extract/compute_resource_hash.py`：静态计算 hash，并可结合 `manifest.jsonl` 查找输出文件。
- `src/common/xp3_inspect.py`：离线解析 Hxv4 table、构建 filter state、验证和提取 XP3 entry。
- `tools/FilterManagerDerive/Program.cs`：离线加载 BOOTSTRAP DLL，导出 `hash_key` / Hxv4 key / nonce / DripValue 状态。

---

> 第三节完成了从逻辑资源名到 Hxv4 record 的定位。每条 record 包含一个 64-bit unique key，这个 key 需要经过 DripValue VM 派生为 filter 种子。下一节分析这个 VM 的架构和运行时语义。
