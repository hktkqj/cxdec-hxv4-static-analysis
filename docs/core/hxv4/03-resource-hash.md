# FileHash / PathHash 算法

[返回 Hxv4 加密体系总览](../Hxv4Ripped.md) | 上一篇：[Bootstrap 初始化与密钥派生](02-bootstrap-kdf.md) | 下一篇：[DripValue VM 密钥派生](04-dripvalue-vm.md)


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

