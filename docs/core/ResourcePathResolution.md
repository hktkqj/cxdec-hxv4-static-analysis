# 游戏资源路径解析与 HXV4 索引查找分析

本文档通过 IDA Pro MCP 逆向分析主程序 `SabbatOfTheWitch_dump_SCY.exe`，梳理游戏如何处理资源路径、如何在不同层级补全文件名、以及最终如何通过 HXV4 索引定位加密资源。

---

## 一、总体架构

```
┌─────────────────────────────────────────────────────────┐
│ TJS / KAG 脚本层                                         │
│   资源请求 (含扩展名补全)                                │
│   例: "bgm01.opus", "学院_廊下モブa.png", "startup.tjs" │
├─────────────────────────────────────────────────────────┤
│ 主程序 EXE 存储框架                                      │
│   TVPCreateBinaryStreamForStorageName (0xC615D0)        │
│   sub_C61740 (亦通过 off_FD2C00 引用)                   │
│   sub_C6EDB0 — 存储媒体名称解析 + 查找                   │
├─────────────────────────────────────────────────────────┤
│ Bootstrap DLL (1ae7153ed25d.dll)                        │
│   CompoundStorageMedia                                  │
│   pathHash() / fileHash() → domain_hash / file_hash    │
│   HXV4 表查找                                           │
│   Stream Filter 解密                                    │
├─────────────────────────────────────────────────────────┤
│ XP3 Archive → HXV4 → 解密后的明文数据                   │
└─────────────────────────────────────────────────────────┘
```

**关键结论**：扩展名（`.opus`, `.png`, `.tjs` 等）**不在主程序 EXE 的 C++ 代码中补全**，而是在到达存储层之前，由 TJS/KAG 脚本层或 Bootstrap DLL 完成。

---

## 二、内部存储名称格式

主程序内部使用特定分隔符来解析存储名称的结构：

### 2.1 分隔符一览

| 分隔符 | 字符 | 使用位置 | 作用 |
|--------|------|----------|------|
| `>` | 0x3E | `sub_C6EDB0` @ `word_FD0CDC` | 分离存储媒体名与文件标识符 |
| `o` | 0x6F | `TVPCreateBinaryStreamForStorageName` (0xC61636) | 定位数字文件键的起始位置 |
| `o` | 0x6F | `sub_C61740` (0xC617A0) | 同上 |
| `b` | 0x62 | `sub_CDAA00` (Array.saveStruct) | 决定使用哪个流打开函数路径 |
| `b` | 0x62 | `sub_D05CB0` (Dictionary.saveStruct) | 同上 |

### 2.2 存储名称解析流程 (`sub_C6EDB0` @ 0xC6EDB0)

```
1. 对传入的 storage URL 查找 '>' (0x3E)
2. 若找到 '>'，分割为 [media_prefix, file_identifier]
3. 对 file_identifier 计算 hash (sub_C6BF30)
4. 以 hash 查找或创建缓存的存储上下文
5. 返回对应的存储媒体对象
```

### 2.3 字符串哈希函数 (`sub_C6BF30` @ 0xC6BF30)

用于对存储名称进行哈希以实现 O(1) 缓存查找：

```python
# 伪代码复现
hash_val = 0
for char in utf16_string:
    hash_val = ((1025 * (char + hash_val)) >> 6) ^ (1025 * (char + hash_val))
# 第二轮压缩
hash_val = 32769 * (((9 * hash_val) >> 11) ^ (9 * hash_val))
if hash_val == 0:
    hash_val = 0xFFFFFFFF  # -1 哨兵
```

### 2.4 数字文件键提取 (`TVPCreateBinaryStreamForStorageName` @ 0xC615D0)

```
1. 在存储名称中查找 'o' (0x6F)
2. 若找到，从 'o' 之后提取连续数字字符 (0-9)
3. 将数字字符串转换为整数 → 作为 file_key
4. 调用存储媒体的 vtable[0](media, file_key, 0, 0) 创建流
```

---

## 三、关键函数调用关系

### 3.1 存储流创建入口

```
TJS Scripts.execStorage()
  → Scripts_execStorage_or_evalStorage_core (0xC68310)
    → sub_C6ECB0()       — 创建存储上下文
    → TVPCreateBinaryStreamForStorageName()  — 打开存储流
    → TryLoadCompiledTJSBytecodeFromStream() — 尝试字节码
    → 若失败：文本流 + compile/execute
```

### 3.2 存储媒体获取

```
TVPCreateBinaryStreamForStorageName (0xC615D0)
  → sub_C6F040()         — 获取存储媒体入口
    → sub_C6EDB0()       — 存储名称解析 + 媒体查找
      → sub_C6EA50()     — 缓存查找/创建
        → sub_C6BF30()   — 字符串哈希
        → sub_C71160()   — 哈希表查找 (64槽 + 链表)
```

### 3.3 全局函数注册 (`TVP_InitTJSGlobalClasses` @ 0xC674A3)

```c
off_FD2C04 = TVPCreateBinaryStreamForStorageName;  // 创建存储流
off_FD2C00 = sub_C61740;                            // 创建存储流 (备用)
off_FD2C08 = sub_C75570;                            // 存储相关
off_FD2C0C = sub_C755F0;                            // 存储相关
```

`TVPCreateBinaryStreamForStorageName` 和 `sub_C61740` 在逻辑上几乎相同，区别是 `sub_C61740` 在找不到 `'o'` 分隔符时直接使用 `sub_C6F040()` 返回默认媒体。

---

## 四、不同资源类型的文件名补全规则

### 4.1 已确认规则（来自 [[Hxv4Ripped.md]] Section 9.8）

| 资源类型 | 裸逻辑名 | 参与 fileHash() 的 filename | XP3 包 | 证据 |
|----------|---------|---------------------------|--------|------|
| BGM 音频 | `bgm01` | `bgm01.opus` | bgm.xp3 | record 1 / entry 1 |
| BGM loop | `bgm01` | `bgm01.opus.sli` | bgm.xp3 | record 2 / entry 2 |
| 背景图 | `学院_廊下モブa` | `学院_廊下モブa.png` | bgimage.xp3 | record 77 / entry 77 |
| 启动脚本 | `startup` | `startup.tjs` | data.xp3 | explicit |
| 数据文件 | `!cglist.csv` | `!cglist.csv` | data.xp3 | 显式扩展名 |

### 4.2 `.sli` 扩展名的 C++ 端处理

**这是唯一在主程序 C++ 代码中被硬编码追加的扩展名**。

调用链：
```
WaveSoundBuffer.open()           — TJS 方法
  → sub_CC0750 (0xCC0750)       — TJS native handler
    → sub_CD1200 (0xCD1200)     — 打开 .sli 文件
      → sub_C66D10(aSli)        — 在音频文件名后追加 ".sli"
      → sub_C6F040()            — 获取存储媒体
      → IStream::Read           — 读取整个 .sli 文件
      → sub_CC6520 (0xCC6520)   — 解析 LoopStart= / LoopLength=
```

`sub_CC6520` 的解析逻辑：
1. 第一字符为 `#` → 跳过注释行
2. 搜索 `link` 或 `label` 标签
3. 搜索 `loopstart=` 和 `looplength=` 键值对
4. 解析等号后的数值

### 4.3 `.opus`/`.png`/`.tlg` 扩展名的补全位置

在主程序 EXE 中**未找到**以下内容：
- `.opus`, `.png`, `.tlg`, `.tjs` 等扩展名字符串
- "按资源类型统一补扩展名"的全局表
- 循环尝试多种扩展名的代码

因此这些扩展名的补全必然发生在：
1. **TJS/KAG 脚本层**（如 startup.tjs 中的资源管理器代码）
2. **Bootstrap DLL** 的 CompoundStorageMedia 实现中

具体是哪一层，需要在 Bootstrap DLL 或 TJS 脚本中进一步确认。建议通过 hook `CompoundStorageMedia.fileHash()` 观察实际传入的字符串。

### 4.4 路径/域名补全规则

来自 [[Hxv4Ripped.md]] Section 9.5：

- 初始自动挂载 domain = `""`（空字符串）
- `pathHash("")` → `94d4a97c61498621`（命中 bgm.xp3 / bgimage.xp3 所有 record）
- 自动挂载使用 `autopath(arg0, arg1, arg2).toLowerCase()` 作为 domain
- **不包含** `arc://./`、物理 XP3 路径或 archive 名前缀
- **不包含** `bgm/`、`bgimage/` 等目录前缀

---

## 五、TJS 层存储接口

### 5.1 Storages 类 (`sub_C820F0`)

在主程序中注册的 TJS 方法：

| 方法 | C++ 实现 | 功能 |
|------|----------|------|
| `Storages.link()` | `sub_C82200` → `sub_C81820` → `TVP_LoadPluginFile_CallV2Link` | 加载存储插件 DLL |
| `Storages.unlink()` | `sub_C822A0` | 卸载存储插件 |
| `Storages.getList()` | `sub_C82360` | 获取已加载列表 |

### 5.2 WaveSoundBuffer 类 (`sub_CBFB10`)

| 方法 | C++ 实现 | 功能 |
|------|----------|------|
| `open` | `sub_CC0750` → `sub_CD1200` | 打开音频文件 + 解析 .sli |
| `play` | `sub_CC0830` | 播放 |
| `stop` | `sub_CC08B0` | 停止 |
| `fade` | `sub_CC0940` | 淡入/淡出 |
| `stopFade` | `sub_CC0A30` | 停止淡变 |
| `setPos` | `sub_CC0B10` | 设置播放位置 |

### 5.3 Array/Dictionary 序列化

| 方法 | C++ 实现 | 分隔符检查 |
|------|----------|-----------|
| `Array.saveStruct` | `sub_CDAA00` | 检查 `'b'` (0x62) |
| `Dict.saveStruct` | `sub_D05CB0` | 检查 `'b'` (0x62) |
| `Array.load` | `sub_CDA470` | — |
| `Dict.load` | `sub_D05C70` | — |

分隔符 `'b'` 的存在与否决定了使用哪个底层流打开函数（`off_FD2C00` vs `off_FD2C0C`）。

---

## 六、Config/数据文件路径构造 (`sub_CA2BC0` @ 0xCA2BC0)

专门的配置数据加载函数：
```
1. 读取 "datapath" 配置值
2. sub_C6AE70(path, datapath_value) — 拼接路径
3. sub_C6AE70(path, "cfu")          — 追加后缀/扩展名
4. sub_C61740(path)                  — 打开存储流
5. 读取 8 字节 magic header
6. 验证并读取后续数据
```

这是主程序中为数不多的在 C++ 层显式追加文件后缀的位置。

---

## 七、完整资源查找流程 (端到端)

```
1. TJS/KAG 脚本请求资源
   - 例: KAG @bgm 命令触发 "bgm01" 的音频加载
   - TJS 层将 "bgm01" 补全为 "bgm01.opus"
   
2. 存储名构造
   - 完整存储名: arc://./bgm01.opus (或其他内部格式)
   - 通过 Storages.link() 已加载的 CompoundStorageMedia 插件处理

3. 主程序存储层
   - TVPCreateBinaryStreamForStorageName() 接收存储名
   - sub_C6EDB0() 解析 '>' 分隔符分割媒体和路径
   - sub_C6BF30() 对存储名做查找哈希

4. Bootstrap DLL
   - CompoundStorageMedia 收到 pathname="" 和 filename="bgm01.opus"
   - pathHash("") → domain_hash (SipHash-2-4, key=0)
   - fileHash("bgm01.opus") → file_hash (BLAKE2s-256, key=0)
   - HXV4 表中查找 (domain_hash, file_hash)

5. HXV4 命中 → 获取 Stream Filter
   - packed[15:0] → xp3_entry_index
   - record.key → BuildFilterStateFromUniqueKey()
   - DripValue VM → 48-byte seed state → FilterRuntimeState

6. 数据读取
   - XP3 段读取、zlib 解压
   - FilterRuntimeState.apply(data, offset) — 四层 XOR 变换
   - Adler32 校验
   - 明文数据返回

7. BGM 特例: 返回到 WaveSoundBuffer.open()
   - sub_CD1200 判断是否需要加载 .sli
   - 如需: 追加 ".sli" → 再次走存储层 → sub_CC6520 解析 loop 参数
```

---

## 八、待确认事项

1. **Bootstrap DLL 中的扩展名补全**：当前无法在 IDA 中直接分析 Bootstrap DLL。若其内确有扩展名补全逻辑，则本文第 4.3 节的结论需要修订。

2. **TJS 脚本中的扩展名补全**：`startup.tjs` 虽已解密但因为 TJS2 二进制格式无法直接阅读。需要用 TJS2 反编译器或从运行时内存 dump 中提取。

3. **不同 XP3 包的 domain 对应关系**：Section 9.5 已确认 bgm.xp3 / bgimage.xp3 使用 domain=""，其他包是否也是如此需要逐一验证。

4. **KAG 插件 DLL**：KAG 引擎可能以独立 DLL 形式存在，其内也可能有文件名补全代码。

---

## 九、相关文件

- `src/common/xp3_inspect.py` — 离线解密/提取实现
- `src/common/resource_hash.py` — SipHash/BLAKE2s 复现
- `src/static_extract/compute_resource_hash.py` — 静态 hash 计算
- `docs/core/Hxv4Ripped.md` — HXV4 加密体系完整文档
- `tools/FilterManagerDerive/` — 从 Bootstrap DLL 导出密钥
