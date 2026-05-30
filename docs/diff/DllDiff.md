# 随机 DLL 多版本对比分析

工作区中存在两个随机 DLL 样本，均为 KiriKiri V2 XP3 加密插件框架的配置变体：

| 文件 | SHA-256 前缀 | 对应游戏 |
| --- | --- | --- |
| `1ae7153ed25d.dll` | 1ae7153ed25d... | 0721 |
| `9bd81f525ace.dll` | 9bd81f525ace... | 扑棱蛾子 |

两文件大小完全相同（**763,392 bytes**），代码段 `.text` 完全一致，仅 `.rdata` 节中存在 **391 字节**差异，集中在三个区域。

## 差异区域 1：PARAMS 密码置换表（VA `0x10080E41`，21 字节）

`.rdata` 内嵌一张以 `PARAMS\0` 为标签的参数表，格式为 `[标签\0][uint16 长度][数据]`，由 `System_bootStrap_callback` → `sub_10010380` 解析，用于驱动 Filter 系统的密钥调度。

| 字节组 | `1ae7153ed25d.dll` | `9bd81f525ace.dll` |
| --- | --- | --- |
| 置换表前 8 字节 | `04 06 02 00 07 01 03 05` | `06 03 01 02 05 00 07 04` |
| 置换表后 8 字节 | `03 00 05 04 02 01 01 02` | `05 02 04 00 01 03 01 02` |
| 附加参数 5 字节 | `80 26 02 C8 01` | `01 E6 01 65 00` |

## 差异区域 2：UNIQUE 字符串与 PUBKEY（VA `0x10080E52`，~350 字节）

**UNIQUE 字符串**（UTF-16LE，由 `Storages_archiveUniqueKey_binary_hook` 读取后作为 XP3 归档唯一标识密钥）：

| 文件 | UNIQUE 字符串 |
| --- | --- |
| `1ae7153ed25d.dll` | `{NENeMEGURuTSUMUGiTOUKoWAKANa}` |
| `9bd81f525ace.dll` | `{Kanna+Natsume+Nozomi+Mei+Suzune}` |

表项中字符串前面的 `0x003C` / `0x0042` 是 `uint16` 数据长度，不属于 UTF-16LE 字符串。后者为明文角色名列表（Kanna、Natsume、Nozomi、Mei、Suzune），前者为混淆后的缩写形式。

**PUBKEY**：两个版本内嵌了完全不同的 RSA 1024-bit PEM 公钥，用于归档密钥的合法性校验。

## 差异区域 3：档案名密钥种子（VA `0x10081758`，8 字节）

位于 `--no` 与 `--debugwin` 选项条目之间。由 `Storages_archiveUniqueKey_string_hook` → `FilterManager_UpdateGlobalKeyFromArchiveName` 使用，作为从 XP3 文件名派生每文件解密密钥的基础种子（`sub_10010410` 对其做 HMAC 后 XOR 到 FilterManager 全局密钥槽）。

| 文件 | 8 字节种子 |
| --- | --- |
| `1ae7153ed25d.dll` | `A4 E0 8D 9B 7E 4B 96 DD` |
| `9bd81f525ace.dll` | `79 D5 3D 8B 5F 13 AB 6D` |

## 结论

两个 DLL 是**同一套加密插件框架针对不同游戏编译的配置变体**。框架代码完全复用，所有差异均为每游戏独立配置的加密材料：密码置换参数表、游戏唯一标识字符串（UNIQUE）、RSA 公钥（PUBKEY），以及档案名哈希种子。
