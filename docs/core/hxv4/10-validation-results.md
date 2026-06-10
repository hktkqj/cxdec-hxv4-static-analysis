# 验证结果

[返回 Hxv4 加密体系总览](../Hxv4Ripped.md) | 上一篇：[关键常量](09-sample-constants.md)


全包 Adler32 验证（使用 recovered filter）：

| 包文件 | 校验条目 | 失败 | 未解析 filter |
| -------- | --------- | ------ | -------------- |
| allage.xp3 | 91 | 0 | 0 |
| bgimage.xp3 | 108 | 0 | 0 |
| bgm.xp3 | 93 | 0 | 0 |
| data.xp3 | 4,087 | 0 | 0 |
| evimage.xp3 | 319 | 0 | 0 |
| fgimage.xp3 | 1,554 | 0 | 0 |
| scn.xp3 | 26 | 0 | 0 |
| steam.xp3 | 3 | 0 | 0 |
| video.xp3 | 12 | 0 | 0 |
| voice.xp3 | 28,988 | 0 | 0 |

**全部 35,281 个条目校验通过，零失败**，证明离线 Python 实现与运行时过滤逻辑完全一致。
