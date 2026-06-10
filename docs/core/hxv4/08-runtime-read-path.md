# Stream Filter 运行时读路径

[返回 Hxv4 加密体系总览](../Hxv4Ripped.md) | 上一篇：[FilterManager 运行时状态](07-filter-manager-runtime.md) | 下一篇：[关键常量](09-sample-constants.md)


随机 DLL 中的完整 stream read 调用链：

```plain
CryptoFilterStream_Read_filter_after_read  (0x10010C80)
  → wrapped IStream::Read
  → FilterImpl_Apply_vfunc(buffer, bytes_read, offset_low, offset_high)
     → FilterImpl_ApplyToReadRange  (0x1000EAE0)
        → FilterChunk_ApplyBulkXor  (0x10014B20)
        → FilterChunk_ApplyBoundaryXor  (0x1000EA20)
           → XorRangeWithRotatedDwordKey  (0x10015B80)
```

这说明内容过滤发生在**普通 IStream 读出之后**，不是在 XP3 index 解析阶段。

---

> 第八节确认了过滤逻辑在运行时的挂载点。下一节给出 Sanoba 样本中实际提取的密钥常量值。

