# 关键常量

[返回 Hxv4 加密体系总览](../Hxv4Ripped.md) | 上一篇：[Stream Filter 运行时读路径](08-runtime-read-path.md) | 下一篇：[验证结果](10-validation-results.md)


```python
# XChaCha20-Poly1305 密钥 (从 FilterManager block 0 恢复)
HXV4_KEY = bytes.fromhex(
    "e4dc1d99d9d9fb1ae5f7529ee70f841b"
    "fadb13d12f4d22b99170d6cc6a62bc54"
)

# XChaCha20-Poly1305 Nonces (从 FilterManager block 1/2 恢复)
HXV4_NONCES = {
    0: bytes.fromhex("d99230e02623f4a0c4f2857682b4de6d"
                     "fefe820b57060e50b7cc2580db04d993")[:24],
    1: bytes.fromhex("b96f89630850dd23a13810c7718ad003"
                     "936d1d4a3ae008909be93eee7ac8fc3e")[:24],
}
```

---

> 第九节给出了具体的 hex 常量。下一节的验证结果证明以上全链路分析与运行时行为完全一致。

