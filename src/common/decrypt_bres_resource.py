"""
decrypt_bres_resource.py
========================
离线解密 SabbatOfTheWitch（sanoba witch）PE 资源中的
bres:// 加密资源（BOOTSTRAP / STARTUP.TJS / PLUGIN）。

算法还原（基于 IDA Pro 逆向）
-------------------------------
1. SHA3-384(UTF-16LE(path_key) + salt_8192bytes)  => digest[48]
2. 构造 ChaCha8 初始状态 T[16]:
     T[0..3]  = "expand 32-byte k"  (标准 ChaCha 常量)
     T[4..11] = digest[0:32]  (密钥，8 个 LE-uint32)
     T[12]    = LE_uint32(digest[40:44]) XOR block_number  (计数器低位)
     T[13]    = LE_uint32(digest[44:48])                   (计数器高位)
     T[14]    = LE_uint32(digest[32:36])                   (nonce 低)
     T[15]    = LE_uint32(digest[36:40])                   (nonce 高)
3. keystream = ChaCha8(T)，每 64 字节一块，block_number = file_offset // 64
4. plaintext = ciphertext XOR keystream

关键参数（来自 SabbatOfTheWitch.exe）:
  path_key = "9kpzeqme93usra66re54h69ymi"
  salt      = 0x2000 bytes @ unk_F44A00  (保存在 salt_F44A00.bin)
  bres 根路径 = "bres://./9kpzeqme93usra66re54h69ymi/"  (TEXT resource ID=127)
  path_key  = folder name only, without bres://./ prefix or slash suffix
"""

import struct
import hashlib
import sys
import os


# ── ChaCha8 实现 ──────────────────────────────────────────────────────────────

CHACHA_CONST = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]


def _rotl32(v: int, n: int) -> int:
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


def chacha8_block(state: list) -> bytes:
    """
    标准 ChaCha8 块函数。
    输入：16 个 uint32 初始状态。
    输出：64 字节 keystream。
    """
    s = list(state)

    def qr(a, b, c, d):
        s[a] = (s[a] + s[b]) & 0xFFFFFFFF
        s[d] ^= s[a]
        s[d] = _rotl32(s[d], 16)
        s[c] = (s[c] + s[d]) & 0xFFFFFFFF
        s[b] ^= s[c]
        s[b] = _rotl32(s[b], 12)
        s[a] = (s[a] + s[b]) & 0xFFFFFFFF
        s[d] ^= s[a]
        s[d] = _rotl32(s[d], 8)
        s[c] = (s[c] + s[d]) & 0xFFFFFFFF
        s[b] ^= s[c]
        s[b] = _rotl32(s[b], 7)

    for _ in range(4):          # 4 double rounds = 8 rounds
        # column rounds
        qr(0, 4, 8, 12)
        qr(1, 5, 9, 13)
        qr(2, 6, 10, 14)
        qr(3, 7, 11, 15)
        # diagonal rounds
        qr(0, 5, 10, 15)
        qr(1, 6, 11, 12)
        qr(2, 7, 8, 13)
        qr(3, 4, 9, 14)

    out = [(s[i] + state[i]) & 0xFFFFFFFF for i in range(16)]
    return struct.pack('<16I', *out)


# ── 密钥派生 ─────────────────────────────────────────────────────────────────

def derive_chacha_params(path_key: str, salt: bytes):
    """
    从 bres:// 路径分量和 0x2000 salt 派生 ChaCha8 参数。

    返回:
      key_words   : [uint32 × 8]  digest[0:32]
      nonce_words : [uint32 × 2]  digest[32:40]
      ctr_base    : uint32        digest[40:44]  (与 block_number XOR)
      ctr_high    : uint32        digest[44:48]
    """
    h = hashlib.sha3_384()
    h.update(path_key.encode('utf-16-le'))
    h.update(salt)
    digest = h.digest()                          # 48 bytes

    key_words   = list(struct.unpack_from('<8I', digest, 0))
    nonce_words = list(struct.unpack_from('<2I', digest, 32))
    ctr_base    = struct.unpack_from('<I', digest, 40)[0]
    ctr_high    = struct.unpack_from('<I', digest, 44)[0]

    return key_words, nonce_words, ctr_base, ctr_high


# ── 解密核心 ─────────────────────────────────────────────────────────────────

def decrypt_bres(ciphertext: bytes, path_key: str, salt: bytes) -> bytes:
    """
    解密一个 bres:// 资源块。

    path_key : bres://./<path_key>/<resource> 中的 folder 名
               对 STARTUP.TJS = "9kpzeqme93usra66re54h69ymi"
    salt     : 0x2000 字节 (从 unk_F44A00 提取)
    """
    key_words, nonce_words, ctr_base, ctr_high = derive_chacha_params(path_key, salt)

    plaintext = bytearray()
    total_blocks = (len(ciphertext) + 63) // 64

    for bn in range(total_blocks):
        # 计数器低位：SHA3_word_40 XOR 块号
        ctr_low = (ctr_base ^ bn) & 0xFFFFFFFF

        state = (
            CHACHA_CONST
            + key_words
            + [ctr_low, ctr_high]
            + nonce_words
        )

        keystream = chacha8_block(state)

        offset = bn * 64
        chunk = ciphertext[offset:offset + 64]
        for i, byte in enumerate(chunk):
            plaintext.append(byte ^ keystream[i])

    return bytes(plaintext)


# ── PE 资源提取（可选） ───────────────────────────────────────────────────────

def extract_pe_rcdata(exe_path: str, resource_name: str) -> bytes:
    """
    从 PE 可执行文件提取指定 RCDATA 资源（名字匹配，不区分大小写）。
    依赖 pefile 库。
    """
    try:
        import pefile
    except ImportError:
        raise ImportError("需要安装 pefile: pip install pefile")

    pe = pefile.PE(exe_path)
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if entry.id == 10:                      # RT_RCDATA = 10
            for subentry in entry.directory.entries:
                name = (subentry.name.string.decode('utf-16-le')
                        if subentry.name else str(subentry.id))
                if name.upper() == resource_name.upper():
                    data_entry = subentry.directory.entries[0]
                    rva = data_entry.data.struct.OffsetToData
                    size = data_entry.data.struct.Size
                    return pe.get_data(rva, size)
    raise KeyError(f"未找到 RCDATA 资源: {resource_name}")


# ── CLI 入口 ─────────────────────────────────────────────────────────────────

def main():
    base = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    salt_path = os.path.join(base, 'salt_F44A00.bin')

    if not os.path.exists(salt_path):
        print(f"[!] salt 文件不存在: {salt_path}")
        print("    请先运行 IDA 脚本提取 unk_F44A00 (0x2000 bytes)。")
        sys.exit(1)

    with open(salt_path, 'rb') as f:
        salt = f.read()
    assert len(salt) == 0x2000, f"salt 长度应为 8192，实际 {len(salt)}"

    PATH_KEY = '9kpzeqme93usra66re54h69ymi'

    # ── 模式1：从命令行传入密文文件 ──────────────────────────────────────────
    if len(sys.argv) >= 3 and sys.argv[1] == '--file':
        cipher_path = sys.argv[2]
        out_path = sys.argv[3] if len(sys.argv) >= 4 else cipher_path + '.dec'
        with open(cipher_path, 'rb') as f:
            ciphertext = f.read()
        plaintext = decrypt_bres(ciphertext, PATH_KEY, salt)
        with open(out_path, 'wb') as f:
            f.write(plaintext)
        print(f"[+] 解密完成: {out_path} ({len(plaintext)} bytes)")
        print(f"    前 32 bytes: {plaintext[:32].hex()}")
        # 尝试检测文件类型
        if plaintext[:3] == b'TJS':
            print("    [文件类型] TJS 脚本")
        elif plaintext[:2] in (b'MZ', b'PK'):
            print(f"    [文件类型] {plaintext[:2]}")
        else:
            # 打印可读 ASCII
            preview = ''.join(chr(b) if 32 <= b < 127 else '.' for b in plaintext[:64])
            print(f"    [预览] {preview}")
        return

    # ── 模式2：从 exe 提取并解密所有 RCDATA ─────────────────────────────────
    exe_candidates = [
        r'F:\SteamLibrary\steamapps\common\SabbatOfTheWitch\SabbatOfTheWitch.exe',
        os.path.join(base, 'SabbatOfTheWitch.exe'),
    ]
    exe_path = None
    for p in exe_candidates:
        if os.path.exists(p):
            exe_path = p
            break

    if exe_path is None:
        print("[!] 找不到 SabbatOfTheWitch.exe，请用 --file 模式手动指定密文文件。")
        print(f"    用法: python {sys.argv[0]} --file <密文.bin> [输出文件]")
        sys.exit(1)

    for name in ('BOOTSTRAP', 'STARTUP.TJS', 'PLUGIN'):
        try:
            ct = extract_pe_rcdata(exe_path, name)
        except Exception as e:
            print(f"[-] {name}: {e}")
            continue

        pt = decrypt_bres(ct, PATH_KEY, salt)
        out = os.path.join(base, f'{name}.dec')
        with open(out, 'wb') as f:
            f.write(pt)

        preview = ''.join(chr(b) if 32 <= b < 127 else '.' for b in pt[:64])
        print(f"[+] {name}: {len(ct)} bytes -> {out}")
        print(f"    前 32 bytes hex: {pt[:32].hex()}")
        print(f"    可读预览: {preview}")


if __name__ == '__main__':
    main()
