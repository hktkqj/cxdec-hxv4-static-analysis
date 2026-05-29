"""Quick disassembler for bootstrap_dll.dll sub_10015630."""
import pefile
import capstone

DLL_PATH = 'bootstrap_dll.dll'
FUNC_RVA = 0x141c0
MAX_INSNS = 200

pe = pefile.PE(DLL_PATH, fast_load=True)
data = bytes(pe.__data__)

offset = pe.get_offset_from_rva(FUNC_RVA)
code = data[offset:offset + MAX_INSNS * 15]

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

base = 0x10000000 + FUNC_RVA
count = 0
for insn in md.disasm(code, base):
    print(f'  {insn.address:#010x}:  {insn.mnemonic:<10s} {insn.op_str}')
    count += 1
    if count >= MAX_INSNS:
        break

pe.close()
