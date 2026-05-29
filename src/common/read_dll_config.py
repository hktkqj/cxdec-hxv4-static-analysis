import struct, sys
import pefile

TABLE_RVA = 0x80E38
ARCHIVE_SEED_RVA = 0x81758

dll_path = sys.argv[1] if len(sys.argv) > 1 else 'bootstrap_dll.dll'
pe = pefile.PE(dll_path, fast_load=True)
data = bytes(pe.__data__)

table_off = pe.get_offset_from_rva(TABLE_RVA)
print(f'Config table at file offset: {table_off:#x}')

ptr = table_off
while True:
    end = data.index(b'\x00', ptr)
    label = data[ptr:end].decode('ascii')
    if not label:
        break
    ptr = end + 1
    length = struct.unpack_from('<H', data, ptr)[0]
    ptr += 2
    value = data[ptr:ptr + length]
    ptr += length
    print(f'{label}: len={length}  hex={value.hex()}')
    try:
        text = value.decode('utf-16-le').rstrip('\x00')
        print(f'  utf16: {repr(text)}')
    except Exception:
        try:
            text = value.decode('ascii')
            print(f'  ascii: {repr(text)}')
        except Exception:
            pass

seed_off = pe.get_offset_from_rva(ARCHIVE_SEED_RVA)
seed = data[seed_off:seed_off + 8]
print(f'\nArchive seed (RVA {ARCHIVE_SEED_RVA:#x}): {seed.hex()}')
pe.close()
