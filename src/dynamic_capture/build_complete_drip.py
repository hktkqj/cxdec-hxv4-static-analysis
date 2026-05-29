"""Build the final production drip_program.json for Sanoba Witch XP3 extraction."""
import json

with open('data/manager_ready.drip_program.json', 'rb') as f:
    d = json.loads(f.read())

# Add correct hxv4 key/nonces (confirmed from live dump of 1ae7153ed25d.dll)
d['hxv4_key'] = 'e4dc1d99d9d9fb1ae5f7529ee70f841bfadb13d12f4d22b99170d6cc6a62bc54'
d['hxv4_nonce0'] = 'd99230e02623f4a0c4f2857682b4de6dfefe820b57060e50'
d['hxv4_nonce1'] = 'b96f89630850dd23a13810c7718ad003936d1d4a3ae008909be93eee7ac8fc3e'[:48]

with open('data/sanoba_complete.drip_program.json', 'w', encoding='utf-8') as f:
    json.dump(d, f, ensure_ascii=False, indent=2)

print('Written data/sanoba_complete.drip_program.json')
print(f'context_u32: {len(d["context_u32"])} entries')
print(f'lanes: {len(d["lanes"])}')
print(f'hxv4_key: {d["hxv4_key"]}')
print(f'hxv4_nonce0: {d["hxv4_nonce0"]}')
print(f'hxv4_nonce1: {d["hxv4_nonce1"]}')
