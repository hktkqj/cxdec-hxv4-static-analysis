import json

with open('data/manager_ready.drip_program.json', 'rb') as f:
    d1 = json.loads(f.read())
with open('data/bootstrap.drip_program.json', 'rb') as f:
    d2 = json.loads(f.read())

c1 = d1['context_u32']
c2 = d2['context_u32']
print(f'context len: {len(c1)} vs {len(c2)}')
diffs = sum(1 for a, b in zip(c1, c2) if a != b)
print(f'context diffs: {diffs}/{len(c1)}')

lanes1 = d1['lanes']
lanes2 = d2['lanes']
print(f'lanes count: {len(lanes1)} vs {len(lanes2)}')
lane_diffs = 0
for i, (l1, l2) in enumerate(zip(lanes1, lanes2)):
    if l1['records'] != l2['records']:
        lane_diffs += 1
print(f'lane record diffs: {lane_diffs}')
print(f'holder_words: {d1["holder_words"]} vs {d2["holder_words"]}')
