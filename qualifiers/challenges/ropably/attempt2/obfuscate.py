#!/usr/bin/env python3

import sys
import random
import re

function_prologue = '''
        leaq chain(%rip), %rbx
        xchg %rsp, %rbx
        ret
'''.strip()

chain_prologue = '''
    .data
    .align 8
chain:
'''.strip()

chunk_prologue = '''
rop_chunk_%d:
        xchg %%rsp, %%rbx
'''.strip()

chunk_epilogue = '''
        xchg %rsp, %rbx
        ret
'''.strip()

JUMPS = [
    'jmp', 'jne', 'je'
]

# Before function code
for line in sys.stdin:
    line = line.rstrip()
    print(line)
    if 'checker:' in line:
        break

# Collect function code
checker_lines = []
for line in sys.stdin:
    line = line.rstrip()

    if 'checker, .-checker' in line:
        print(line)
        break
    else:
        checker_lines.append(line)

print(function_prologue)

# identify basic blocks
basic_blocks = []
basic_block = []
for line in checker_lines:
    if re.match(r'\.[a-zA-Z0-9]+:' , line.strip().split()[0]):
        basic_blocks.append(basic_block)
        basic_block = []
    basic_block.append(line)
    if line.strip().split()[0] in JUMPS:
        basic_blocks.append(basic_block)
        basic_block = []
basic_blocks.append(basic_block)

basic_blocks = [x for x in basic_blocks if len(x) > 0]

#print(chunks)

# sub-divide basic blocks
chunks = []
for basic_block in basic_blocks:
    while len(basic_block) > 0:
        chunk_len = random.randint(2, 6)
        chunk, basic_block = basic_block[:chunk_len], basic_block[chunk_len:]
        chunks.append((len(chunks), chunk))

random.shuffle(chunks)

# Print chunks
for chunk_idx, chunk in chunks:
    print(chunk_prologue % chunk_idx)
    for line in chunk:
        print(line)
    print(chunk_epilogue)

# After function code
for line in sys.stdin:
    line = line.rstrip()
    print(line)

# Print chunks pointer array
print(chain_prologue)
chunks_str = ', '.join(f'rop_chunk_{i}' for i in range(len(chunks)))
print(f'        .quad {chunks_str}')
