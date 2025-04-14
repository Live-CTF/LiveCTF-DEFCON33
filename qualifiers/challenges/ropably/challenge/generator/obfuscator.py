#!/usr/bin/env python3

import random
import re
import hmac
from typing import TextIO, List, Tuple

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

def obfuscate(seed: bytes, infile: TextIO, outfile: TextIO) -> None:
    obfuscator_seed = hmac.digest(seed, b'obfuscator', 'sha256')
    random.seed(obfuscator_seed)

    # Before function code
    for line in infile:
        line = line.rstrip()
        outfile.write(line + '\n')
        if 'checker:' in line:
            break

    # Collect function code
    checker_lines = []
    for line in infile:
        line = line.rstrip()

        if 'checker, .-checker' in line:
            outfile.write(line + '\n')
            break
        else:
            checker_lines.append(line)

    outfile.write(function_prologue + '\n')

    # identify basic blocks
    basic_blocks = []
    basic_block: List[str] = []
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
    chunks: List[Tuple[int, List[str]]] = []
    for basic_block in basic_blocks:
        while len(basic_block) > 0:
            chunk_len = random.randint(2, 6)
            chunk, basic_block = basic_block[:chunk_len], basic_block[chunk_len:]
            chunks.append((len(chunks), chunk))

    random.shuffle(chunks)

    # Print chunks
    for chunk_idx, chunk in chunks:
        outfile.write(chunk_prologue % chunk_idx + '\n')
        for line in chunk:
            outfile.write(line + '\n')
        outfile.write(chunk_epilogue + '\n')

    # After function code
    for line in infile:
        line = line.rstrip()
        outfile.write(line + '\n')

    # Print chunks pointer array
    outfile.write(chain_prologue + '\n')
    chunks_str = ', '.join(f'rop_chunk_{i}' for i in range(len(chunks)))
    outfile.write(f'        .quad {chunks_str}' + '\n')
