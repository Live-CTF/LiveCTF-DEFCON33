#!/usr/bin/env python3

import random
import string
import hmac
from typing import TextIO

function_prologue = '''
#include <stdio.h>
#include <stdlib.h>

int checker(char *input) {
    int result = 1;
'''

function_epilogue = '''
    return result;
}
'''

ALPHABET = string.ascii_letters + string.digits

def generate_checker(seed: bytes, out: TextIO) -> str:
    checker_seed = hmac.digest(seed, b'checker', 'sha256')
    random.seed(checker_seed)

    password = ''.join(random.choice(ALPHABET) for _ in range(16))
    password_values = password.encode()
    constraint_indices = list(range(len(password)))
    random.shuffle(constraint_indices)

    out.write(function_prologue + '\n')
    out.write(f'// password = "{password}"\n')

    for i in range(len(password)):
        idx_a = constraint_indices[(i+0) % len(constraint_indices)]
        idx_b = constraint_indices[(i+1) % len(constraint_indices)]
        a = password_values[idx_a]
        b = password_values[idx_b]

        constraint = 'result &= '
        match op := random.choice(['ADD', 'SUB', 'MUL', 'XOR']):
            case 'ADD':
                constant = (a + b) & 0xFFFF
                constraint += f'((input[{idx_a}] + input[{idx_b}]) & 0xFFFF) == {constant}'
            case 'SUB':
                constant = (a - b) & 0xFFFF
                constraint += f'((input[{idx_a}] - input[{idx_b}]) & 0xFFFF) == {constant}'
            case 'MUL':
                constant = (a * b) & 0xFFFF
                constraint += f'((input[{idx_a}] *  input[{idx_b}]) & 0xFFFF) == {constant}'
            case 'XOR':
                constant = (a ^ b) & 0xFFFF
                constraint += f'((input[{idx_a}] ^ input[{idx_b}]) & 0xFFFF) == {constant}'
            case _:
                raise ValueError(f'Unexpected operation: {op}')

        constraint += ';\n'
        out.write(constraint)
    out.write(function_epilogue + '\n')

    return password
