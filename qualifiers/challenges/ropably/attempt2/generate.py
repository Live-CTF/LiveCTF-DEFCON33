#!/usr/bin/env python3

import sys

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

import random
import string

ALPHABET = string.ascii_letters + string.digits

password = ''.join(random.choice(ALPHABET) for _ in range(16))
password_values = password.encode()
constraint_indices = list(range(len(password)))
random.shuffle(constraint_indices)

print(function_prologue)
print(f'// password = "{password}"')

for i in range(len(password)):
    idx_a = constraint_indices[(i+0) % len(constraint_indices)]
    idx_b = constraint_indices[(i+1) % len(constraint_indices)]
    a = password_values[idx_a]
    b = password_values[idx_b]

    constraint = 'result &= '
    match random.choice(['ADD', 'SUB', 'MUL', 'XOR']):
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
            print('ERROR')
            sys.exit(1)

    constraint += ';'
    print(constraint)
print(function_epilogue)
