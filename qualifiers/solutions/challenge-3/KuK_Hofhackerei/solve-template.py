#!/usr/bin/env python3
from pwn import *
from qiling import Qiling


#context.log_level = 'debug'


def hook_fun(ql):
    global password
    global syms
    password += syms[ql.arch.regs.rip]


def solve(file: str):
    binfile = ELF(file)
    binfile.address = 0x555555554000

    global syms
    global password
    syms = dict()
    password = ''

    for sym in binfile.symbols:
        if sym.startswith('func_') and len(set(sym.split('_')[1])) == 1:
            syms[binfile.symbols[sym]] = sym[-1]

    ql = Qiling([file], rootfs='/')

    for sym in syms:
        ql.hook_address(hook_fun, sym)

    ql.run()
    return password[4:]

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

r = remote(HOST, int(PORT))
#r = process('./challenge', env={'FLAG': 'test'})
#r.interactive()

r.recvuntil('Round ')
r.recvuntil('/')
rounds = int(r.recvuntil('\n')[:-1])

for i in range(rounds):
    r.recvuntil('Watchme: ')
    elf_bytes = b64d(r.recvuntil('Password: ')[:-10])
    path = f'/tmp/challenge_{i}'
    with open(path, 'wb') as f:
        f.write(elf_bytes)
    passw = solve(path)
    s = 'PASS{' + passw + '}'
    r.sendline(s.encode())

print(r.recvall(timeout=3))
r.close()
