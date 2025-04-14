#!/usr/bin/env python3

from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))
# io = process('./challenge')
inp = """
1
1
400000001
400000001
402218
408286
1
402216
98273
1
1
468764
493943
434104
436488
403675
434104
434109
401917
0
"""
for l in inp.split('\n'):
    if not l.strip():
        continue
    # print(l)
    io.sendline(l.encode())
    io.recv(timeout=0.1)

io.sendline(b'./submitter')
print(io.recv())
