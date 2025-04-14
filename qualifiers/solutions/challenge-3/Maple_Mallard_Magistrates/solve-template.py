#!/usr/bin/env python3

from pwn import *
import base64

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337
io = remote(HOST, int(PORT))

context.arch = "amd64"

import re

pattern = r"^func_([A-Za-z0-9])\1{9}$"

fnccll = re.compile(pattern)

for i in range(10):
    io.recvuntil(b"Watchme: ")
    b = io.recvline()
    bn = base64.b64decode(b)
    pth = f"./tmp_{i}"
    with open(pth, "wb") as f:
        f.write(bn)

    os.popen(f"chmod +x ./tmp_{i}")
    f = ""
    for i in os.popen(f"gdb -batch -x this.gdb ./tmp_{i}").read().split("\n"):
        #print(i)
        if " FLAG: " in i:
            f = i.split("FLAG: ")[1]
    print(f)
    assert "PASS" in f
    flag = "PASS{" + f[4:] + "}"
    io.sendline(flag.encode())

log.info(io.recvall())
io.interactive()

