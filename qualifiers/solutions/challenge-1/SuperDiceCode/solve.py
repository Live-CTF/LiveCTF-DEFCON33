#!/usr/bin/env python3

from pwn import *
import angr
import cle
import claripy
import io


def solve(binary):
    loader = cle.Loader(io.BytesIO(binary), auto_load_libs=False)
    proj = angr.Project(loader, auto_load_libs=False)
    input_len = 16
    input_chars = [claripy.BVS(f'byte_{i}', 8) for i in range(input_len)]
    input_buffer = claripy.Concat(*input_chars)
    base = proj.loader.main_object.min_addr
    check = proj.factory.callable(base + 0x131a, prototype="int x(char*)")
    buf = angr.PointerWrapper(claripy.Concat(*input_chars), buffer=True)
    s = claripy.Solver()
    s.add(check(buf) == 1)

    return bytes(s.batch_eval(input_chars, 1)[0])


HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

r = remote(HOST, int(PORT))
while True:
    try:
        r.recvuntil(b"Crackme: ")
    except:
        break
    crackme = r.recvline().strip().decode()
    crackme = b64d(crackme)
    r.sendlineafter(b"Password: ", solve(crackme))
print(r.recvall())
