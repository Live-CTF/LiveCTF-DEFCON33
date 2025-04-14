import angr
import claripy


def solve(filename):
    p = angr.Project(filename)
    state = p.factory.blank_state(addr=0x129b+0x400000)

    input_size = 0x100

    inputs = [claripy.BVS("input_%d" % i, 8) for i in range(input_size)]
    input_memory_addr = 0x600000

    for i in range(len(inputs)):
        state.memory.store(input_memory_addr+i, inputs[i])

    state.regs.rax = input_memory_addr

    simgr = p.factory.simulation_manager(state)
    simgr.explore(find=0x12A3+0x400000)

    state = simgr.found[0]
    state.add_constraints(state.regs.rax == 1)

    flag = b""
    for i in inputs:
        c = state.solver.eval(i, cast_to=bytes)
        if c == b"\x00":
            break
        flag += c

    print(flag)
    return flag



import os
from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

s = remote(HOST, PORT)

def download_challenge(i):
    s.recvuntil(b"Crackme:")
    b64con = s.recvuntil(b"Password",drop=True)
    con = base64.b64decode(b64con)
    with open(f"./samples/challenge_{i}","wb") as f:
        f.write(con)

os.system("rm -rf ./samples")
os.mkdir("./samples")
for i in range(20):

    download_challenge(i)
    flag = solve(f"./samples/challenge_{i}")
    # s.interactive()
    s.sendlineafter(b':', flag)
s.recvuntil(b"Here is the flag:")
flag = s.recvuntil(b"\n").strip()
print(flag)
# s.interactive()
