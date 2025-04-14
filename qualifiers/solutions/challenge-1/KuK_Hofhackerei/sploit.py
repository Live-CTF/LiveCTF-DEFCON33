#!/usr/bin/env python3
import angr
import claripy
import tempfile
from pwn import *


MAX_GADGET_SIZE = 64
EPILOGUE = bytes.fromhex('4887e3c3')


def solve_binary(file: str):
    binfile = ELF(file)

    full_chain = b''

    data = binfile.section('.data')
    for i in range(16, len(data), 8):
        gadget_addr = u64(data[i:i+8])

        gadget = binfile.read(gadget_addr, MAX_GADGET_SIZE)
        gadget_bytes = gadget[3:gadget.find(EPILOGUE)]
        full_chain += gadget_bytes

    p = angr.project.load_shellcode(full_chain, 'amd64', start_offset=0x0)
    bv = claripy.BVS('pass', 16 * 8)
    wrap = angr.PointerWrapper(bv, buffer=True)
    s = p.factory.call_state(0x0, wrap)
    simgr = p.factory.simgr(s)
    simgr.explore(find=len(full_chain) - 1)
    state = simgr.found[0]
    state.add_constraints(state.regs.rax == 1)
    return state.solver.eval(bv, cast_to=bytes).decode()



#dump('./handout/samples/challenge_0')

#r = process('./challenge', env={'FLAG': 'test'})

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

r = remote(HOST, int(PORT))
#r.interactive()

r.recvuntil('Round ')
r.recvuntil('/')
rounds = int(r.recvuntil('\n')[:-1])

for i in range(rounds):
    r.recvuntil('Crackme: ')
    elf_bytes = b64d(r.recvuntil('Password: ')[:-10])
    path = f'/tmp/challenge_{i}'
    with open(path, 'wb') as f:
        f.write(elf_bytes)
    passw = solve_binary(path)
    r.sendline(passw.encode())

print(r.recvall(timeout=3))
r.close()
