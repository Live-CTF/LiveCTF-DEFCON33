#!/usr/bin/env python3

import nclib
import sys
import os
import base64
import angr
import claripy

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

inp = claripy.BVS('inp', 8*16)

class FoundException(Exception):
    pass

class getline(angr.SimProcedure):
    def run(self, lineptr, n, stream):
        self.state.mem[lineptr].long = 0x12340000
        self.state.mem[n].long = 17
        self.state.memory.store(0x12340000, inp)
        self.state.memory.store(0x12340010, b'\n\0')
        return 17

class strcspn(angr.SimProcedure):
    def run(self, a, b):
        return 16

class strlen(angr.SimProcedure):
    def run(self, a):
        return 16

class puts(angr.SimProcedure):
    def run(self, a):
        if self.state.mem[a].string.concrete == b'Yes':
            found = self.state.solver.eval_one(inp, cast_to=bytes)
            raise FoundException(found)

def solve_one(filepath):
    p = angr.Project(filepath, load_options={"auto_load_libs": False})

    s = p.factory.call_state(addr=p.loader.find_symbol("main").rebased_addr)
    s.options.add(angr.options.UNICORN)
    s.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
    s.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    s.options.add(angr.options.UNICORN_TRACK_BBL_ADDRS)
    s.unicorn.max_steps = 10000

    simgr = p.factory.simgr(s)
    simgr.explore()

    result = bytearray()
    for addr in simgr.deadended[0].history.bbl_addrs:
        sym = p.loader.find_symbol(addr)
        if sym is not None and sym.name.startswith("func_"):
            removed = sym.name[5:]
            chars = set(removed)
            if len(chars) == 1:
                result.append(ord(next(iter(chars))))
    r = result.decode()
    assert r.startswith('PASS')
    return f"PASS{{{r[4:]}}}"

def realmain():
    nc = nclib.Netcat(HOST, int(PORT), verbose=False, log_yield=True)
    nc.recvuntil('Round ')
    rounds = int(nc.recvline().strip().split(b'/')[-1])

    for i in range(rounds):
        nc.recvuntil("Watchme: ")
        crackme = nc.recvline()
        nc.recvuntil("Password: ")
        decoded = base64.b64decode(crackme)
        print(decoded[:4].hex())
        open('sample', 'wb').write(decoded)
        solved = solve_one('sample')
        print(solved)
        nc.sendline(solved)
        result = nc.recvline()
        print(result)
        assert result == b'Correct!\n'
    nc.recvuntil('flag: ')
    print(nc.recvline())
    #print(nc.recvall())

def testmain():
    for arg in sys.argv[2:]:
        print(solve_one(arg))

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == "--rhelmot-test":
        testmain()
    else:
        realmain()

