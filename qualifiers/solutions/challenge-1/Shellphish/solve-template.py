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
    p = angr.Project(filepath, auto_load_libs=False)
    p.hook_symbol('getline', getline(prototype='size_t getline(char **lineptr, size_t *n, void *stream)'))
    p.hook_symbol('strlen', strlen(prototype='size_t strlen(char *data)'))
    p.hook_symbol('strcspn', strcspn(prototype='size_t strcspn(char *data, char *needle)'))
    p.hook_symbol('puts', puts(prototype='void puts(char *data)'))
    s = p.factory.entry_state()
    sm = p.factory.simgr(s)
    try:
        sm.run()
    except FoundException as e:
        return e.args[0]

def realmain():
    nc = nclib.Netcat(HOST, int(PORT), verbose=False, log_yield=True)

    for i in range(20):
        nc.recvuntil("Crackme: ")
        crackme = nc.recvline()
        nc.recvuntil("Password: ")
        decoded = base64.b64decode(crackme)
        print(decoded[:4].hex())
        open('sample', 'wb').write(decoded)
        nc.sendline(solve_one('sample'))
        assert nc.recvline() == b'Correct!\n'
    nc.recvuntil('flag: ')
    print(nc.recvline())

def testmain():
    for arg in sys.argv[2:]:
        print(solve_one(arg))

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == "--rhelmot-test":
        testmain()
    else:
        realmain()

