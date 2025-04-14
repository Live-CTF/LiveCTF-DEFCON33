#!/usr/bin/env python3

from pwn import *
import angr
import base64
import claripy

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))
#io = process(['python3', 'server.py'])

for i in range(20):
    io.recvuntil(b'Crackme: ',)
    raw = base64.b64decode(io.recvline())
    # open temp file
    import tempfile
    f = tempfile.NamedTemporaryFile(delete=False)
    f.write(raw)

    p = angr.Project(f.name, auto_load_libs=False)
    flag = claripy.BVS('flag', 0x10*8)
    init_st = p.factory.entry_state(stdin=flag)
    sm = p.factory.simulation_manager(init_st)

    class Strlen(angr.SimProcedure):
        def run(self):
            self.state.regs.rax = 0x10
            return 0x10
            

    p.hook_symbol('strlen', Strlen())

    class Getline(angr.SimProcedure):
        def run(self):
            self.state.memory.store(0x313377, flag)
            self.state.memory.store(self.state.regs.rdi, 0x313377, endness='Iend_LE')
            self.state.regs.rax = 0
            

    p.hook_symbol('getline', Getline())

    def find(st):
        return b'Yes' in st.posix.dumps(1)    

    def avoid(st):
        return b'No' in st.posix.dumps(1)
    sm.explore(find=find, avoid=avoid)
    st = sm.found[0]
    io.sendline(st.solver.eval(flag, bytes).decode())
    print(i)
print(io.recvall())