#!/usr/bin/env python3
import angr
import claripy
from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

def find_password(binary_path):
    proj = angr.Project(binary_path, auto_load_libs=False)

    input_len = 16
    flag_chars = [claripy.BVS(f'flag_{i}', 8) for i in range(input_len)]
    flag = claripy.Concat(*flag_chars)

    class StrlenHook(angr.SimProcedure):
        def run(self, s):
            return claripy.BVV(16, self.state.arch.bits)

    proj.hook_symbol("strlen", StrlenHook(), replace=True)

    class GetlineHook(angr.SimProcedure):
        def __init__(self, flag_bvs, *args, **kwargs):
            super(GetlineHook, self).__init__(*args, **kwargs)
            self.flag_bvs = flag_bvs

        def run(self, lineptr_addr, n_addr, stream_addr):
            """
            Signature: ssize_t getline(char **lineptr, size_t *n, FILE *stream);
            On return, *lineptr will point to a buffer containing the read line,
            *n will hold its size, and the function returns number of chars read.
            """
            line_len = len(self.flag_bvs)

            newline     = claripy.BVV(b"\n")
            null_byte   = claripy.BVV(b"\x00")
            symbolic_in = claripy.Concat(*self.flag_bvs, newline, null_byte)

            total_size = line_len + 2

            ptr_size = self.state.arch.bytes
            buf_ptr_bv = self.state.memory.load(lineptr_addr, ptr_size, endness=self.state.arch.memory_endness)
            
            buf_addr = self.state.solver.eval(buf_ptr_bv)

            self.state.memory.store(buf_addr, symbolic_in)

            self.state.memory.store(
                n_addr,
                claripy.BVV(total_size, self.state.arch.bits),
                endness=self.state.arch.memory_endness
            )

            return claripy.BVV(line_len + 1, self.state.arch.bits)


    proj.hook_symbol('getline', GetlineHook(flag_chars), replace=True)

    state = proj.factory.full_init_state(
        args=[binary_path],
    )

    simgr = proj.factory.simulation_manager(state)

    def is_successful(state):
        return b"Yes" in state.posix.dumps(1)

    def is_failure(state):
        return b"No" in state.posix.dumps(1)

    simgr.explore(find=is_successful, avoid=is_failure)

    if simgr.found:
        found = simgr.found[0]
        solution = found.solver.eval(flag, cast_to=bytes)
        return solution
    else:
        print("[-] No solution found")
        exit(1)


io = remote(HOST, int(PORT))

for i in range(20):
    io.recvuntil(b"Crackme: ")
    encoded = io.recvline(keepends=False)
    with open("/tmp/chal", "wb") as f:
        f.write(b64d(encoded))
    password = find_password("/tmp/chal")
    io.sendlineafter(b"Password: ", password)

io.recvuntil(b"Here is the flag: ")
flag = io.recvline(keepends=False).decode()

print(flag)
