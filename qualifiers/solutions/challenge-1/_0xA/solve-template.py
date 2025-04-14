#!/usr/bin/env python3

from pwn import *
from base64 import b64decode
import angr
import claripy

def solve_one(fp):
    project = angr.Project(fp, auto_load_libs=False)
    base = project.loader.main_object.image_base_delta
    
    input_size = 17
    input_str = claripy.BVS("input", input_size * 8)  # 每个字节8位
    
    initial_state = project.factory.entry_state(
        stdin=input_str,
        add_options={angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY}
    )
    for i in range(16):
        byte = input_str.get_byte(i)
        initial_state.solver.add(byte != 0x00)
        initial_state.solver.add(byte != 0x0A)
    # initial_state.solver.add(input_str.get_byte(16) == 0xA)
    initial_state.solver.add(input_str.get_byte(16) == 0)
    
    def hook_getline(state: angr.SimState):
        ptr = 0x300000
        state.memory.map_region(ptr, 0x1000, 7)
        state.memory.store(state.regs.rdi, int.to_bytes(ptr, 8, "little"))
        state.memory.store(ptr, input_str)
        state.memory.store(state.regs.rsi, int.to_bytes(17, 8, "little"))
        state.regs.rax = input_size

        ret_addr = state.solver.eval(state.memory.load(state.regs.rsp, 8), cast_to=bytes)
        ret_addr = int.from_bytes(ret_addr, "little")
        state.regs.rsp += 8
        state.regs.rip = ret_addr
        # print(hex(ret_addr))
    
    project.hook_symbol(base + 0x10f0, hook_getline)
    
    # def hook_strlen(state: angr.SimState):
    #     print("hook_strlen")
    #     strlen_arg0 = state.regs.rdi
    #     print(f"{strlen_arg0 = }")
    #     pointee = state.memory.load(strlen_arg0, 17)
    #     print(f"{pointee = }")
    
    # project.hook(base + 0x10c0, hook_strlen)
    
    simulation = project.factory.simgr(initial_state)
    
    def is_successful(state):
        stdout_output = state.posix.dumps(1)  # 标准输出
        return b"Yes" in stdout_output
    
    def should_abort(state):
        stdout_output = state.posix.dumps(1)  # 标准输出
        return b"No" in stdout_output
    
    simulation.explore(
        find=is_successful,
        avoid=should_abort
    )
    
    if simulation.found:
        solution_state = simulation.found[0]
        solution = solution_state.solver.eval(input_str, cast_to=bytes)
        solution = solution[:-1].decode()
        return solution
    else:
        print(simulation)
        print("No solution found")

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

NUM_ROUNDS = 20

io = remote(HOST, int(PORT))

for i in range(NUM_ROUNDS):
    io.recvuntil(b"Crackme: ")
    elf = b64decode(io.recvline())
    fn = "/tmp/chall"
    with open(fn, "wb") as f:
        f.write(elf)
    solution = solve_one(fn)
    io.recvuntil(b"Password: ")
    io.sendline(solution)

io.recvuntil(b"Congratulations! Here is the flag: ")
print(io.recvline().decode().strip())

