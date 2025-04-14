#!/usr/bin/env python3

from pwn import *
from base64 import b64decode
import angr
import claripy

import logging
logging.getLogger('angr').setLevel('CRITICAL')
logging.getLogger('pwnlib').setLevel(logging.WARNING)
logging.disable(logging.DEBUG)

context.arch='amd64'
context.log_level='error'

def solvei(BIN):
    F=open('challenge','wb')
    F.write(BIN)
    F.close()
    exe=ELF(f"./challenge")

    funcs=exe.read(0x4010,0x200)
    funcs=[u64(funcs[i:i+8]) for i in range(0,len(funcs),8)]

    # print([hex(a) for a in funcs])
    # exit()
    SC=b""
    W=False
    for a in funcs:
      if a==0:
        W=True
        break
      E=exe.read(a,0x100)
      
      D=disasm(E)
      Ln=D.split("\n")
      
      for a in Ln:
        if 'ret' in a:
          Num=a.split(":")[0]
          Num=int(Num,16)
          break
      #  print(Num)
      E=E[:Num]
      
      SC+=E
      #  print(disasm(E))
      #  print("="*40)
      
    L=len(SC)
    SC+=b'I\x89\xc7'
    #  print(disasm(SC))

    addr = 0x400000

    input_size = 0x10
    input_addr = 0x500000

    # Create symbolic bytes
    # sym_input = claripy.BVS("sym_input", input_size * 8)
    sym_input = [claripy.BVS(f"sym_input_{i}", 8) for i in range(input_size)]

    proj = angr.load_shellcode(SC, arch='amd64', load_address=addr)

    state = proj.factory.blank_state(addr=addr)

    # add constraints
    for i in range(input_size):
        state.solver.add(sym_input[i] >= 0x20)
        state.solver.add(sym_input[i] <= 0x7f)

    state.memory.store(input_addr, claripy.Concat(*sym_input))
    state.regs.rdi = input_addr
    state.regs.rax = input_addr
    state.regs.rcx = 0
    state.regs.rsi = 1
    state.regs.r15=0

    simgr = proj.factory.simgr(state)

    simgr.explore(find=lambda s: s.solver.satisfiable(extra_constraints=[s.regs.r15==1]))

    if simgr.found:
      state = simgr.found[0]
      
      concrete_input = state.solver.eval(claripy.Concat(*sym_input), cast_to=bytes)
    #   print("Symbolic memory (concretized):", concrete_input)
    #   print(state.regs.rax)
      return concrete_input

  
  



  



HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))

sols = []
for i in range(20):
  io.recvuntil(b"Crackme: ")
  B=b64decode(io.recvline())
  
  sol=solvei(B)
  sols.append(sol)
  
  
  io.sendline(sol)

print(sols)
io.recvuntil(b"flag: ")
flag = io.recvline().strip()
print(flag)
