#!/usr/bin/env python3

from capstone import *
from pwn import *
from triton import TritonContext, ARCH, Instruction, MemoryAccess

def solve_challenge(path):
    ctx = TritonContext(ARCH.X86_64)
    ctx.setConcreteRegisterValue(ctx.registers.rbx, 0x10000)
    ctx.setConcreteRegisterValue(ctx.registers.rsp, 0x20000)
    ctx.setConcreteRegisterValue(ctx.registers.rdi, 0x30000)

    indata = []
    v = ctx.symbolizeMemory(MemoryAccess(0x30000, 1), "rdi0")
    indata.append(v.getId())
    v = ctx.symbolizeMemory(MemoryAccess(0x30001, 1), "rdi1")
    indata.append(v.getId())
    v = ctx.symbolizeMemory(MemoryAccess(0x30002, 1), "rdi2")
    indata.append(v.getId())
    v = ctx.symbolizeMemory(MemoryAccess(0x30003, 1), "rdi3")
    indata.append(v.getId())
    v = ctx.symbolizeMemory(MemoryAccess(0x30004, 1), "rdi4")
    indata.append(v.getId())
    v = ctx.symbolizeMemory(MemoryAccess(0x30005, 1), "rdi5")
    indata.append(v.getId())
    v = ctx.symbolizeMemory(MemoryAccess(0x30006, 1), "rdi6")
    indata.append(v.getId())
    v = ctx.symbolizeMemory(MemoryAccess(0x30007, 1), "rdi7")
    indata.append(v.getId())
    v = ctx.symbolizeMemory(MemoryAccess(0x30008, 1), "rdi8")
    indata.append(v.getId())
    v = ctx.symbolizeMemory(MemoryAccess(0x30009, 1), "rdi9")
    indata.append(v.getId())
    v = ctx.symbolizeMemory(MemoryAccess(0x3000a, 1), "rdi10")
    indata.append(v.getId())
    v = ctx.symbolizeMemory(MemoryAccess(0x3000b, 1), "rdi11")
    indata.append(v.getId())
    v = ctx.symbolizeMemory(MemoryAccess(0x3000c, 1), "rdi12")
    indata.append(v.getId())
    v = ctx.symbolizeMemory(MemoryAccess(0x3000d, 1), "rdi13")
    indata.append(v.getId())
    v = ctx.symbolizeMemory(MemoryAccess(0x3000e, 1), "rdi14")
    indata.append(v.getId())
    v = ctx.symbolizeMemory(MemoryAccess(0x3000f, 1), "rdi15")
    indata.append(v.getId())

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    elf = ELF(path)
    rop_ptr = 0x4010
    while True:
        pc = u64(elf.read(rop_ptr, 8))
        rop_ptr += 8
        for insn in md.disasm(elf.read(pc, 0x100), pc):
            if insn.mnemonic == "ret":
                break
            ctx.setConcreteRegisterValue(ctx.registers.rip, insn.address)
            ctx.processing(Instruction(bytes(insn.bytes)))
        if ctx.getConcreteRegisterValue(ctx.registers.rsp) <= 0x10000:
            break
    astCtx = ctx.getAstContext()
    model = ctx.getModel(astCtx.equal(ctx.getRegisterAst(ctx.registers.rax), astCtx.bv(1, 64)))
    concrete_indata = b""
    for var_id in indata:
        concrete_indata += bytes([model[var_id].getValue()])
    return concrete_indata.decode()

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

import base64

io = remote(HOST, int(PORT))
while True:
    line = io.readline()
    if line.startswith(b"Crackme: "):
        with open("/tmp/challenge", "wb") as f:
            f.write(base64.b64decode(line[9:].strip()))
        io.sendline(solve_challenge("/tmp/challenge"))
    else:
        log.info("line: %s", line)
