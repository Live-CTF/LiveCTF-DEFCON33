#!/usr/bin/env python3

from pwn import *
import struct
import re

from capstone import *
from elftools.elf.elffile import ELFFile
import struct
from z3 import *
context.log_level='critical'

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

def solve(chall):
    # def p64(val):
    #     return struct.pack("<Q", val)

    # def u64(b):
    #     return struct.unpack("<Q", b)[0]

    def get_qword(addr):
        return u64(data[addr:addr+8])

    with open(chall, "rb") as f:
        data = f.read()

    functbl = 0x3010
    addr = functbl
    chain_list = []
    ROP_CHAIN_END = 0x4010 +  0x8

    while True:
        func = get_qword(addr)

        if func > 0xffff:
            break

        chain_list.append(func)

        addr += 8
        ROP_CHAIN_END += 8


    ROP_CHAIN_START = 0x4010
    ROP_CHAIN_END = 0x41C0
    MAX_INST_PARSE = 0x1000

    elf = ELF(chall)

    chains = elf.read(ROP_CHAIN_START, ROP_CHAIN_END - ROP_CHAIN_START)
    # chain_list = struct.unpack("<" + "Q" * ((ROP_CHAIN_END - ROP_CHAIN_START) // 8), chains)

    class Disassembler:
        def __init__(self, elf_path):
            self.elf_path = elf_path
            self._load_elf()
        
        def _load_elf(self):
            with open(self.elf_path, "rb") as f:
                self.elf = ELFFile(f)
                self.text_section = self.elf.get_section_by_name('.text')
                if not self.text_section:
                    raise Exception(".text section not found")

                self.text_addr = self.text_section['sh_addr']
                self.text_offset = self.text_section['sh_offset']
                self.text_data = self.text_section.data()
            
            self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        
        def disasm_at(self, vaddr, count=3):
            if not (self.text_addr <= vaddr < self.text_addr + len(self.text_data)):
                raise Exception(f"address 0x{vaddr:x} not in .text section")
        
            offset = vaddr - self.text_addr
            code = self.text_data[offset:offset+0x200]
            result = []
            last_insn_end = vaddr
            for i, insn in enumerate(self.md.disasm(code, vaddr)):           
                result.append({"addr": insn.address, "mnemonic": insn.mnemonic, "op_str": insn.op_str})
                last_insn_end = insn.address + insn.size
                if i + 1 == count:
                    break
            return result, last_insn_end
        
    def parse_add_imm(line):
        match = re.search(r'add\s+rax\s*,\s*(-?0x[\da-fA-F]+|-?\d+)', line)
        if match:
            val = match.group(1)
            return int(val, 0)
        return 0

    def get_opcode_fixed_regs(line):
        match = re.match(r'\s*(\w+)\s+(edx|eax)\s*,\s*(edx|eax)', line, re.IGNORECASE)
        return match.group(1).lower() if match else None


    def get_imm_from_cmp(line):
        match = re.match(r'^\s*cmp\s+[a-zA-Z0-9_]+\s*,\s*(-?0x[\da-fA-F]+|-?\d+)', line)
        if match:
            return match.group(1)
        return None

    solver = Solver()
    pay = [BitVec(f'f{i}', 32) for i in range(16)]
    flag = False
    offsets = []

    for i in range(16):
        solver.add(And(pay[i] >= 0x21, pay[i] <= 0x7e))


    d = Disassembler(chall)
    for chain_addr in chain_list:
        opc_list, _ = d.disasm_at(chain_addr, MAX_INST_PARSE)
        for opc in opc_list:
            result = (opc["mnemonic"] + " " + opc["op_str"]).strip()
            # print(result)
            if result == "xchg rbx, rsp":
                continue
            elif result == "ret":
                break
            # print(result)

            if ', qword ptr [rbp - 0x18]' in result:
                flag = True
                continue

            if flag:
                offset = parse_add_imm(result)
                # print("---- index", offset)
                offsets.append(offset)
                flag = False
            
            elif 'cmp' in result:
                val = get_imm_from_cmp(result)
                # print('val', offsets)
                eval(f'solver.add((pay[{offsets[o]}] {op} pay[{offsets[o ^ 1]}]) & 0xffff == ({val} & 0xffff))')
                # print(f'solver.add((pay[{offsets[o]}] {op} pay[{offsets[o ^ 1]}]) & 0xffff == ({val} & 0xffff))')
                offsets = []
                op_ = ''

            elif 'test' in result:
                eval(f'solver.add(pay[{offsets[o]}] == pay[{offsets[o ^ 1]}])')
                offsets = []
                op_ = ''

            else:
                op_ = get_opcode_fixed_regs(result)
                # print(result, op_)
                if op_ == 'sub':
                    op = '-'
                elif op_ == 'xor':
                    op = '^'
                elif op_ == 'add':
                    op = '+'
                elif op_ == 'or':
                    op = '|'
                elif op_ == 'imul':
                    op = '*'

                if result.split()[-1] == 'eax':
                    o = 1
                else:
                    o = 0
                


    solver.check()

    m = solver.model()
    return ''.join([chr(m[x].as_long()) for x in pay])

p = remote(HOST, int(PORT))

for i in range(20):
    print(p.recvuntil(b'Crackme: '))
    res = p.recvline()
    bin = base64.b64decode(res)

    with open(f"chall_{i}", "wb") as f:
        f.write(bin)
    
    x = solve(f"chall_{i}")
    p.sendline(x)
p.recvuntil(b"flag: ")
flag = p.recvline().decode()
print(f"@@@@@@@@@@@@@@@@flag: {flag}")

p.interactive()
