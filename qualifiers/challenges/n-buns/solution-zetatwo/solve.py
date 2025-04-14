#!/usr/bin/env python3

import lief
from qiling import Qiling
from qiling.const import QL_VERBOSE
from capstone import Cs

# from qiling.arch.models import X86_CPU_MODEL
from unicorn.x86_const import UC_X86_INS_CPUID
from unicorn.unicorn_const import UC_HOOK_INSN

# Fix from: https://github.com/qilingframework/qiling/issues/1201#issuecomment-2424259376
# CPUID leafs description : https://en.wikipedia.org/wiki/CPUID
# ISA level distribution : https://sources.debian.org/src/glibc/2.36-9%2Bdeb12u7/sysdeps/x86/get-isa-level.h/
def hook_cpuid(uc, ql):
    leaf = ql.arch.regs.eax
    res = None
    if leaf == 0x0:  # Amount of leafs
        res = [0x10, 0x68747541, 0x444D4163, 0x69746E65]
    elif leaf == 0x1:  # Base features (removed XSAVE and OSXSAVE among others)
        res = [0xA20F12, 0x030C0800, 0x72F8320B, 0x178BFBFF]
    elif leaf == 0x7:  # Extended features
        param = ql.arch.regs.ecx
        if param == 0x0:
            res = [0x0, 0x219C97A9, 0x40069C, 0x10]
        elif param == 0x1:
            res = [0x0, 0x0, 0x0, 0x0]
    elif leaf == 0xD:  # XSAVE features
        res = [0xF, 0x358, 0x1800, 0]
    elif leaf == 0x80000000:
        res = [0x80000023, 0x68747541, 0x444D4163, 0x69746E65]
    elif leaf == 0x80000001:
        res = [0x00A20F12, 0x20000000, 0x75C237FF, 0x2FD3FBFF]
    elif leaf == 0x80000005:
        res = [0xFF40FF40, 0xFF40FF40, 0x20080140, 0x20080140]
    elif leaf == 0x80000007:
        res = [0x00000000, 0x0000003B, 0x00000000, 0x00006799]
    elif leaf == 0x80000008:
        res = [0x00003030, 0x111EF657, 0x0000400B, 0x00010000]
    elif leaf == 0x8000001D:
        param = ql.arch.regs.ecx
        if param == 0:
            res = [0x00004121, 0x01C0003F, 0x0000003F, 0x00000000]
        elif param == 1:
            res = [0x00004122, 0x01C0003F, 0x0000003F, 0x00000000]
        elif param == 2:
            res = [0x00004143, 0x01C0003F, 0x000003FF, 0x00000002]
        elif param == 3:
            res = [0x0002C163, 0x03C0003F, 0x00007FFF, 0x00000001]
    if res is not None:
        ql.arch.regs.eax, ql.arch.regs.ebx, ql.arch.regs.ecx, ql.arch.regs.edx = res
    return res is not None


def tracer(ql: Qiling, address: int, size: int, userdata) -> None:
    elf, base_address, function_names, password = userdata


    if address < base_address or address > (base_address + elf.virtual_size):
        return

    buf = ql.mem.read(address, size)
    insn = next(ql.arch.disassembler.disasm(buf, address))
    if insn.mnemonic != "endbr64":
        return

    offset = address - base_address
    binja_offset = offset + 0x400000
    function_name = function_names.get(offset, "???")

    if not function_name.startswith("func_"):
        return
    c = set(function_name[5:])
    if len(c) != 1:
        return

    ql.log.info("Offset: %#x, name: %s", binja_offset, function_name)
    password.append(c.pop())


elf_path = "./challenge_0"
elf = lief.ELF.parse(elf_path)

function_names = {}
for sym in elf.exported_symbols:
    function_names[sym.value] = sym.demangled_name

ql = Qiling([elf_path], rootfs="/")
ql.verbose = QL_VERBOSE.DISABLED
ba = ql.loader.images[0].base
ql.log.info("%#x", ba)
ql.uc.hook_add(UC_HOOK_INSN, hook_cpuid, ql, 1, 0, UC_X86_INS_CPUID)
password_chars = []
ql.hook_code(tracer, user_data=(elf, ba, function_names, password_chars))
ql.run()

password = "".join(password_chars)
print(f"Password: {password}")
