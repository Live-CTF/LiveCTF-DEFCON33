from pwn import *
import angr
import claripy
import base64
from capstone import *

context.arch = 'amd64'

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337
r = remote(HOST, int(PORT))

for i in range(20):
    # bin = ELF(f"handout/samples/challenge_{i}")
    r.recvuntil(b'Crackme: ')
    binfile = base64.b64decode(r.recvline())
    with open("/tmp/bin.elf", 'wb') as f:
        f.write(binfile)
    bin = ELF("/tmp/bin.elf")
    log.info(f"Round {i}")

    addr = 0x4010
    ptr = u64(bin.read(addr, 8))

    valid = True
    bytecode = b''
    while valid:
        valid = False
        code = bin.read(ptr, 0x100)
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        for i in md.disasm(code, 0):
            if i.mnemonic == 'ret':
                code = code[:i.address]
                break
        else:
            break
        if code.endswith(b'\x48\x87\xe3'):
            addr += 8
            ptr = u64(bin.read(addr, 8))
            code = code[:-3]
            valid = True
        code = code[3:]
        bytecode += code

    p = angr.project.load_shellcode(bytecode, 'amd64')
    input_len = 0x10
    flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(input_len)]
    flag = claripy.Concat( *flag_chars + [claripy.BVV(b'\n')])

    state = p.factory.entry_state()
    for k in flag_chars:
        state.solver.add(k <= 0x7f)
        state.solver.add(k >= 0x20)

    state.memory.store(0x1338000, flag)
    state.regs.rbp = 0x0
    state.regs.rsp = 0x1338000
    state.regs.rdi = 0x1338000

    sm = p.factory.simulation_manager(state)
    sm.explore(find = len(bytecode))

    for x in sm.found:
        x.add_constraints(x.regs.rax == 1)
        data = x.solver.eval(flag)
    log.info(data.to_bytes(17))
    r.send(data.to_bytes(17))
r.sendline(b'./submitter')
flag = r.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)
