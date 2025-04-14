from pwn import *
from base64 import b64decode
import angr


#p = process("./handout/server.py",env={"FLAG": "meow"})
HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

p = remote(HOST, int(PORT))


def getPassword(data):
    addrs = []
    for i in range(0x3010,len(data),8):
        addr = int.from_bytes(data[i:i+8], byteorder='little')
        if addr > 0xFFFF:
            break
        addrs.append((addr))
    funcAddrs = []
    for addr in addrs:
        start = addr + 3
        end  = data[start:].find(bytes.fromhex("48 87 E3 C3"))
        funcAddrs.append((addr, end+start))
    #extract the bytes from the funcs and create a new function
    funcBytes = b""

    for addr, end in funcAddrs:
        start = addr + 3
        funcBytes += data[start:end]

    shellcode = funcBytes
    base = 0x0
    proj = angr.load_shellcode(shellcode,'amd64',base)
    state = proj.factory.entry_state(addr=base,add_options={angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})

    flag_sym = []
    for i in range(16):
        sym_byte = state.solver.BVS(f"flag_{len(flag_sym)}",8)
        state.memory.store(0x2000000+i,sym_byte,endness=state.arch.memory_endness)
        flag_sym.append(sym_byte)
    state.regs.rdi = 0x2000000
    simgr = proj.factory.simgr(state)
    simgr.explore(find=(len(funcBytes)-2))
    if simgr.found:
        found_state = simgr.found[0]
        flag = ""
        found_state.add_constraints(found_state.regs.rax == 0x1)

        for sym_byte in flag_sym:
            state.add_constraints(sym_byte != 0)
            flag += chr(found_state.solver.eval(sym_byte))
        return flag
    else:
        return None

for i in range(20):
    p.recvuntil("Crackme: ")
    binData = b64decode(p.recvuntil("\n"))
    p.sendlineafter("Password:",getPassword(binData))
p.recvuntil("Here is the flag: ")
flag = p.recvline()
log.info('Flag: %s', flag)
p.interactive()









