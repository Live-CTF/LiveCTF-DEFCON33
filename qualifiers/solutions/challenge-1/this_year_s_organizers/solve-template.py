#!/bin/env python3

from pwn import *
from z3 import *
from iced_x86 import *
from glob import glob
from base64 import b64decode

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))
#context.log_level = "DEBUG"

for _ in range(20):
    io.recvuntil(b"Crackme: ")
    elf_data = b64decode(io.recvline().strip())
    
    #print("elf:", elf_data[:16])
    with open(f"/tmp/a{_}.elf", "wb") as f:
        f.write(elf_data)

    e = ELF(f"/tmp/a{_}.elf")

    def disasm(a, vma=0):
        decoder = Decoder(64, a, ip=vma)
        formatter = Formatter(FormatterSyntax.INTEL)
        return "\n".join([f"{i:}" for i in decoder])

    def i2bytes(a, vma=0):
        decoder = Decoder(64, a, ip=vma)
        formatter = Formatter(FormatterSyntax.INTEL)
        return "\n".join([a[i.ip-vma:][:i.len].hex() for i in decoder])

    main = int(disasm(e.read(e.entry, 100), vma=e.entry).split("rdi,")[1].split("\n")[0][1:-2], 16)
    check = int(disasm(e.read(main, 100), vma=main).split("call")[1].split("\n")[0].strip()[:-1], 16)
    start = int(disasm(e.read(check, 256), vma=check).split("],eax")[0].split("call")[-1].split("\n")[0].strip()[:-1], 16)
    x = disasm(e.read(start, 100), vma=start).split("\n")[0].split(",")[1]
    ropchain = int(x[1:-2], 16)

    instrs = ""
    while True:
        addr = u64(e.read(ropchain, 8))
        if not addr: break
        ropchain += 8
        instrs += "\n".join(i2bytes(e.read(addr, 1024), vma=addr).split("\nc3")[0].split("\n")[1:-1])

    code = bytes.fromhex(instrs + "c3")

    input = [BitVec(f"i{i}", 8) for i in range(64)]
    regs = {}

    R32 = ["eax", "edx", "edi", "esi", "ebx", "ecx"]
    s = Solver()

    last_accessed = 0

    for l in disasm(code).split("\n"):
        l = l.replace("dword ptr ", "")

        for r in R32:
            if f"movzx {r},byte ptr [rax]" in l:
                regs[r] = ZeroExt(8, input[ptr])
        
        for r in R32:
            if f"movsx {r},al" in l:
                #regs[r] = SignExt(24, Extract(7, 0, regs["eax"]))
                regs[r] = regs["eax"]

        if "add rax," in l:
            ptr = int(l.split(",")[-1].replace("h", ""), 16)
            last_accessed = max(last_accessed, ptr)
        elif "rax,[rbp" in l:
            ptr = 0
        elif "imul" in l:
            dst = l.split(" ")[1].split(",")[0]
            src = l.split(" ")[1].split(",")[1]
            regs[dst] = regs[dst] * regs[src]
        elif "sub" in l:
            dst = l.split(" ")[1].split(",")[0]
            src = l.split(" ")[1].split(",")[1]
            regs[dst] = regs[dst] - regs[src]
        elif "add" in l:
            dst = l.split(" ")[1].split(",")[0]
            src = l.split(" ")[1].split(",")[1]
            regs[dst] = regs[dst] + regs[src]
        elif "xor" in l:
            dst = l.split(" ")[1].split(",")[0]
            src = l.split(" ")[1].split(",")[1]
            regs[dst] = regs[dst] ^ regs[src]
        elif "cmp" in l:
            a = regs[l.split(" ")[1].split(",")[0]]
            a = regs[dst]
            b = int(l.split(" ")[1].split(",")[1].replace("h", ""), 16)
            #print(b == a)
            #print(regs)
            s.add(a == b)
        elif "test" in l:
            a = l.split(" ")[1].split(",")[0]
            b = l.split(" ")[1].split(",")[1]
            assert a==b
            #print(regs[dst] == 0)
            s.add(regs[dst] == 0)
        #print("=>", l)

    if s.check() == sat:
        password = bytes([s.model()[i].as_long() for i in input[:last_accessed+1]])
        print("Got pass: ", password)
        io.sendlineafter(b"Password: ", password)

io.recvuntil(b"Here is the")
print(io.recvline())
io.close()
