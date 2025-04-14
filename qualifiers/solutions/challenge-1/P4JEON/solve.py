from capstone import *
from pwn import *
from z3 import *

def solve(file_path):
    f = open(file_path, "rb")

    result = []
    def disasm(offset):
        f.seek(offset)
        CODE = f.read(0x100)
        count = 0
        for i in md.disasm(CODE, offset):
            address, mnemonic, op_str = i.address, i.mnemonic, i.op_str
            if count == 2:
                break
            if mnemonic == "xchg":
                count += 1
            else:
                result.append((hex(address), mnemonic, op_str))
                
            if mnemonic == "ret":
                break

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    f.seek(0x3010)
    func = f.read(8 * 200)
    func = [u64(func[i:i+8]) for i in range(0, len(func), 8)]
    l = []
    for v in func:
        if v > 0xffff:
            break
        l.append(v)

    for addr in l:
        disasm(addr)

    idx = []
    for i, line in enumerate(result):
        address, mnemonic, op_str = line
        if mnemonic == "mov" and op_str == "rax, qword ptr [rbp - 0x18]":
            idx.append(i+1)

    idx_list = []
    idx1 = None
    idx2 = None
    for i, v in enumerate(idx):
        _, mnemonic, op_str = result[v]
        
        if i != 0 and i % 2 == 0:
            idx_list.append((idx1, idx2))
            idx1, idx2 = None, None
        
        if "byte ptr [rax]" in op_str:
            if idx1 == None:
                idx1 = 0
            else:
                idx2 = 0
        else:
            if idx1 == None:
                idx1 = int(op_str.split("rax, ")[1], 16)
            else:
                idx2 = int(op_str.split("rax, ")[1], 16)
        
        if i == len(idx) - 1:
            idx_list.append((idx1, idx2))
            break

    operation = []
    for i, line in enumerate(result):
        address, mnemonic, op_str = line
        if op_str in ["eax, edx" , "edx, eax"]:
            operation.append(mnemonic.split(" ")[0])

    assert len(operation) == len(idx_list)

    const_val = []
    for i, line in enumerate(result):
        address, mnemonic, op_str = line
        if mnemonic in ["test", "cmp"]:
            if mnemonic == "test":
                const_val.append(0)
            else:
                const_val.append(int(op_str.split(", ")[1], 16))

    assert len(operation) == len(const_val)


    conditions = []
    s = [BitVec(f's_{i}', 8) for i in range(16)]
    for a, b, c in zip(operation, idx_list, const_val):
        ii, jj = b
        if a == "imul":
            conditions.append(((SignExt(8, s[ii]) * SignExt(8, s[jj])) & 0xFFFF) == c)
        elif a == "xor":
            conditions.append(((SignExt(8, s[ii]) ^ SignExt(8, s[jj])) & 0xFFFF) == c)
        elif a == "add":
            conditions.append(((SignExt(8, s[ii]) + SignExt(8, s[jj])) & 0xFFFF) == c)
        elif a == "sub":
            conditions.append(((SignExt(8, s[ii]) - SignExt(8, s[jj])) & 0xFFFF) == c)

    solver = Solver()
    solver.add(And(*conditions))

    assert solver.check() == sat

    model = solver.model()
    password = [model[byte].as_long() for byte in s]
    password = ''.join(map(chr, password))
    return password

import glob, base64
files = glob.glob("./samples/challenge_*")

# io = process("/home/livectf/challenge")
import os
HOST = os.environ.get('HOST', 'localhost')
PORT = 31337
io = remote(HOST, int(PORT))

for round in range(20):
    io.recvuntil("Crackme: ")
    enc = io.recvline()[:-1]
    file_data = base64.b64decode(enc)
    with open("temp", "wb") as f:
        f.write(file_data)
    
    password = solve("temp")
    print(password)
    io.sendlineafter("Password: ", password)

io.recvuntil("Congratulations! Here is the flag: ")
flag = io.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)
io.interactive()
