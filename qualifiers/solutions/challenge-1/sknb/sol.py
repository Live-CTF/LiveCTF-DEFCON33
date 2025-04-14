from pwn import *
from z3 import *
import base64 
import warnings
warnings.filterwarnings("ignore")

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

#context.log_level = 'debug'
context.arch = 'amd64'
#context.terminal = ['tmux', 'splitw', '-h']

p = remote(HOST, PORT)
tag = b'\x48\x87\xe3\xc3'

def getOp(t):
    offset = 0x3010
    ops = []
    while True:
        addr = u64(t[offset:offset+8])
        #print(hex(addr))
        #final gadget will be pop rbp, don't need it
        nextGadget = u64(t[offset+8:offset+0x10])
        if nextGadget > 0x10000:
            break
        #Extract up until xchg rbx, rsp; ret;
        ss = t[addr:t.find(tag, addr)]
        ops.append(disasm(ss))
        offset += 8
    return ops


for _ in range(20):
    p.recvuntil('Crackme: ')
    data = p.recvline().strip()
    t = base64.b64decode(data)

    gadgets = getOp(t)

    solver = Solver()
    solver.reset()
    vals = [BitVec(f'v{i}_{_}', 16) for i in range(0x10)]
    #Assert is ASCII
    for i in range(0x10):
        solver.add(vals[i] >= 48)
        solver.add(vals[i] <= 122)

    rax = 0
    rdx = 0
    eax = 0
    prevOp = '?'
    for gadget in gadgets:
        gadget = gadget.split('\n')
        for g in gadget:
            #print(g)
            g = g.split()
            if len(g) < 5:
                continue
            if g[-3] == 'add':
                if g[-1] == 'edx':
                    prevOp = '+'
                else:
                    eax = int(g[-1], 16)
            elif g[-3] == 'xor':
                prevOp = '^'
            elif g[-3] == 'sub':
                prevOp = '-'
            elif g[-3] == 'imul':
                prevOp = '*'
            elif g[-5] == 'movzx':
                if g[-4] == 'edx,':
                    rdx = eax
                elif g[-4] == 'eax,':
                    rax = eax
            elif g[-3] == 'movsx':
                if g[-2] == 'edx,':
                    rdx = eax
            elif g[-3] == 'cmp':
                print(g)
                value = int(g[-1], 16)
                if prevOp == '+':
                    solver.add(vals[rax] + vals[rdx] == value)
                elif prevOp == '-':
                    solver.add(vals[rdx] - vals[rax] == value)
                elif prevOp == '*':
                    solver.add(((vals[rdx] * vals[rax]) % 0x10000) == value)
                elif prevOp == '^':
                    solver.add(vals[rax] ^ vals[rdx] == value)
                else:
                    print("what other operation???")
            elif g[-2] == 'sete' or g[-5] == 'mov':
                eax = 0
                rax = 0
            else:
                pass
                #print("NO MATCH: ")
    print(solver.check())
    modl = solver.model()
    password = ''
    for i in range(0x10):
        password += chr(modl[vals[i]].as_long())
    print("PASSWORD: ", password)

    p.sendline(password)

print(p.clean().decode())
