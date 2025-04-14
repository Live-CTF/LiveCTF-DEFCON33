from pwn import *
from base64 import b64decode as bd
from z3 import *

context.arch = 'amd64'
# context.log_level = 0

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

p = remote(HOST, int(PORT))
# p = process(['python3', '-u', 'server.py'], env={'FLAG':'SIBAL'})

# ROUNDS = int(p.recvline().strip().split(b'/')[-1]) 
# print(ROUNDS)

def abs(x):
    return If(x >= 0,x,-x)

for _ in range(20):
    p.recvuntil(b'Crackme: ')
    binary = bd(p.recvline().strip().decode())
    with open('elf', 'wb') as f:
        f.write(binary)
    e = ELF('elf')
    x = e.read(0x4010, 0x400)
    addrs = [u64(x[i:i+8]) for i in range(0, len(x), 8)]
    # print(hex(addrs[0]))

    funcs = []
    for addr in addrs:
        if addr == 0:
            break
        func = e.read(addr, 0x20)
        x = disasm(func, offset=0, vma=addr, byte=0).splitlines()
        d = x.index('ret')
        x =x[1:d-1]
        # print(x)
        funcs += x

    # a, b = -1
    operands = []
    s = Solver()
    t = [BitVec(f't{i}', 32) for i in range(16)]
    s.add(*[Or(*[i == j for j in b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789']) for i in t])
    # print(*funcs, sep='\n')
    for line in funcs:
        # print(line)
        if 'QWORD PTR [rbp-0x18]' in line:
            GET = 1
            operands.append(0)
        elif line.startswith('add') and GET:
            idx = int(line.strip().split()[-1], 16)
            operands[-1] += idx
        elif line.startswith('movsx') and GET:
            GET = 0
        else:
            # print(line.split()[0])
            # print()
            match line.split()[0]:
                case 'add':
                    operands = [t[operands[-2]] + t[operands[-1]]]
                case 'imul':
                    operands = [t[operands[-2]] * t[operands[-1]]]
                case 'xor':
                    operands = [t[operands[-2]] ^ t[operands[-1]]]
                case 'sub':
                    operands = [t[operands[-2]] - t[operands[-1]]]
                case 'cmp':
                    cmp = int(line.strip().split()[-1], 16)
                    if cmp & 0x8000:
                        cmp = 0x10000 - cmp
                    s.add(cmp == abs(operands.pop()))
        
    s.check()
    m = s.model()
    o = [m[i].as_long() for i in t]
    # print(bytes(o))

    p.sendlineafter(b': ', bytes(o)) 

    # break

# p.interactive()

flag = p.recvline_contains(b'LiveCTF{').decode().strip()

log.info('Flag: %s', flag)