import angr
import argparse
import claripy
import sys
import base64

from tqdm import tqdm
from pwn import *

context.terminal = ['tmux', 'splitw', '-v']
context.log_level = 'info'
context.arch='amd64'


PATH = "/solve/handout/challenge"
# LIBC = "/handout/libc.so.6"
# LD = "/handout/ld-linux-x86-64.so.2"
# e = ELF(PATH)
# libc = ELF(LIBC)

network = len(sys.argv) > 1

if network:
    parser = argparse.ArgumentParser()
    default_addr = os.environ.get("HOST", "127.0.0.1") + ":" + os.environ.get("PORT", "31337")
    parser.add_argument("--network", action='store_true')
    parser.add_argument("address", default=default_addr,
                        nargs="?", help="Address of challenge")
    args = parser.parse_args()
    HOST, PORT = args.address.split(':')

    r = remote(HOST, int(PORT))
else:
    assert False
    # r = process(PATH)
#     r = gdb.debug(PATH, f'''
# file {PATH}
# c
# ''')

# https://github.com/angr/angr-examples/blob/master/examples/csaw_wyvern/solve.py
# https://github.com/angr/angr-examples/blob/master/examples/codegate_2017-angrybird/solve.py
# https://github.com/angr/angr-examples/blob/master/examples/ekopartyctf2015_rev100/solve.py

def solve():
    p = angr.Project("chal")
    stdin = claripy.BVS('stdin', 17 * 8)
    init = p.factory.entry_state(
        add_options=angr.options.unicorn & {angr.options.LAZY_SOLVES},
        addr=0x0040129e,
    )
    init.mem[init.regs.rdi+16].uint8_t = 0xa
    for i in range(16):
        bv = claripy.BVS(f'flag{i}', 8)
        init.mem[init.regs.rdi+i].uint8_t = bv
        init.add_constraints(bv != 0)
        init.add_constraints(bv != 0xa)
        init.add_constraints(bv >= ord('0'), bv <= ord('z'))

    sm = p.factory.simgr(init)
    sm.use_technique(angr.exploration_techniques.DFS())
    sm.explore(find=0x004012a3)
    f = sm.found[0]
    f.add_constraints(f.regs.rax == 1)
    flag = ''.join((chr(f.mem[f.regs.rdi+i].uint8_t.concrete) for i in range(16)))
    print(flag)
    return flag.encode()


for i in tqdm(range(20)):
    r.recvuntil(b"Crackme: ")
    conts = r.recvuntil(b"\n")[:-1]
    conts = base64.b64decode(conts)

    Path("chal").write_bytes(conts)

    pw = solve()
    r.sendline(pw)

flag = r.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)