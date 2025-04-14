#!/usr/bin/env python3

from pwn import *
import os

context.log_level = "error"

HOST = os.environ.get("HOST", "localhost")
PORT = 31337

r = remote(HOST, int(PORT))

finish = False
while not finish:
    r.recvuntil(b"Round ")
    cur_round = int(r.recvuntil(b"/", drop=True))
    total_rounds = int(r.recvuntil(b"\n", drop=True))

    if cur_round == total_rounds:
        finish = True

    r.recvuntil(b"Watchme: ")
    watchme = r.recvuntil(b"\n", drop=True)
    watchme = base64.b64decode(watchme)
    with open(f"watchme_{cur_round}.bin", "wb") as f:
        f.write(watchme)
    os.chmod(f"watchme_{cur_round}.bin", 0o755)

    with process(["python3", "/gdb-trace.py", f"./watchme_{cur_round}.bin"]) as p:
        p.recvuntil(b"Password FOUND\n")
        password = p.recvuntil(b"\n", drop=True)
        if password.startswith(b"PASS"):
            password = password[:4] + b"{" + password[4:] + b"}"
        print(f"Password for round {cur_round}: {password}")

    r.sendlineafter(b"Password: ", password)
    verdict = r.recvuntil([b"Correct!", b"Incorrect..."])
    if b"Correct!" in verdict:
        print(f"Correct for round {cur_round}")
    else:
        print(f"Incorrect for round {cur_round}")
        break

print(r.recvall(timeout=3))
