#!/usr/bin/env python3

import os
import secrets
import subprocess

from pwn import *

context.log_level = "CRITICAL"


def solve_one(elf_name: str) -> str:
    completed_process = subprocess.run(
        ["gdb", "--nx", "-x", "./gdb-script.py", elf_name],
        capture_output=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed_process.returncode != 0:
        print("Failed!")
        print(f"{completed_process.stdout = }")
        print(f"{completed_process.stderr = }")

    with open("result.txt") as f:
        content = f.read().strip()
        print(f"{content = }")
        # return content
        return content[:4] + "{" + content[4:] + "}"
        # return "PASS{" + content + "}"


HOST = os.environ.get("HOST", "localhost")
PORT = 31337

io = remote(HOST, int(PORT))

NUM_ROUNDS = 10  # ローカル実行時は1にする
ROUND_TIMEOUT = 10.0


for round in range(NUM_ROUNDS):
    io.recvuntil(b"Watchme: ")
    received_line = io.recvline()
    # print(f"{received_line = }")
    elf_bytes = base64.b64decode(received_line)
    elf_name = secrets.token_hex(16)
    with open(elf_name, "wb") as fout:
        fout.write(elf_bytes)
    subprocess.run(["chmod", "777", elf_name], capture_output=True, text=True)
    user_password = solve_one(elf_name)
    print(f"{user_password = }")
    io.sendlineafter(b"Password", user_password.encode())
io.interactive()  # 最後のフラグを表示させる
