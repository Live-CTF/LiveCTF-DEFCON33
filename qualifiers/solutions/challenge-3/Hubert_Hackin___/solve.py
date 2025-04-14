#!/usr/bin/env python3

from pwn import *

import base64
import os
import subprocess
import re

from collections import Counter
import math

def calculate_entropy(s: str) -> float:
    length = len(s)

    if length == 0:
        return 0.0

    counts = Counter(s)
    probabilities = [count / length for count in counts.values()]
    entropy = -sum(p * math.log2(p) for p in probabilities)

    return entropy

FUNC_RE = re.compile(r"func_(\w)\w+")

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337
LOCAL = bool(os.environ.get("LOCAL", None))

if LOCAL:
    io = process(["python", "../handout/server.py"], env={"FLAG": "FLAG", "LOCAL": "1"}, cwd="../handout/")
else:
    io = remote(HOST, int(PORT))

if LOCAL:
    iter = 1
else:
    iter = 10

for i in range(iter):
    io.recvuntil(b"Watchme:")

    challenge_b64 = io.recvline()

    with open("/tmp/challenge", "wb") as h:
        h.write(base64.b64decode(challenge_b64))

    os.system("chmod +x /tmp/challenge")

    e = ELF("/tmp/challenge")

    functions = []

    for sym in e.symbols.keys():
        if not sym.startswith("func_"):
            continue

        if calculate_entropy(sym) < 2:
            functions.append(sym)

    p = subprocess.Popen(
        ["gdb", "-nx", "-x", "worker.py"],
        stdout=subprocess.PIPE,
        env={
            "FUNCTIONS": "$".join(functions)
        }
    )

    p.wait()

    buffer = ""
    for s in FUNC_RE.findall(p.stdout.read().decode()):
        buffer += s

    print("Buffer:", buffer)

    flag = f"PASS{{{buffer[4:]}}}"

    print("Flag:", flag)

    io.sendline(flag.encode())

print(io.recvall(timeout=10))
