#!/usr/bin/env python3

from pwn import *
import string
import subprocess
import os
import re

# context.log_level = "debug"

HOST = os.environ.get("HOST", "localhost")
PORT = 31337

io = remote(HOST, int(PORT))

for i in range(10):
    io.recvuntil(b"Watchme: ")
    challenge_b64 = io.recvuntil(b"Password: ", drop=True).strip()
    chal = base64.b64decode(challenge_b64)
    open("/tmp/challenge", "wb").write(chal)
    os.chmod("/tmp/challenge", 0o755)

    code = ELF("/tmp/challenge")
    script = ""
    for c in string.ascii_letters + string.digits:
        if "func_" + c * 10 in code.symbols:
            script += f"b func_{c * 10}\n"
    script += f"r\n"
    # print(script)

    open("script", "w").write(script)
    p = subprocess.run(
        ["gdb", "-q", "--batch", "/tmp/challenge", "-x", "debug.py"],
        shell=False,
        check=True,
        stdout=subprocess.PIPE,
    )
    out = p.stdout.decode()
    print(out)

    flag = ""
    for l in out.splitlines():
        if m := re.match(
            r"^Breakpoint [0-9]+, 0x[0-9a-f]+ in func_([a-zA-Z0-9]){10} \(\)$", l
        ):
            flag += m.groups()[0]
    flag = flag[:4] + "{" + flag[4:] + "}"
    print(flag)

    io.sendline(flag.encode())
io.recvuntil(b"Boy howdy! Here's that flag: ")
flag = io.recvline().strip()
print("flag", flag.decode())
# io.interactive()
