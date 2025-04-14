#!/usr/bin/env python3

import re
import subprocess
from pwn import *
from base64 import b64decode

# context.log_level = "DEBUG"

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))
# io = process(['python3.13', 'server.py'])
ITERS = 10

for i in range(ITERS):
    io.recvuntil(b"Watchme: ")
    chal = b64decode(io.recvline(keepends=True).decode())
    binary = f"/tmp/chal{i}"
    gdb_file = f"/tmp/gdb{i}.txt"
    with open(binary, "wb") as f:
        f.write(chal)
    os.chmod(binary, 0o777)

    pattern = re.compile(r'func_(.)\1{8,}$')  # Match func_AAAAAAAAAA, etc.

    # Step 1: Extract matching symbols
    nm_out = subprocess.check_output(["nm", "-C", binary], universal_newlines=True)
    funcs = []
    for line in nm_out.splitlines():
        parts = line.strip().split()
        if len(parts) == 3 and pattern.fullmatch(parts[2]):
            funcs.append(parts[2])

    # Step 2: Generate GDB script
    gdb_script = "set pagination off\n"
    gdb_script += f"set logging file {gdb_file}\n"
    gdb_script += "set logging on\n"
    for func in funcs:
        letter = func[-1]  # Last character should be the repeated letter
        gdb_script += f"break {func}\n"
        gdb_script += f"commands\nsilent\nprintf \"{letter}\\n\"\ncontinue\nend\n"
    gdb_script += "run\nquit\n"

    with open("/tmp/trace.gdb", "w") as f:
        f.write(gdb_script)

    # Step 3: Run GDB
    print(f"[+] Tracking functions: {', '.join(funcs)}")
    subprocess.run(["gdb", "-q", "-x", "/tmp/trace.gdb", binary])

    # Step 4: Parse gdb output
    with open(gdb_file, "r") as f:
        output = f.read()

    # Step 5: Extract and print sequence of unique single letters
    sequence = re.findall(r'^.$', output, re.MULTILINE)
    result = "".join(sequence)
    print("[+] Call order:", result)

    assert result.startswith("PASS")
    result = result[:4] + "{" + result[4:] + "}"

    io.sendlineafter(b"Password: ", result.encode())
    result = io.recvline()

    if b"Correct" not in result:
        print(f"Failed on round {i}")
        print(result)
        io.close()
        exit()

print(io.recvall())
io.close()