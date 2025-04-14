#!/bin/python

from pwn import *
from base64 import b64decode as b64d
import subprocess
import os

open("bp.py", "w").write("""
f = open("/tmp/name.txt", "w")

class LoggingBreakpoint(gdb.Breakpoint):
    def __init__(self, location):

        super(LoggingBreakpoint, self).__init__(location, gdb.BP_BREAKPOINT)

    def stop(self):
        print(f"{gdb.selected_frame().name()[5]}")
        f.write(f"{gdb.selected_frame().name()[5]}")
        f.flush()
""")

local = False
if local:
    io = process(["python", "server.py"], env={"FLAG": "flag{fakeflag}", "LOCAL": "1"})
    rounds = 1
else:
    HOST = os.environ.get('HOST', 'localhost')
    PORT = 31337
    io = remote(HOST, int(PORT))
    rounds = 10

for _ in range(rounds):
    io.readuntil("Watchme: ")
    d = io.readuntil("Password: ", drop=True)
    d = b64d(d)
    with open("__chal", "wb") as f:
        f.write(d)
    elf = ELF("__chal")
    os.system(f"chmod +x __chal")

    e = elf
    ss = e.symbols

    interesting_functions = [v for v in ss.keys() if v.startswith("func_") and len(set(v[5:])) == 1]


    gdbscript = "source ./bp.py\n"
    for f in interesting_functions:
        gdbscript+= f"python LoggingBreakpoint('{f}')\n"

    gdbscript += "r\n"

    open("gdbscript", "w").write(gdbscript)

    try:
        subprocess.run(["gdb", "__chal", "-x", "./gdbscript"], timeout=4)
    except TimeoutExpired:
        pass
    print("gdb done")
    password = open("/tmp/name.txt").read()
    assert password.startswith("PASS")
    password = "PASS{" + password[4:] + "}"
    
    io.sendline(password)

print(io.readallS())
