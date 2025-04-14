#!/usr/bin/env python3

from pwn import *
import subprocess
import time
import os

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))

def run_gdb():
    os.system('gdb --batch-silent -x /deploy/gdb-py.py /tmp/challenge > /dev/null 2>&1')
    time.sleep(5)

for i in range(10):
    io.recvuntil(b'Watchme: ')
    challenge_b64 = io.recvline().strip().decode()
    challenge_data = base64.b64decode(challenge_b64)

    with open('/tmp/challenge', 'wb') as f:
        f.write(challenge_data)

    os.system("chmod +x /tmp/challenge")
    # print(challenge_data)
    password = ""
    run_gdb()
    with open('/tmp/result.txt', 'r') as result_file:
        result_content = result_file.read()
        print(result_content)
        password = result_content

        io.sendline(password.encode())
    print(f"stage {i} success")
io.recvuntil(b"flag: ")
print(io.recvline())

io.interactive()
