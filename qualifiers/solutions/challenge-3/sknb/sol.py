from pwn import *
import os
import base64 
import time
import warnings
warnings.filterwarnings("ignore")

HOST = os.environ.get("HOST", 'localhost')
PORT = 31337
p = remote(HOST, int(PORT))
#p = process(['python3', 'server.py'])

for _ in range(10):
    p.recvuntil('Watchme: ')
    binDump = base64.b64decode(p.recvline().strip())
    with open('chall', 'wb') as f:
        f.write(binDump)

    os.system("rm bt.txt")
    os.system("chmod +x chall")
    os.system('gdb -batch -x gdbs.txt ./chall > /dev/null 2>&1')
    time.sleep(3)#give it a bit of time?
    os.system("cat bt.txt")
    with open('bt.txt', 'r') as f:
        lines = f.readlines()
    password = ''
    for line in lines:
        password += line.split()[-2][-1]
    print(password)
    if password[:4] == 'PASS':
        password = 'PASS{' + password[4:] + '}'
    p.sendline(password)


print(p.clean().decode())

