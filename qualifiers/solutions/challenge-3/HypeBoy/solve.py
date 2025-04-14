from pwn import *
from base64 import b64decode as bd
from subprocess import check_output as co

context.arch = 'amd64'
# context.log_level = 0

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

p = remote(HOST, int(PORT))
# p = process(['python3', '-u', 'server.py'], env={'FLAG':'SIBAL'})

# ROUNDS = int(p.recvline().strip().split(b'/')[-1]) 
# print(ROUNDS)

for _ in range(10):
    p.recvuntil(b'Watchme: ')
    binary = bd(p.recvline().strip().decode())
    with open('elf', 'wb') as f:
        f.write(binary)
    co('chmod +x elf', shell=True)
    # print(hex(addrs[0]))

    pwd = co('gdb -x sibal.py', shell=True).strip().splitlines()[-1]
    print(pwd)
    p.sendlineafter(b': ', pwd)


        
# p.interactive()

flag = p.recvline_contains(b'LiveCTF{').decode().strip()

log.info('Flag: %s', flag)