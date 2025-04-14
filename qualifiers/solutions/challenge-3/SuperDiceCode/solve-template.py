#!/usr/bin/env python3

from pwn import *
import base64
import subprocess
import re

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337


io = remote(HOST, int(PORT))
# io.interactive()

def test(chal):
    print('testing', chal)
    names = subprocess.check_output(['nm', '-n', chal]).decode().split('\n')
    names = [name.split(' ')[-1] for name in names]
    names = [x for x in names if x.startswith('func_')]

    # print('got names', names)
    valid = []
    for x in names:
        after = set(x.split('func_')[1])
        if len(after) == 1:
            valid.append(x)

    print('got valid', valid)
    # print(valid)
    valid += ['func_leftcurly0', 'func_rightcurly']

    s = process(['gdb', '-q', '--nx', chal])
    for x in valid:
        s.sendlineafter('(gdb)', 'rbreak ' + x)
    s.sendlineafter('(gdb)', 'r')

    flag = ''
    while True:
        dat = s.recvuntil('(gdb)').decode('latin1')
        
        # find last func_xxx in dat
        func = re.findall(r'func_(.*?) ', dat)
        if len(func) > 0:
            t = str(func[-1])
            flag += t[0]
            print(flag)
        else:
            print('done')
            break

        s.sendline('c')

    return flag.replace('l', '{').replace('r', '}')


for i in range(10):
    dat = io.recvuntil('Password:').decode('latin1')
    dat = dat.split('Watchme:')[1]
    dat = base64.b64decode(dat)
    print('len', len(dat))
    open('/tmp/challenge', 'wb').write(dat)
    subprocess.run(['chmod', '+x', '/tmp/challenge'])

    flag = test('/tmp/challenge')
    io.sendline(flag)

io.interactive()
