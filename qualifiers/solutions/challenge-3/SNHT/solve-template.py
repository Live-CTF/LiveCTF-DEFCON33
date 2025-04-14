#!/usr/bin/env python3

from pwn import *
import subprocess
from collections import defaultdict
import base64
import tempfile
import os



HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

skibidi = remote(HOST, int(PORT))

for ongod in range(10):
    skibidi.recvuntil(b'Watchme: ')
    hawk = base64.b64decode(skibidi.recvline())
    tuah = tempfile.NamedTemporaryFile(delete=False)
    tuah.write(hawk)
    tuah.close()
    os.chmod(tuah.name, 0o777)

    chimpanzini = subprocess.run(['valgrind', '--tool=callgrind', '--callgrind-out-file=out.cg', tuah.name])

    tungtung = {}
    def tripitropa(name):
        br = name.split()
        brr = int(br[0][1:-1])
        if len(br) == 1:
            return brr
        tungtung[brr] = ' '.join(br[1:])
        return brr

    sauhur = defaultdict(list)
    with open('out.cg', 'r') as tuah:
        curr_parent = None
        for line in tuah.readlines():
            if line.startswith('fn='):
                curr_parent = tripitropa(line[3:])
            elif line.startswith('cfn='):
                child = tripitropa(line[4:])
                sauhur[curr_parent].append(child)

    def get_rizz(rizzler):
        for ohio, sigm in sauhur.items():
            if rizzler in sigm:
                return ohio
        return None

    yeet = next(k for k, v in tungtung.items() if v.startswith('func_'))
    while True:
        zesty = get_rizz(yeet)
        if zesty is None:
            break
        if tungtung[zesty] == 'main': break
        yeet = zesty

    bussin = []

    def mew(mewer):
        bussin.append(mewer)
        for child in sauhur[mewer]:
            mew(child)

    mew(yeet)
    fr = ''.join([tungtung[n][5] for n in bussin if len(set(tungtung[n][6:]))==1])
    fr = fr.replace('PASS', 'PASS{') + '}'
    skibidi.sendlineafter(b'Password: ', fr.encode())
    print(ongod)
print(skibidi.recvall())