#!/usr/bin/env python3

from pwn import *
import angr
import claripy
import hashlib
import base64

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))
#io = process(['python3','server.py'])
ar = ['292416353dfef6bb5866ae16b5702076031f176f2daccf547cf8423b598dc831',0,'af07a1d6d5a6b6a27e138d520082a94ea2707efa9c9542683deb33901a55928f',1,'c6f6e946ef61f12a164a5253c394f79ef875f4bf2a31ce7d99b1c81b388ee83b',10,'25e6182a66ad357ec15e5c7ee80f545d3b406a3cae2d88fcab1db36c1fd8d2c6',11,'38ab16999c79c05b166090d4116475dbf005b13437f2a12948d53a0163cd0531',12,'a845b22d6b314c7131b7067b723688d25199b0aece097468a258913af621cacd',13,'08df5fa751e9fb5dacf5a484d9dbf49b24fb5b7eb20f10b0d3da6cb453cebaf4',14,'d2ace5dbb27f1fdea5b26d19ce2f4c4e163a57aa32be7ccf34cee6a48c6eed95',15,'88610852c57b680d569da2ee5245ed5ed46b78ee974894d59533033254a156e1',16,'63565002013f6cd6fa099743f509cba52dc794180099b8157fd6171f133f237b',17,'ebd5b04ad3f0a9935074805a51b6f31f94f12033ae154d841af79c940ab181ba',18,'282b7bb046c54a672947c7a146a00380c15d9b09fdd69206716c84a3b59eee4d',19,'a88fe67d352f9d7087e996e4e27c26987ca75d531feb587f93ea63e8d61375c9',2,'bce712f523a4db941ca14dca29c39dd11512ccb4f1473b3a31fbdb7c5b638a4b',3,'0e351df3df29a13b8f4fe5abe01240ca7fa59e38ec95199a0349ffcd3bdcd576',4,'76469b8094d247a52785ddd4a881694d41e2539cf829efcbb9b8d2f6b29605c8',5,'1180b5a1c409331404c469cb1015267f43c3a729a60a4e9418304b5148c86356',6,'5d33ad0818a8ad7562fbce8492600080d56f29321bd8f3b12981150d1c29977d',7,'edb5a51d5739351037298619dfb74c1e26f922ad3b7e35739902accca2cf210e',8,'26d7c3c010e2febf8fa302672ac742989c6eeb2721660e57e72dbc4d3549a21e',9]
hm = {}
for x,y in zip(ar[::2], ar[1::2]):
    D = {0: b'OKs5fOmT3oTGdvlE', 1: b'xoI553kHMqbZmmen', 2: b'fxp8K8oS1eOzLhha', 3: b'eothog2YsACVKsjO', 4: b's223pHzYciI0405p', 5: b'56Nu8DUcG3xYkssV', 6: b'bOi6SCvbfuSBGmxH', 7: b'lZa7ciSUROQVfvro', 8: b'myToAy7xarst2GOU', 9: b'FgyQ4QYwXVgbBalD', 10: b'zLTS8hmbpdcerft2', 11: b'USQDB3OQzqdbPtwh', 12: b'DdF78uv9Hmx8wLxC', 13: b'lH9yaLwkRFUuEl8D', 14: b'Dsx2oqBiseHRawsf', 15: b'X4X9DAZNy8gVxvV0', 16: b'Tp4VElxG1aILeQWb', 17: b'QkGJTXWGEKq112f7', 18: b'05mDdOhQd9BsLXNM', 19: b'V1pkFjV72OEx59Gu'}
    hm[x] = D[y]
#print
for _ in range(20):
    io.recvuntil(b'Crackme:')
    f = base64.b64decode((io.recvline()))
    a = f[0x3010:]
    a = [int.from_bytes(a[i:i+8],'little') for i in range(0, len(a), 8)]
    #print(a)
    #f = b''.join([f[i:].split(b'\xc3')[0]])
    fn = b''
    for i in a:
        dat = f[i:]
        dat = dat[:dat.find(b'\x48\x87\xe3\xc3')]
        if dat[:3] != b'\x48\x87\xe3':
            break
        dat = dat[3:]
        fn += dat
    f = fn
    if f[-1] != 0xc3:
        f += b'\xc3'
    #print(fi, len(f))
    #f = f.replace(b'\x0f\xb6\xc0\x21\x45\xfc', b'\xf6\xf0\x90\x90\x90\x90')
    #f = f[:-2] + fasm64('div eax\n ret')
    f = f[:-2] + b'\xf6\xf0\xc3' #fasm64('div eax\n ret')
    #print(fi, len(f))
    flag = claripy.BVS('flag', 256)
    prj = angr.Project('/bin/true')
    st = prj.factory.blank_state()
    st.memory.store(0x1000, f)
    st.regs.rip = 0x1000
    st.regs.rbp = 0x2000
    st.regs.rdi = 0x3000
    st.mem[0x2000 - 0x18:].uint64_t = 0x3000
    st.memory.store(0x3000, flag)
    sm = prj.factory.simgr(st)
    ex = sm.explore(find = 0x1000 + len(f) - 1)
    for s in ex.found:
        fl = s.solver.eval(flag).to_bytes(32,'big')
        assert sum(fl[16:]) == 0
        #print(fl[:16], sum(fl[16:]))
        #ANS[fi] = fl[:16]
        print(fl[:16])
        io.sendline(fl[:16].decode())
    #with open(f'fun_{fi}', 'wb') as f2:
    #    f2.write(fn)
    #print(hashlib.sha256(f).hexdigest())
    #io.sendline(hm[hashlib.sha256(f).hexdigest()])
for _ in range(2):
    print(io.recvline().decode())
#print(io.recvuntil('lag')[:2])

#print(f)
io.interactive()
