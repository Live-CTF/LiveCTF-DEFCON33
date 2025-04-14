from pwn import *
import subprocess

ru	= lambda *x: r.recvuntil(*x)
rl	= lambda *x: r.recvline(*x)
rc	= lambda *x: r.recv(*x)
sla = lambda *x: r.sendlineafter(*x)
sa	= lambda *x: r.sendafter(*x)
sl	= lambda *x: r.sendline(*x)
sn	= lambda *x: r.send(*x)

HOST = os.environ.get("HOST", "localhost")
PORT = 31337
r = connect(HOST, int(PORT))

def solve():
	x = "./pin/pin -t ./MyPinTool.so -- /tmp/bin".split()
	proc = subprocess.run(x, stderr=subprocess.PIPE)
	trace = proc.stderr.decode().splitlines()

	kekw = ""
	for line in trace:
		if "func" in line:
			line = line.replace("func_", "")
			if all(line[0] == x for x in line):
				kekw += line[0]

	kekw = kekw[:4] + "{" + kekw[4:] + "}"
	print(kekw)
	return kekw


for i in range(10):
	ru(b"Watchme: ")
	code = b64d(rl().strip())
	with open("/tmp/bin", "wb") as f:
		f.write(code)
	os.system("chmod +x /tmp/bin")

	pas = solve()
	sla(b"Password: ", pas)



print(r.recvall(timeout=1))
