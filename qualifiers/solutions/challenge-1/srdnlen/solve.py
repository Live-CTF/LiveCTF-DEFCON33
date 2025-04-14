#!/usr/bin/env python3

from capstone import *
from capstone.x86 import *
from pwn import *
from unicorn import *
from unicorn.x86_const import *
import base64
import string

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))
# io = process(['python3','./server.py'], env={'FLAG':'DIOOO'})

char_idx = 0
operation = ''
curr_char_idx = [0, 0]
did_add = False

operations = []

def do_round():

    io.recvuntil(b'Crackme: ')
    binary = base64.b64decode(io.recvline())
    BIN = './chall'
    with open(BIN, 'wb') as f:
        f.write(binary)

    context.binary = elf = ELF(BIN)

    # 1. Read binary file in correct mode
    with open(BIN, 'rb') as f:
        code = f.read()  # Read entire binary content


    # 2. Configure disassembler (example: x86-64)
    md = Cs(CS_ARCH_X86, CS_MODE_64)

    # Initialize the emulator
    mu = Uc(UC_ARCH_X86, UC_MODE_64)


    # Map memory for our code
    BASE_ADDR = 0x100000
    mu.mem_map(BASE_ADDR, len(code) + (4096-len(code)%4096))

    # Write the binary data into the mapped memory
    mu.mem_write(BASE_ADDR, code)




    # Map memory for our code
    FLAG_ADDR = 0x900000
    mu.mem_map(FLAG_ADDR, 0x1000)

    # Write the binary data into the mapped memory
    mu.mem_write(FLAG_ADDR, string.hexdigits.encode())





    JUMPTABLE = elf.vaddr_to_offset(0x4010)


    addrs = []
    idx = 0
    while True:
        f_addr = u64(mu.mem_read(BASE_ADDR+JUMPTABLE+idx*8, 8))
        # relocate
        mu.mem_write(BASE_ADDR+JUMPTABLE+idx*8, p64(f_addr+BASE_ADDR))
        if f_addr < 0x2000:
            addrs.append(f_addr)
            # print(f_addr)
        else: break
        idx+=1


    # print(addrs)

    md.detail = True  # Enable detailed mode to access operand information


    # ALLOCATE STACK

    STACK_BASE = 0x7ff000000  # Starting address of the stack
    STACK_SIZE = 1024 * 1024 # Size of the stack (1 GB)

    # Map the stack memory
    mu.mem_map(STACK_BASE, STACK_SIZE)

    # Initialize the stack pointer (RSP) to the top of the stack
    mu.mem_write(STACK_BASE + STACK_SIZE - 0x10, p64(0xdeaddeaddead))
    mu.reg_write(UC_X86_REG_RBX, STACK_BASE + STACK_SIZE-0x10)
    mu.reg_write(UC_X86_REG_RSP, BASE_ADDR+JUMPTABLE+0)

    mu.reg_write(UC_X86_REG_RDI, FLAG_ADDR)




    def unsigned_to_signed(val, bits):
        if val & (1 << (bits - 1)):
            return val - (1 << bits)
        return val



    char_idx = 0
    operation = ''
    curr_char_idx = [0, 0]
    did_add = False

    operations = []

    # Add a hook to stop emulation when a specific instruction is reached
    def hook_code(uc, address, size, user_data):
        global char_idx, operation, curr_char_idx, did_add

        if address == BASE_ADDR + len(code):
            uc.emu_stop()

        # Read memory at the current instruction pointer
        codee = uc.mem_read(address, size)
        # Disassemble instruction using Capstone
        for insn in md.disasm(codee, address):
            # print(f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")
            if insn.mnemonic == 'add' and insn.operands[1].type == 2 and insn.operands[0].type == 1:
                added_val = insn.operands[1].imm
                curr_char_idx[char_idx%2] = added_val
                char_idx += 1
                # print(f'{curr_char_idx = }')
                # print('B'*0x20)
                did_add = True
            elif insn.mnemonic == 'mov' and insn.operands[1].type == X86_OP_MEM and insn.operands[0].type == X86_OP_REG:
                if insn.operands[0].reg == X86_REG_RAX:
                    # print('A'*0x20)
                    did_add = False
            elif insn.mnemonic == 'movzx' and insn.operands[1].type == X86_OP_MEM and insn.operands[0].type == X86_OP_REG:
                if insn.operands[0].reg == X86_REG_EDX or insn.operands[0].reg == X86_REG_EAX:
                    if not did_add:
                        curr_char_idx[char_idx%2] = 0 # THIS IS ZERO
                        # print('FOUND A ZERO'*10)
                        char_idx += 1
            elif insn.mnemonic == 'imul':
                operation = 'imul'
            elif insn.mnemonic == 'add':
                operation = 'add'
            elif insn.mnemonic == 'sub':
                operation = 'sub'
            elif insn.mnemonic == 'xor':
                operation = 'xor'
            elif insn.mnemonic == 'cmp' or insn.mnemonic == 'test':
                result = insn.operands[1].imm if insn.mnemonic == 'cmp' else 0
                result = unsigned_to_signed(result, 16)
                op1 = curr_char_idx[char_idx%2]
                op2 = curr_char_idx[(char_idx+1)%2]
                # print(f'new operation: {operation = } {result = } {op1} {op2} ')

                operations.append((op1, op2, operation, result))
        return True


    # Callback for handling invalid memory access
    def hook_mem_invalid(uc, access, address, size, value, user_data):
        rip = uc.reg_read(UC_X86_REG_RIP)  # Get current instruction pointer
        # if access == UC_MEM_READ_UNMAPPED:
        #     print(f"Invalid memory read detected!")
        # elif access == UC_MEM_WRITE_UNMAPPED:
        #     print(f"Invalid memory write detected!")
        # elif access == UC_MEM_FETCH_UNMAPPED:
        #     print(f"Invalid memory fetch detected!")
        # else:
        #     print(f"Unknown memory error detected!")

        # print('stack data: ', mem.reg_READ(UC_X86_REG_RSP))
        # print('stack data: ', mem.read(mem.reg_READ(UC_X86_REG_RSP), 0x20))

        # print(f"Instruction Pointer (RIP): 0x{rip:x}")
        # print(f"Memory Address: 0x{address:x}")
        # print(f"Access Size: {size} bytes")
        # if access in (UC_MEM_WRITE_UNMAPPED, UC_MEM_READ_UNMAPPED):
        #     print(f"Value: 0x{value:x}")


        uc.emu_stop()  # Stop emulation for debugging
        return False


    mu.hook_add(UC_HOOK_CODE, hook_code)
    mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED, hook_mem_invalid)
    mu.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid)
    mu.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, hook_mem_invalid)



    # Set up registers (optional)
    mu.reg_write(UC_X86_REG_RIP, BASE_ADDR+addrs[0])  # Set RIP to the start of our code



    # Start emulation
    try:
        mu.emu_start(BASE_ADDR + addrs[0], BASE_ADDR + len(code))
    except UcError as e:
        print(f"Error: {e}")

    # Optionally, print the final state of registers
    # print("Final RIP:", hex(mu.reg_read(UC_X86_REG_RIP)))



    # print(operations)







    import z3

    def resolve_tuple(buffer: list[z3.BitVecRef], solver: z3.Solver, tuple: tuple[int, int, str, int]):
        # tuple of (ind_1, ind_2, operation, result)

        if tuple[2] == "add":
            solver.add(buffer[tuple[0]] + buffer[tuple[1]] == tuple[3])
        elif tuple[2] == "sub":
            solver.add(buffer[tuple[0]] - buffer[tuple[1]] == tuple[3])
        elif tuple[2] == "imul":
            solver.add(buffer[tuple[0]] * buffer[tuple[1]] == tuple[3])
        elif tuple[2] == "xor":
            solver.add(buffer[tuple[0]] ^ buffer[tuple[1]] == tuple[3])

    def resolve(list_tuple: list[tuple]):
        buffer = [z3.BitVec(f'x{i}', 32) for i in range(16)]
        solver = z3.Solver()

        for i in range(16):
            solver.add(buffer[i] >= 0x20)
            solver.add(buffer[i] <= 0x7e)

        for t in list_tuple:
            resolve_tuple(buffer, solver, t)
            # break
        # solver.add(buffer[0] == 0x61)

        if solver.check() == z3.sat:
            model = solver.model()
            final = ''
            for v in buffer:
                final += chr(model[v].as_long())
            # print(f'{final=}')
            io.sendlineafter(b'Password: ', final)
            io.recvline()
        # else:
        #     print('sad')


    # print(f'{len(operations) = }')
    # for p in operations:
    #     print(p)
    # print(resolve(operations))
    resolve(operations)


for i in range(20):
    do_round()

io.recvuntil(b'Here is the flag: ')
log.info(io.recvline().decode())

