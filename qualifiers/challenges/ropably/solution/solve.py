#!/usr/bin/env python3

from pwn import *
import base64
import lief
import struct
from capstone import *
from keystone import *
import angr
import claripy
import hashlib
import tempfile

def u64(data):
    return struct.unpack("<Q", data)[0]

def solve(elf_b64):
    with tempfile.NamedTemporaryFile('wb') as tmpelf:
        tmpelf.write(base64.b64decode(elf_b64))
        tmpelf.flush()
        
        with open(tmpelf.name, "rb") as fin:
            elf_data = fin.read()
        elf = lief.ELF.parse(tmpelf.name)

        data_section = elf.get_section(".data")
        data_offset = data_section.file_offset
        data_size = data_section.original_size
        print(f".data offset: {data_offset:#x}, size: {data_size:#x}")

        rop_table = []
        for table_offset in range(data_offset, data_offset + data_size, 8):
            candidate_entry = elf_data[table_offset : table_offset + 8]
            candidate_addr = u64(candidate_entry)
            candidate_offset = elf.virtual_address_to_offset(candidate_addr)
            cand_marker = elf_data[candidate_offset : candidate_offset + 3]
            if cand_marker != bytes.fromhex("4887e3"):
                continue

            code = []
            gadget_addr = candidate_addr
            
            code_len = elf_data[candidate_offset:].find(bytes.fromhex("4887e3c3"))
            code = elf_data[candidate_offset:candidate_offset+code_len]

            rop_table.append((gadget_addr, code))

        """
        with open('deobf.S', 'w') as fout:
            for addr, code in rop_table:
                #print(f'Addr: {gadget_addr:#x}')
                #print(code.hex())

                md = Cs(CS_ARCH_X86, CS_MODE_64)
                md.syntax = CS_OPT_SYNTAX_ATT
                for i in md.disasm(code, addr):
                    if i.mnemonic == 'xchgq' and i.op_str == '%rsp, %rbx':
                        continue
                    if i.mnemonic == 'retq':
                        continue
                    line = "%s\t%s" % (i.mnemonic, i.op_str)
                    print(line)
                    fout.write(line + '\n')
            fout.write('ret\n')
        """

        clean_lines = []
        for addr, code in rop_table:
            # print(f'Addr: {gadget_addr:#x}')
            # print(code.hex())

            md = Cs(CS_ARCH_X86, CS_MODE_64)
            for i in md.disasm(code, addr):
                if i.mnemonic == "xchg" and i.op_str == "rbx, rsp":
                    continue
                if i.mnemonic == "ret":
                    continue
                if i.mnemonic == "endbr64":
                    continue
                line = "%s\t%s" % (i.mnemonic, i.op_str)
                clean_lines.append(line)
        clean_lines.append("ret")
        clean_code = "\n".join(clean_lines[:])

        #print(clean_code)

        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        try:
            encoding, count = ks.asm(clean_code)
        except KsError as e:
            print("ERROR: %s" % e)
            print(dir(e))

        func = bytes(encoding)
        #print(func.hex())

        project = angr.project.load_shellcode(func, arch="amd64")

        password_len = 16
        password = claripy.BVS(f'password', 8*password_len)
        password_ptr = [angr.PointerWrapper(password, buffer=True)]

        cc = project.factory.cc()
        state = project.factory.call_state(0, *password_ptr, add_options={angr.options.CONSTRAINT_TRACKING_IN_SOLVER}, ret_addr=0x31337, cc=cc)
        for i in range(password_len):
            state.solver.add(
                claripy.Or(
                    password.get_byte(i) == 0,
                    claripy.And(password.get_byte(i) >= ord('0'), password.get_byte(i) <= ord('9')),
                    claripy.And(password.get_byte(i) >= ord('a'), password.get_byte(i) <= ord('z')),
                    claripy.And(password.get_byte(i) >= ord('A'), password.get_byte(i) <= ord('Z')),
                )
            )

        state.regs.rbp = 0
        state.regs.cc_ndep = 0
        simgr = project.factory.simulation_manager(state)
        simgr.explore(find=0x31337)
        found = simgr.found[0]
        found.solver.add(found.regs.rax == 1)
        print(simgr)

        try:
            solution = found.solver.eval(password, cast_to=bytes)
            password = solution.rstrip(b'\0').decode()
            return password[:password_len]
        except Exception as e:
            log.error('Failed: %s', str(e))
            challenge_id = hashlib.sha256(elf_data).digest()
            log.info('Challenge id: %s', challenge_id.hex())
            with open('unsat_elf', 'wb') as fout:
                fout.write(elf_data)
            with open('unsat_elf_deobf', 'wb') as fout:
                fout.write(func)
            return None


HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

def main():
    io = remote(HOST, int(PORT))
    for _ in range(20):
        io.recvuntil(b'Round ')
        challenge_round = int(io.recvuntil(b'/').decode()[:-1].strip())
        log.info('Challenge round: %d', challenge_round)
        io.recvuntil(b'Crackme: ')
        challenge_b64 = io.recvline().decode().strip()
        log.info('Challenge B64 length: %d', len(challenge_b64))
        password = solve(challenge_b64)
        if password == None:
            log.error('Failed')
            return
        log.info('Password: %s', password)
        io.recvuntil(b'Password: ')
        io.sendline(password.encode())
    io.recvuntil(b'Congratulations! Here is the flag: ')
    flag = io.recvline().decode().strip()
    log.info('Flag: %s', flag)
    #io.interactive()

if __name__ == '__main__':
    main()