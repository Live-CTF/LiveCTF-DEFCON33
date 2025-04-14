#!/usr/bin/env python3

import os
import subprocess
import stat
import string
import sys
import time
from typing import Dict, List

import base64
from elftools.elf.elffile import ELFFile
from pwn import *


def get_function_symbols(binary_path):
    functions = []
    with open(binary_path, 'rb') as f:
        elffile = ELFFile(f)
        symtab = elffile.get_section_by_name('.symtab')
        if symtab:
            for sym in symtab.iter_symbols():
                if sym['st_info']['type'] == 'STT_FUNC':
                    functions.append(sym.name)
    return [f for f in functions if f]  # filter out empty names


def get_func_name_map() -> Dict[str, str]:

    special_chars = '_}{'
    characters = string.ascii_letters + string.digits + special_chars

    func_to_char = {}

    for cur_char in characters:

        if cur_char in special_chars:
            name_map = {
                "_": "func_underscore",
                "{": "func_leftcurly0",
                "}": "func_rightcurly",
            }
            func_name = name_map[cur_char]
        else:
            func_name = "func_" + cur_char * 10

        func_to_char[func_name] = cur_char

    return func_to_char


def emit_gdb_script(
    func_list: List[str],
    func_to_char: Dict[str, str],
    outfile: str = 'print_script.gdb',
):

    script_contents = 'set pagination off\n'
    script_contents += 'set verbose off\n'

    # Set one breakpoint for each func to print the character out
    for func_name in func_list:
        cur_char = func_to_char[func_name]
        cur_breakpoint = f'''
break {func_name}
commands
    printf "{cur_char}"
    continue
end
'''
        # end cur_breakpoint
        script_contents += cur_breakpoint

    # Run it til it stops, then quit
    script_contents += "r\n"
    script_contents += "q\n"


    with open(outfile, 'w') as f:
        f.write(script_contents)

    if os.path.exists(outfile):
        size = os.path.getsize(outfile)
        print(f'[+] Wrote gdb script to "{outfile}" ({size} bytes)')
    else:
        print(f'[-] Failed to write gdb script to "{outfile}"')


def solve_one(target_path: str) -> str:
    """Solve one binary and return the password"""

    start_time = time.time()

    print(f'[*] Parsing functions...')
    target_functions = get_function_symbols(target_path)

    print(f'[*] Creating gdb script...')
    func_to_char = get_func_name_map()
    present_functions = [name for name in func_to_char if name in target_functions]

    gdb_script_file = 'print_script.gdb'
    emit_gdb_script(present_functions, func_to_char, gdb_script_file)

    print(f'[*] Running gdb with script...')
    gdb_command = f'gdb -nh -x {gdb_script_file} ./{target_path}'
    print(f'  Command="{gdb_command}"')
    bytes_out = subprocess.check_output(gdb_command.split())

    output = bytes_out.decode()
    flag = ''
    for cur_line in output.splitlines():
        cur_line = cur_line.strip()
        if len(cur_line) == 1:
            flag += cur_line
        elif len(cur_line) > 1 and cur_line[0] == '}':
            flag += cur_line[0]  # Trailing right curly isn't by itself

    duration = time.time() - start_time
    print(f"[*] Finished in {duration:.01f} seconds")

    print(f'{flag=}')
    return flag


HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

def main():

    # Run on remote
    io = remote(HOST, int(PORT))
    # DEBUG: run the server script directly
    # SCRIPT_PATH = '../server/server.py'
    # GENERATOR_DIR = '../challenge/generator'
    # test_env = os.environ.copy()
    # test_env['FLAG'] = "TEST{FLAG_GOES_HERE}"
    # io = process(
    #     argv=['python3', SCRIPT_PATH],
    #     cwd=GENERATOR_DIR,
    #     env=test_env,
    #     # level='debug',
    # )

    NUM_ROUNDS = 10
    for _ in range(NUM_ROUNDS):

        io.recvuntil(b'Round ')
        challenge_round = int(io.recvuntil(b'/').decode()[:-1].strip())
        log.info('Challenge round: %d', challenge_round)

        io.recvuntil(b'Watchme: ')
        challenge_b64 = io.recvline().decode().strip()
        log.info('Challenge B64 length: %d', len(challenge_b64))

        tmp_elf = 'tmp_challenge.bin'
        with open(tmp_elf, 'wb') as f:
            f.write(base64.b64decode(challenge_b64))
            f.flush()
        # chmod +x
        mode = os.stat(tmp_elf).st_mode
        os.chmod(tmp_elf, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

        password = solve_one(tmp_elf)
        if password == None:
            log.error('Failed')
            return

        log.info('Password: %s', password)
        io.recvuntil(b'Password: ')
        io.sendline(password.encode())

    io.recvuntil(b"Boy howdy! Here's that flag: ")
    flag = io.recvline().decode().strip()
    log.info('Flag: %s', flag)

    #io.interactive()


if __name__ == '__main__':
    main()
