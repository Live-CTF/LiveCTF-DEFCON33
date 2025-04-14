#!/usr/bin/env python3

import base64
import secrets
import subprocess
import time

import z3
from pwn import *

context.log_level = "INFO"
context.arch = "amd64"

HOST = os.environ.get("HOST", "localhost")
PORT = 31337


def enumerate_rop_blocks(elf_name: str):
    with open(elf_name, "rb") as f:
        bin = f.read()

        ind = 0x3008
        assert bin[ind : ind + 8] == b"\x08\x40\x00\x00\x00\x00\x00\x00"
        ind += 8
        insns = b""
        # print(f"\n\n=== challenge_{challind}\n")
        while True:
            addr = u64(bin[ind : ind + 8])
            if not (0x1300 < addr < 0x2000):
                break
            instr = bin[addr:]
            assert instr[:3] == b"\x48\x87\xe3"
            block = instr[3 : instr.index(b"\x48\x87\xe3\xc3")]
            insns += block
            ind += 8

        # print(insns.hex())
        assert (
            insns[:0x13]
            == b"\xf3\x0f\x1e\xfaUH\x89\xe5H\x89}\xe8\xc7E\xfc\x01\x00\x00\x00"
        )

        insns = insns[0x13:]
        while True:
            ind = insns.find(b"\x21\x45\xfc")
            if ind == -1:
                break
            cur = insns[: ind + 3]
            # print(cur.hex())
            # print(disasm(cur))
            # print(len(cur))
            yield cur
            insns = insns[ind + 3 :]

        # print(insns.hex())


def solve_one(elf_name: str) -> str:
    # TODO: 正解となる入力を返す
    solver = z3.Solver()
    answer_list = [z3.BitVec(f"answer_{i:02d}", 8) for i in range(16)]
    for answer in answer_list:
        # solver.add(answer >= 0x21, answer < 0x7F)
        solver.add(
            z3.Or(
                z3.And(ord("0") <= answer, answer <= ord("9")),
                z3.And(ord("a") <= answer, answer <= ord("z")),
                z3.And(ord("A") <= answer, answer <= ord("Z")),
            )
        )

    block_index = 0
    answer_index: int | None = None
    eax_index = None
    edx_index = None
    operator = None
    cmp_target = 0
    for rop_block in enumerate_rop_blocks(elf_name):
        disassembled = disasm(rop_block)
        for line in disassembled.splitlines():
            # print(f"{line = }")

            def match(code: str):
                return code in line

            if match("imul   eax, edx"):
                operator = "*"
            elif match("add    eax, edx"):
                operator = "+"
            elif match("sub    edx, eax"):
                operator = "-"
            elif match("xor    eax, edx"):
                operator = "^"
            elif match("mov    rax, QWORD PTR [rbp-0x18]"):
                answer_index = 0
            elif match("add    rax, "):
                # add    rax, 0x6 等
                answer_index = int(line.split(",")[1], 0)
            elif match("movsx  eax, al"):
                assert answer_index is not None
                eax_index = answer_index
            elif match("movsx  edx, al") or match("movzx  edx, BYTE PTR [rax]"):
                assert answer_index is not None
                edx_index = answer_index
            elif match("cmp    eax, "):
                # 直後に「sete   al」が続く
                cmp_target = int(line.split(",")[1], 0)
            elif match("test   eax, eax"):
                # 直後に「sete   al」が続く
                cmp_target = 0
            elif match("sete   al"):
                # 毎回最後にあるはず
                assert edx_index is not None
                assert eax_index is not None
                assert cmp_target is not None
                assert operator is not None
                match operator:
                    case "+":
                        solver.add(
                            answer_list[edx_index] + answer_list[eax_index]
                            == cmp_target
                        )
                    case "-":
                        solver.add(
                            answer_list[edx_index] - answer_list[eax_index]
                            == cmp_target
                        )
                    case "*":
                        solver.add(
                            answer_list[edx_index] * answer_list[eax_index]
                            == cmp_target
                        )
                    case "^":
                        solver.add(
                            answer_list[edx_index] ^ answer_list[eax_index]
                            == cmp_target
                        )
                edx_index = None
                eax_index = None
                cmp_target = None
                operator = None
                answer_index = None
            else:
                pass  # 他にもいろいろあるので

    if solver.check() != z3.sat:
        raise Exception("Can not find answer")
    model = solver.model()
    return "".join(chr(model[answer].as_long()) for answer in answer_list)


def local_test():
    for i in range(20):
        time_before = time.time()
        challenge_path = f"../handout/samples/challenge_{i}"
        user_password = solve_one(challenge_path)

        p = subprocess.run(
            [challenge_path],
            input=user_password.encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        challenge_output = p.stdout
        correct_password = challenge_output.decode().strip() == "Yes"
        time_after = time.time()
        print(f"challenge {i} : {user_password} for {time_after - time_before}")
        assert correct_password


# local_test()
# exit(0)

io = remote(HOST, int(PORT))

NUM_ROUNDS = 20
ROUND_TIMEOUT = 10.0

for round in range(NUM_ROUNDS):
    io.recvuntil(b"Crackme: ")
    received_line = io.recvline()
    # print(f"{received_line = }")
    elf_bytes = base64.b64decode(received_line)
    elf_name = secrets.token_hex(16)
    with open(elf_name, "wb") as fout:
        fout.write(elf_bytes)
    user_password = solve_one(elf_name)
    io.sendlineafter(b"Password", user_password.encode())
io.interactive()  # 最後のフラグを表示させる
