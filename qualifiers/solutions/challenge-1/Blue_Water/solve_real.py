import base64
import struct
from z3 import *
from pwn import *

# am lazy
from binarystream import *


class Instruction:
    def __init__(self, name: str, id: int, param: list):
        self.name = name
        self.id = id
        self.param = param


# ignore all of the string writing junk lmao this was supposed to be a lot different earlier


def pattern_match(data: bytes) -> tuple[Instruction, int]:
    # print(data[:20].hex())
    if data[:6] == bytes.fromhex("0f af c2 0f b7 c0"):
        # IMUL               EAX,EDX
        # MOVZX              EAX,AX
        return (Instruction("EAX = (EAX*EDX)&0xffff", 0, []), 6)
    elif (
        data[0 : 0 + 3] == bytes.fromhex("48 8b 45")
        and data[4 : 4 + 3] == bytes.fromhex("48 83 c0")
        and data[8 : 8 + 3] == bytes.fromhex("0f b6 00")
    ):
        # MOV                RAX,qword ptr [RBP + -0x18]
        # ADD                RAX,0x6
        # MOVZX              EAX,byte ptr [RAX]
        return (Instruction("EAX = flag[p0]", 1, [data[7]]), 11)
    elif (
        data[0 : 0 + 3] == bytes.fromhex("48 8b 45")
        and data[4 : 4 + 3] == bytes.fromhex("48 83 c0")
        and data[8 : 8 + 3] == bytes.fromhex("0f b6 10")
    ):
        # MOV                RAX,qword ptr [RBP + -0x18]
        # ADD                RAX,0x6
        # MOVZX              EDX,byte ptr [RAX]
        return (Instruction("EDX = flag[p0]", 8, [data[7]]), 11)
    elif data[0 : 0 + 3] == bytes.fromhex("48 8b 45") and data[
        4 : 4 + 3
    ] == bytes.fromhex("0f b6 00"):
        # MOV                RAX,qword ptr [RBP + -0x18]
        # MOVZX              EAX,byte ptr [RAX]
        return (Instruction("EAX = flag[p0]", 1, [0]), 7)
    elif data[0 : 0 + 3] == bytes.fromhex("48 8b 45") and data[
        4 : 4 + 3
    ] == bytes.fromhex("0f b6 10"):
        # MOV                RAX,qword ptr [RBP + -0x18]
        # MOVZX              EDX,byte ptr [RAX]
        return (Instruction("EDX = flag[p0]", 8, [0]), 7)
    elif data[:3] == bytes.fromhex("0f be d0"):
        # MOVSX              EDX,AL
        return (Instruction("EDX = EAX&0xff", 2, []), 3)
    elif data[:3] == bytes.fromhex("0f be c0"):
        # MOVSX              EAX,AL
        return (Instruction("EAX = EAX&0xff", 3, []), 3)
    elif (
        data[0] == 0x3D
        and data[5 : 5 + 3] == bytes.fromhex("0f 94 c0")
        and data[8 : 8 + 3] == bytes.fromhex("0f b6 c0")
        and data[11 : 11 + 3] == bytes.fromhex("21 45 fc")
    ):
        # CMP                EAX,0x323e
        # SETZ               AL
        # MOVZX              EAX,AL
        # AND                dword ptr [RBP + -0x4],EAX
        return (
            Instruction("s.add(EAX == p0)", 4, [struct.unpack("<I", data[1:5])[0]]),
            14,
        )
    elif (
        data[0 : 0 + 2] == bytes.fromhex("83 f8")
        and data[3 : 3 + 3] == bytes.fromhex("0f 94 c0")
        and data[6 : 6 + 3] == bytes.fromhex("0f b6 c0")
        and data[9 : 9 + 3] == bytes.fromhex("21 45 fc")
    ):
        # CMP                EAX,0xa
        # SETZ               AL
        # MOVZX              EAX,AL
        # AND                dword ptr [RBP + -0x4],EAX
        return (
            Instruction("s.add(EAX == p0)", 4, [data[2]]),
            6 + 6,
        )
    elif (
        data[0 : 0 + 2] == bytes.fromhex("85 c0")
        and data[2 : 2 + 3] == bytes.fromhex("0f 94 c0")
        and data[5 : 5 + 3] == bytes.fromhex("0f b6 c0")
        and data[8 : 8 + 3] == bytes.fromhex("21 45 fc")
    ):
        # TEST               EAX,EAX
        # SETZ               AL
        # MOVZX              EAX,AL
        # AND                dword ptr [RBP + -0x4],EAX
        return (
            Instruction("s.add(EAX == p0)", 4, [0]),
            11,
        )
    elif data[:5] == bytes.fromhex("01 d0 0f b7 c0"):
        # ADD                EAX,EDX
        # MOVZX              EAX,AX
        return (Instruction("EAX = (EDX+EAX)&0xffff", 5, []), 5)
    elif data[:5] == bytes.fromhex("29 c2 0f b7 c2"):
        # SUB                EDX,EAX
        # MOVZX              EAX,DX
        return (Instruction("EAX = (EDX-EAX)&0xffff", 6, []), 5)
    elif data[:8] == bytes.fromhex("31 d0 0f be c0 0f b7 c0"):
        # XOR                EAX,EDX
        # MOVSX              EAX,AL
        # MOVZX              EAX,AX
        return (Instruction("EAX = (EDX^EAX)&0xffff", 9, []), 8)
    elif data[:19] == bytes.fromhex(
        "f3 0f 1e fa 55 48 89 e5 48 89 7d e8 c7 45 fc 01 00 00 00"
    ):
        return (Instruction("# start of function", 7, []), 19)
    elif data[:4] == bytes.fromhex("8b 45 fc 5d"):
        return None, None
    else:
        raise Exception("IDK???? " + data[:20].hex())


def do_thing(f):
    bs = BinaryStream(f)

    bs.base_stream.seek(0x3010)

    ptrs = []
    while True:
        ptr = bs.readU64()
        if ptr == 0x625528203A434347:
            break

        ptrs.append(ptr)

    code_bytes = []
    for p in ptrs:
        bs.base_stream.seek(p)
        print(f"at {hex(p)}")
        this_code_bytes = b""
        while True:
            this_code_bytes += bs.readB()
            if this_code_bytes.endswith(b"\x48\x87\xe3\xc3"):
                code_bytes.append((p, this_code_bytes[3:-4]))
                break

    code_bytes_combo = b""
    for cb in code_bytes:
        p, cbd = cb
        # print(hex(p), cbd.hex())
        code_bytes_combo += cbd

    code = """
from z3 import *

flag = [BitVec(f"{i}", 32) for i in range(16)]
s = Solver()

for i in range(16):
    s.add(flag[i] >= 0)
    s.add(flag[i] <= 127)

"""

    while True:
        ins, size = pattern_match(code_bytes_combo)
        if ins == None:
            break

        text = ins.name
        for i in range(len(ins.param)):
            text = text.replace(f"p{i}", str(ins.param[i]))

        code += text + " # " + str(ins.id) + "\n"
        code_bytes_combo = code_bytes_combo[size:]

    code += """

print(s.check())
model = s.model()
results = [int(str(model[flag[i]])) for i in range(len(model))]
pc = ""
for ri in results:
    pc += chr(ri)

RESULT = pc
"""

    context = {}
    exec(code, context)
    result = context["RESULT"]
    return result



HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

p = remote(HOST, int(PORT))
for i in range(20):
    p.recvuntil(b"Crackme: ")
    data = base64.b64decode(p.recvuntil(b"Password: ").decode().strip())
    bio = io.BytesIO(data)
    answer = do_thing(bio)
    print(f"correct answer is {answer}")
    p.send(answer.encode() + b"\n")

p.interactive()
