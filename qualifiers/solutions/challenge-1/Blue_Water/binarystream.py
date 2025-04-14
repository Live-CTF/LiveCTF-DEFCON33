from struct import *


class BinaryStream:
    def __init__(self, base_stream):
        self.base_stream = base_stream

    def readB(self) -> bytes:
        return self.base_stream.read(1)

    def readBs(self, length):
        return self.base_stream.read(length)

    def readC(self):
        return self.unpack("b")

    def readUC(self):
        return self.unpack("B")

    def readBl(self):
        return self.unpack("?")

    def readI16(self):
        return self.unpack("h", 2)

    def readU16(self):
        return self.unpack("H", 2)

    def readI32(self):
        return self.unpack("i", 4)

    def readU32(self):
        return self.unpack("I", 4)

    def readI64(self):
        return self.unpack("q", 8)

    def readU64(self):
        return self.unpack("Q", 8)

    def readF(self):
        return self.unpack("f", 4)

    def readD(self):
        return self.unpack("d", 8)

    def readS(self):
        length = self.readU16()
        return self.unpack(str(length) + "s", length).decode("utf-8")

    def readSL(self, length):
        return self.unpack(str(length) + "s", length).decode("utf-8")

    def writeBs(self, value):
        self.base_stream.write(value)

    def writeC(self, value):
        self.pack("b", value)

    def writeUC(self, value):
        self.pack("B", value)

    def writeBl(self, value):
        self.pack("?", value)

    def writeI16(self, value):
        self.pack("h", value)

    def writeU16(self, value):
        self.pack("H", value)

    def writeI32(self, value):
        self.pack("i", value)

    def writeU32(self, value):
        self.pack("I", value)

    def writeI64(self, value):
        self.pack("q", value)

    def writeU64(self, value):
        self.pack("Q", value)

    def writeF(self, value):
        self.pack("f", value)

    def writeD(self, value):
        self.pack("d", value)

    def writeS(self, value):
        length = len(value)
        self.writeU16(length)
        self.pack(str(length) + "s", value.encode("utf-8"))

    def pack(self, fmt, data):
        return self.writeBs(pack("<" + fmt, data))

    def unpack(self, fmt, length=1):
        return unpack("<" + fmt, self.readBs(length))[0]

    def tell(self):
        return self.base_stream.tell()

    def seek(self, pos, whence=0):
        return self.base_stream.seek(pos, whence)
