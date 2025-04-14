def curpos(grid):
    for y in range(len(grid)):
        for x in range(len(grid[y])):
            if grid[y][x] == '@':
                return (x, y)
    return None

def pathfind(grid, sx, sy, ex, ey):
    if grid[ey][ex] == 'o':
        return None
    import collections
    q = collections.deque()
    prev = {}
    for y in range(len(grid)):
        for x in range(len(grid[y])):
            prev[(x, y)] = None
    
    prev[(sx, sy)] = (sx, sy)
    q.appendleft((sx, sy))

    while len(q) > 0:
        (nx, ny) = q.pop()
        if nx == ex and ny == ey:
            break
        if nx > 0:
            if prev[(nx - 1, ny)] is None and grid[ny][nx - 1] == '.':
                prev[(nx - 1, ny)] = (nx, ny)
                q.appendleft((nx - 1, ny))
        if nx < len(grid[nx]) - 1:
            if prev[(nx + 1, ny)] is None and grid[ny][nx + 1] == '.':
                prev[(nx + 1, ny)] = (nx, ny)
                q.appendleft((nx + 1, ny))
        if ny > 0:
            if prev[(nx, ny - 1)] is None and grid[ny - 1][nx] == '.':
                prev[(nx, ny - 1)] = (nx, ny)
                q.appendleft((nx, ny - 1))
        if ny < len(grid) - 1:
            if prev[(nx, ny + 1)] is None and grid[ny + 1][nx] == '.':
                prev[(nx, ny + 1)] = (nx, ny)
                q.appendleft((nx, ny + 1))
    
    if prev[(ex, ey)] is None:
        return None
    
    path = []
    (nx, ny) = (ex, ey)
    while (nx, ny) != (sx, sy):
        path.insert(0, (nx, ny))
        (nx, ny) = prev[(nx, ny)]
    path.insert(0, (sx, sy))
    assert (nx, ny) == (sx, sy)
    return path


def pairwise(stuff):
    return zip(stuff[:-1], stuff[1:])


def pathfindstr(grid, sx, sy, ex, ey):
    p = pathfind(grid, sx, sy, ex, ey)
    if p is None:
        return None
    moves = b""
    for ((sx, sy), (ex, ey)) in pairwise(p):
        if ex == sx - 1:
            moves += b"a"
        if ex == sx + 1:
            moves += b"s"
        if ey == sy - 1:
            moves += b"r"
        if ey == sy + 1:
            moves += b"w"
    return moves
