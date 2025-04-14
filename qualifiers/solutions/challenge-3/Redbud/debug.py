import gdb

gdb.execute("file /tmp/challenge")
gdb.execute(open("script").read())
while True:
    try:
        gdb.execute("c")
    except gdb.error as e:
        break
gdb.execute("q")
