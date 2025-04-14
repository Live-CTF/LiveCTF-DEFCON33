import gdb

import os

gdb.execute("set debuginfod enabled off")
gdb.execute("file /tmp/challenge")

for sym in os.environ.get("FUNCTIONS", "").split("$"):
    gdb.execute(f"b {sym}")

gdb.execute("r")

while True:
    try:
        gdb.execute("c")
    except:
        break

gdb.execute("q")
