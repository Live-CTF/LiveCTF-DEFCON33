import gdb

# Make breakpoint pending on future shared library load?
gdb.execute("set breakpoint pending on")

# Type <RET> for more, q to quit, c to continue without paging
gdb.execute("set pagination off")

gdb.execute("starti")

for j in range(1, 100):
    for c in range(0x21, 0x7F):
        func_name = "func_" + (chr(c) * j)
        gdb.execute(f"b {func_name}")
    # func_name = "func_" + ("_" * j)
    # func_name = "func_" + ("-" * j)
    # func_name = "func_" + ("{" * j)
    # func_name = "func_" + ("}" * j)
    # for i in range(26):
    #     func_name = "func_" + (chr(ord("A") + i) * j)
    #     gdb.execute(f"b {func_name}")
    #     func_name = "func_" + (chr(ord("a") + i) * j)
    #     gdb.execute(f"b {func_name}")

with open("result.txt", "w") as f_out:
    while True:
        gdb.execute("continue")

        inferior = gdb.selected_inferior()
        if not inferior.is_valid() or inferior.pid == 0:
            break

        line = gdb.execute("x/1i $rip", to_string=True)
        func_name = line.split("<")[1].split(">")[0]
        if "+" in func_name:
            func_name = func_name.split("+")[0]
        print(func_name[5])
        f_out.write(func_name[5])
gdb.execute("quit")
