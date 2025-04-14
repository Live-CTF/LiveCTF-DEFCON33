# Usage: gdb -x this_script.gdb ./executable
set pagination off
set height 0
set width 0
set logging overwrite on
set logging file gdb_trace.log
set logging on

set disable-randomization off

echo \n[+] Starting function call trace for CTF challenge\n\n

echo [+] Dumping all functions...\n
python

import re
import gdb

call_order = []

def find_target_functions():
    output = gdb.execute("info functions", to_string=True)

    target_funcs = []

    for line in output.splitlines():
        if "func_" in line:
            parts = line.split()
            for part in parts:
                if "func_" in part:
                    func_name = part.strip()
                    func_name = re.sub(r'[:;,()].*$', '', func_name)

                    if re.fullmatch(r"func_([ -~])\1{9}", func_name):
                        # print("uuuu")
                        # print(func_name)
                        target_funcs.append(func_name)

    print(f"[+] Found {len(target_funcs)} target functions")
    for i, func in enumerate(target_funcs):
        print(f"  {i+1}. {func}")

    return target_funcs

def setup_breakpoints():
    funcs = find_target_functions()

    print(funcs)

    if not funcs:
        print("[!] No matching functions found. Trying alternative method...")
        try:
            gdb.execute("rbreak func_.*")
            print("[+] Set breakpoints on all func_* functions")
        except gdb.error as e:
            print(f"[!] Error setting breakpoints: {e}")
        return False

    for func in funcs:
        try:
            bp = gdb.Breakpoint(func)
            bp.silent = True
            print(f"[+] Set breakpoint on {func}")
        except gdb.error as e:
            print(f"[!] Error setting breakpoint on {func}: {e}")

    return True

def handle_breakpoint(event):
    frame = gdb.selected_frame()
    func_name = frame.name()

    if func_name and func_name.startswith("func_"):
        char = func_name[5]

        call_order.append(char)
        print(f"[TRACE] Called: {func_name} (Character: {char})")

    gdb.execute("continue")
    return False

setup_breakpoints()

gdb.events.stop.connect(handle_breakpoint)

def show_results():
    if call_order:
        print("\n[+] Function call order:")
        for i, char in enumerate(call_order):
            print(f"  {i+1}. func_*{char}* (Character: {char})")

        flag = ''.join(call_order)
        print(f"\n[+] FLAG: {flag}")
    else:
        print("\n[!] No matching functions were called during execution")
end

echo \n[+] Running the program...\n
run

python
show_results()
end

set logging off
echo \n[+] Execution trace saved to gdb_trace.log\n

