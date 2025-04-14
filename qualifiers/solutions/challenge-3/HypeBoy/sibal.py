#!gdb -x
import gdb
from subprocess import check_output as co
import re


funcs = co('nm elf', shell=True).decode().splitlines()

table = {}
for line in funcs:
    if 'func_' not in line:
        continue

    addr, name = line.split()[::2]

    if 'func_' + name[-1] * 10 == name:
        addr = int(addr, 16)
        table[addr] = name

gdb.execute('file elf')
gdb.execute('start')

lines = gdb.execute('x/100i $rip', to_string=True).splitlines()

for i in table:
    gdb.execute(f'b *{table[i]}')

gdb.execute('c')
pwd = ''
try:
# if 1:
    while 1:
        x = gdb.execute('x/4i $rip', to_string=True)
        print(x)
        print(re.findall(r'<func_(.)', x))
        pwd += re.findall(r'<func_(.)', x)[0]
        gdb.execute('c')
except:
    pass

# print(pwd)
pwd = f'PASS{{{pwd[4:]}}}'
print(pwd)

gdb.execute('q')