from pwn import *
import angr
import claripy
import sys
import struct
from capstone import *
import logging
logging.getLogger("angr").setLevel(logging.CRITICAL)
logging.getLogger("pwnlib").setLevel(logging.CRITICAL)
logging.getLogger("pwn").setLevel(logging.CRITICAL)


context.arch = 'amd64'



def solve_small(elf, sh_len):
	filename = elf
	elf = ELF(filename)
	proj = angr.Project(filename, auto_load_libs=False, main_opts={"base_addr": 0})  # , selfmodifying_code=True)

	input_str = claripy.BVS("input", 8 * 0x100)
	chars = input_str.chop(8)


	initial_state = proj.factory.entry_state(
		add_options={
			# angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
			# angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
			# angr.options.DOWNSIZE_Z3,
			# angr.options.SIMPLIFY_CONSTRAINTS,
			# angr.options.SIMPLIFY_EXPRS,
			# angr.options.LAZY_SOLVES,
			# angr.options.UNICORN,
			# angr.options.SUPPORT_FLOATING_POINT
		}
	)

	initial_state.regs.rdi = initial_state.regs.rsp + 0x100
	initial_state.memory.store(initial_state.regs.rdi, input_str)

	sim = proj.factory.simgr(initial_state)


	while sim.active:
		sim.explore(find=[0x401000+sh_len - 1], n=1)  # , step_func=drop_useless)
		# print(sim.active)
		if sim.found:
			break

	if not sim.found:
		print("No solution found")
		return

	sim.one_found.add_constraints(sim.one_found.regs.rax == 1)
	return sim.one_found.solver.eval_upto(input_str, 1, cast_to=bytes)


def biondo(path):
	with open(path, 'rb') as f:
		data = f.read()

	e = ELF(path, checksec=False)

	md = Cs(CS_ARCH_X86, CS_MODE_64)

	o = 6
	while True:
		o = data.index(b'\x48\x87\xE3\xC3', o+1)
		if data[o:o+4] == b'\x48\x87\xE3\xC3':
			lea = data[o-7:o]
			if lea[:3] == b'\x48\x8d\x1d':
				chain_virt_off = o + struct.unpack('<i', lea[3:])[0]
				s = e.get_segment_for_address(chain_virt_off)
				chain_off = chain_virt_off - s['p_vaddr'] + s['p_offset']
				print(f'Chain @ 0x{chain_off:x}')
				break



	bodies = []

	done = False
	off = chain_off
	while not done:
		gadget_off, = struct.unpack('<Q', data[off:off+8])
		#print(hex(gadget_off))

		assert data[gadget_off:gadget_off+3] == b'\x48\x87\xe3'

		body = b''
		o = gadget_off + 3
		while True:
			if data[o:o+4] == b'\x48\x87\xe3\xc3':
				break
			insn = next(md.disasm(data[o:o+20], o))
			body += data[o:o+insn.size]
			if insn.mnemonic == 'ret':
				done = True
				break
			o += insn.size

		#print(body)
		bodies.append(body)

		off += 8


	return b"".join(bodies)



def solve(path):
	assembly = biondo(path)
	small = make_elf(assembly)
	with open("/tmp/small", "wb") as f:
		f.write(small)
	os.system("chmod +x /tmp/small")

	sol = solve_small("/tmp/small", len(assembly))[0]
	# print(sol)
	return sol.rstrip(b"\x00")


var = os.getenv("DEBUGINFOD_URLS")

# binary_name = "challenge_1"
# exe  = ELF(binary_name, checksec=True)
# context.binary = exe

ru	= lambda *x: r.recvuntil(*x)
rl	= lambda *x: r.recvline(*x)
rc	= lambda *x: r.recv(*x)
sla = lambda *x: r.sendlineafter(*x)
sa	= lambda *x: r.sendafter(*x)
sl	= lambda *x: r.sendline(*x)
sn	= lambda *x: r.send(*x)

if var is None:
	HOST = os.environ.get("HOST", "localhost")
	PORT = 31337
	r = connect(HOST, int(PORT))
elif args.GDB:
	r = gdb.debug(f"./{binary_name}", """
		c
	""", aslr=False)
else:
	r = process(f"./{binary_name}")

for i in range(20):
	ru(b"Crackme: ")
	file = b64d(rl())
	with open("/tmp/bin", "wb") as f:
		f.write(file)
	
	solution = solve("/tmp/bin")

	print(solution)
	ru(b": ")
	sl(solution)



if var is None:
	# r.sendline(b'./submitter')
	print(r.recvall(timeout=10))
else:
	r.interactive()
