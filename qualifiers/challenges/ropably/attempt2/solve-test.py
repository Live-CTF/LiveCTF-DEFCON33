#!/usr/bin/env python
# coding: utf-8
import angr
import claripy
import time

#compiled on ubuntu 18.04 system:
#https://github.com/b01lers/b01lers-ctf-2020/tree/master/rev/100_little_engine

def correct(state):
    try:
        return b'Yes' in state.posix.dumps(1)
    except:
        return False
def wrong(state):
    try:
        return b'No' in state.posix.dumps(1)
    except:
        return False

def main():
    #length of desired input is 75 as found from reversing the binary in ghidra
    #need to add 4 times this size, since the actual array is 4 times the size
    #1 extra byte for first input
    input_len = 16+1

    base_addr = 0x100000

    p = angr.Project('./program-plain', main_opts={'base_addr': base_addr}, auto_load_libs=True)
    flag_chars = [claripy.BVS('flag_%d' % i, 8) for i in range(input_len)]
    flag = claripy.Concat( *flag_chars + [claripy.BVV(b'\n')])

    # enable unicorn engine for fast efficient solving
    st = p.factory.entry_state(stdin=flag)

    #constrain to non-newline bytes
    #constrain to ascii-only characters
    for k in flag_chars:
        st.solver.add(k < 0x7f)
        st.solver.add(k > 0x20)

    # Construct a SimulationManager to perform symbolic execution.
    # Step until there is nothing left to be stepped.
    sm = p.factory.simulation_manager(st)
    sm.explore(find=correct, avoid=wrong)

    return sm.found[0].posix.dumps(0)

if __name__ == "__main__":
    before = time.time()
    print(main())
    after = time.time()
    print("Time elapsed: {}".format(after - before))
