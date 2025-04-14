from pwn import *
import os
import sys
import angr
import claripy
import multiprocessing
import functools
import base64

# https://book.hacktricks.xyz/reversing-and-exploiting/reversing-tools-basic-methods/angr/angr-examples
# https://hitcon.org/2016/CMT/slide/day1-r1-a-1.pdf
# https://docs.angr.io/en/latest/examples.html
# https://github.com/angr/angr-doc/blob/master/docs/more-examples.md
# https://docs.angr.io/en/latest/advanced-topics/claripy.html

context.arch='amd64'

class Angr:
    ZERO_FILL_OPTIONS = {angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY}
    DEFAULT_STACK = 0x7ffabcdef000
    DEFAULT_RET = 0xdeadbeef87
    def __init__(self, executable=None, base_addr=0, load_libs=False, elf=None, p=None, initstate=None, overwrite_endian=None):
        if executable is not None:
            assert os.path.exists(executable)
            self.elf=ELF(executable)
            self.p=angr.Project(executable, auto_load_libs=load_libs, main_opts={'base_addr': base_addr})
            self.initstate=self.p.factory.entry_state()
        else:
            assert elf is not None and p is not None and initstate is not None
            self.elf=elf
            self.p=p
            self.initstate=initstate
        self.overwrite_endian=overwrite_endian
    
    @property
    def endian(self):
        return self.elf.endian if self.overwrite_endian is None else self.overwrite_endian

    @property
    def endness(self):
        return self.p.arch.memory_endness

    def symbol(self, name):
        return self.elf.symbols.get(name, None)

    def function(self, name):
        return self.elf.functions.get(name, None)

    def value_to_bits(self, value, size=0):
        if type(value)==int:
            if size==0:
                size=8
            return claripy.BVV(value,size*8)
        elif type(value)==list:
            if size==0:
                size=8
            val=0
            for v in value[::-1]:
                val=(val<<(size*8))|v
            return claripy.BVV(val,size*len(value)*8)
        elif type(value)==str or type(value)==bytes:
            if type(value)==str:
                value=value.encode()
            if size>0:
                assert len(value)<=size
                value=value.ljust(size, b'\x00')
            size=len(value)
            value=unpack(value,size*8,endianness=self.endian)
            return claripy.BVV(value,size*8)
        elif type(value)==float:
            if size==0:
                size=8
            assert size==4 or size==8
            return claripy.FPV(value,claripy.FSORT_DOUBLE if size==8 else claripy.FSORT_FLOAT)
        else:
            return value

    def bits_to_value(self, value, size=8, ctype=bytes):
        if ctype==int or ctype=='int':
            return value
        elif ctype==list or ctype=='list':
            ret=[]
            while value>0:
                ret.append(value&((1<<(size*8))-1))
                value>>=(size*8)
            return ret
        elif ctype==str or ctype=='str' or ctype==bytes or ctype=='bytes':
            value=pack(value,size*8,endianness=self.endian)
            if ctype==str or ctype=='str':
                value=value.decode()
            return value
        elif ctype==float or ctype=='float':
            assert size==4 or size==8
            value=claripy.BVV(value,size*8).raw_to_fp().concrete_value
            return value
        else:
            return value

    def evalinit(self, data, ctype=None):
        if ctype=='raw' or ctype==claripy or ctype=='claripy':
            return data
        value=self.initstate.solver.eval(data)
        return self.bits_to_value(value,size=data.size()//8,ctype=ctype)

    def read_init_memory(self, addr, size=8, ctype=None):
        # value=self.initstate.memory.load(addr,size,endness=self.endness).concrete_value
        data=self.initstate.memory.load(addr,size,endness=self.endness)
        return self.evalinit(data,ctype)

    def read_init_global(self, addr, size=8, ctype=None):
        return self.read_init_memory(addr,size)

    def read_global_elf(self, addr, size):
        pass

    def newstate(self, addr=None, args=None, zero_fill=False):
        if addr is None:
            return AngrState(self.p.factory.entry_state(args=args),self.elf,self.p,self.initstate,self.overwrite_endian)
        elif zero_fill:
            return AngrState(self.p.factory.blank_state(addr=addr,add_options=Angr.ZERO_FILL_OPTIONS),self.elf,self.p,self.initstate,self.overwrite_endian)
        else:
            return AngrState(self.p.factory.blank_state(addr=addr),self.elf,self.p,self.initstate,self.overwrite_endian)

    def fuzz(self, args=None):
        if args is not None:
            args=[self.elf.path]+args
        return self.newstate(args=args)

    def fuzzfunc(self, funcaddr, zero_fill=False):
        state=self.newstate(funcaddr, zero_fill=zero_fill)
        state.isfunc=True
        return state

    def fuzzfrom(self, addr, zero_fill=False):
        return self.newstate(addr, zero_fill=zero_fill)

class AngrState(Angr):
    def __init__(self, state, elf, p, initstate, overwrite_endian=None):
        super().__init__(elf=elf,p=p,initstate=initstate)
        self.startstate=state
        self.state=state.copy()
        self.sim=None
        self.allsolst=[]
        self.vars={}
        self.files={}
        self.isfunc=False
        self.overwrite_endian=overwrite_endian

    def fuzz(self, args=None):
        if args is not None:
            args=[self.elf.path]+args
        self.startstate=self.p.factory.entry_state(args=args)
        self.state=self.startstate.copy()
        self.isfunc=False

    def fuzzfunc(self, funcaddr, zero_fill=False):
        if zero_fill:
            self.startstate=self.p.factory.blank_state(addr=funcaddr,add_options=Angr.ZERO_FILL_OPTIONS)
        else:
            self.startstate=self.p.factory.blank_state(addr=funcaddr)
        self.state=self.startstate.copy()
        self.isfunc=True

    def fuzzfrom(self, addr, zero_fill=False):
        if zero_fill:
            self.startstate=self.p.factory.blank_state(addr=addr,add_options=Angr.ZERO_FILL_OPTIONS)
        else:
            self.startstate=self.p.factory.blank_state(addr=addr)
        self.state=self.startstate.copy()
        self.isfunc=False

    @property
    def regs(self):
        return self.state.regs

    def regname(self,name,size=0):
        if size==8:
            name='r'+name[1:]
        elif size==4:
            name='e'+name[1:]
        elif size==2:
            name=name[1:]
        return name

    def reg(self,name,size=0):
        name=self.regname(name,size)
        return getattr(self.state.regs,name)
    
    def setreg(self,name,value,size=0):
        name=self.regname(name,size)
        value=self.value_to_bits(value,size=size)
        return setattr(self.state.regs,name,value)
    
    def var(self,name):
        return self.vars.get(name, None)

    def newvar(self,size=64,name=None,vtype='BV'):
        if name is None:
            if vtype=='BV':
                return claripy.BVS('tmp',size)
                # return self.state.BVS('tmp',size)
            elif vtype=='float':
                return claripy.FPS('tmp',claripy.fp.FSORT_FLOAT)
            elif vtype=='double':
                return claripy.FPS('tmp',claripy.fp.FSORT_DOUBLE)
            elif vtype=='bool':
                return claripy.BoolS('tmp')
        else:
            if vtype=='BV':
                var=claripy.BVS(name,size)
                # var=self.state.BVS(name,size)
            elif vtype=='float':
                var=claripy.FPS(name,claripy.fp.FSORT_FLOAT)
            elif vtype=='double':
                var=claripy.FPS(name,claripy.fp.FSORT_DOUBLE)
            elif vtype=='bool':
                var=claripy.BoolS(name)
            self.vars[name]=var
            return var

    def newvalue(self,value,size=64,vtype='BV'):
        if vtype=='BV':
            return claripy.BVV(value,size)
        elif vtype=='float':
            return claripy.FPV(value,claripy.fp.FSORT_FLOAT)
        elif vtype=='double':
            return claripy.FPV(value,claripy.fp.FSORT_DOUBLE)
        elif vtype=='bool':
            return claripy.BoolV(value)

    # value0 and value1 must be claripy vars or values with the same type
    def newcond(self,condexpr,value1,value0):
        return claripy.If(condexpr,value1,value0)

    def concat(self, value1, value2):
        return claripy.Concat(value1,value2)
        # return value1.concat(value2)

    def satisfiable(self):
        return self.state.satisfiable()

    def eval(self, data, ctype=None):
        if ctype=='raw' or ctype==claripy or ctype=='claripy':
            return data
        value=self.state.solver.eval(data)
        return self.bits_to_value(value,size=data.size()//8,ctype=ctype)

    def evalall(self, obj, ctype=None, limit=10):
        values=self.state.solver.eval_upto(obj,limit)
        values=list(map(lambda value: self.bits_to_value(value,size=obj.size()//8,ctype=ctype), values))
        return values

    def evalmin(self, obj, ctype=None):
        value=self.state.solver.min(obj)
        return self.bits_to_value(value,size=obj.size()//8,ctype=ctype)

    def evalmax(self, obj, ctype=None):
        value=self.state.solver.max(obj)
        return self.bits_to_value(value,size=obj.size()//8,ctype=ctype)

    def readreg(self,name,ctype=None,size=None):
        reg=self.reg(name,size)
        return self.eval(reg,ctype)
    
    def readvar(self,name,ctype=None):
        var=self.var(name)
        return self.eval(var,ctype)
    
    def read_memory(self, addr, size=8, ctype=None):
        # value=self.state.memory.load(addr,size,endness=self.endness).concrete_value
        # return self.bits_to_value(value,size=size//8,ctype=ctype)
        data=self.state.memory.load(addr,size,endness=self.endness)
        return self.eval(data,ctype)

    def read_global(self, addr, size=8, ctype=None):
        return self.read_memory(addr,size)

    def read_file(self, filename, offset=0, size=None):
        if size is None:
            size=self.files[filename].size-offset
        return self.files[filename].load(offset,size)

    def write_memory(self, address, value, size=0):
        data=self.value_to_bits(value, size)
        self.state.memory.store(address,data,endness=self.endness)

    def write_global(self, addr, value, size=0):
        self.state.write_memory(self, address, value, size)

    @property
    def rsp(self):
        return self.readreg('rsp',int)

    @property
    def rbp(self):
        return self.readreg('rbp',int)

    def stack_push(self, value):
        value=self.value_to_bits(value,8)
        self.state.stack_push(value)
        return self.state.regs.rsp

    def stack_pop(self, value, ctype=None):
        return self.eval(self.state.stack_pop(),ctype)

    def readfd(self, fd, state=None):
        if state is None:
            state=self.state
        return state.posix.dumps(fd)

    def stdin(self, state=None):
        return self.readfd(sys.stdin.fileno(),state)

    def stdout(self, state=None):
        return self.readfd(sys.stdout.fileno(),state)

    def stderr(self, state=None):
        return self.readfd(sys.stderr.fileno(),state)

    # content must be claripy vars or values, can use claripy.Concat or self.concat to concat vars and/or values
    def setfile(self, filename, content=None, size=None):
        if type(content)==str:
            content=content.encode()
        if type(content)==bytes:
            content=self.value_to_bits(content, len(content))
        file=angr.storage.SimFile(filename,content=content,size=size)
        return self.state.fs.insert(filename,file)
    
    # hook a symbol (function), often used to bypass complex code with easy context
    # usage:
    # class CheckSecretHook(angr.SimProcedure):
    #  def run(self, strptr, length):
    #   guess=self.state.memory.load(strptr,length,endness=angrstate.endness)
    #   return claripy.If(guess==b'DEADBEEF', claripy.BVV(1,32), claripy.BVV(0,32))
    # angrstate.hook('check_secret',CheckSecretHook())
    # angrstate.hook(0x401234,CheckSecretHook())
    #
    # readintcnt=0
    # class ReadintHook(angr.SimProcedure):
    #  def run(self, addr):
    #   inputvar=angrstate.newvar(size=64,name=f'readint{readintcnt}')
    #   readintcnt+=1
    #   self.state.memory.store(addr,inputvar,endness=angrstate.endness)
    # angrstate.hook('readint',ReadintHook())
    def hook(self, func, funcobj):
        if type(func)==str:
            self.p.hook_symbol(func, funcobj)
        else:
            self.p.hook(func, funcobj)

    # often used in static compiled binary, as the original library functions are often complex
    # angrstate.hook_lib('malloc','libc','malloc')
    # angrstate.hook_lib(0x401234,'libc','printf')
    def hook_lib(self, func, lib, symbol):
        self.hook(func,angr.SIM_PROCEDURES[lib][symbol])

    # alternatively, directly replace [addr,addr+length] with specific hook function (length defaults to 0)
    # @angrstate.p.hook(0x401234, length=5) # call instruction has length 5
    # def hookfunc(state):
    #  guess=state.read_memory(state.regs.rdi,state.regs.rsi,ctype='raw')
    #  state.regs.eax=claripy.If(guess==b'DEADBEEF', claripy.BVV(1,32), claripy.BVV(0,32))

    def check_stdout_func(self, data):
        if type(data) is str:
            data=data.encode()
        def func(state):
            stdout=state.posix.dumps(sys.stdout.fileno())
            return data in stdout
        return func

    # veritesting: heuristically auto merge some branches to speedup while slightly reduce accuracy (only useful when there are too many branches)
    def explore(self, find=None, avoid=None, ret=None, veritesting=False, manual=False, hook=None, verbose=True, show_instr=False):
        if self.eval(self.regs.rsp) == 0:
            self.regs.rsp = self.DEFAULT_STACK
        if self.isfunc:
            self.stack_push(self.DEFAULT_RET)
            if find is None:
                if ret is None:
                    find=self.DEFAULT_RET
                else:
                    def findf(st):
                        if st.solver.eval(st.regs.rip)==self.DEFAULT_RET:
                            st.add_constraints(st.regs.rax==ret)
                            return st.satisfiable()
                        return False
                    find=findf
            else:
                addfindf=find
                find=lambda st:st.solver.eval(st.regs.rip)==self.DEFAULT_RET and addfindf(st)
            if avoid is None:
                avoid=self.DEFAULT_RET
            else:
                addavoidf=avoid
                avoid=lambda st:st.solver.eval(st.regs.rip)==self.DEFAULT_RET and addavoidf(st)
        if type(find)==str or type(find)==bytes:
            find=self.check_stdout_func(find)
        if type(avoid)==str or type(avoid)==bytes:
            avoid=self.check_stdout_func(avoid)
        assert find is not None
        if not manual:
            self.sim=self.p.factory.simgr(self.state,veritesting=veritesting)
            self.sim.explore(find=find,avoid=avoid)
        else:
            self.manual_explore(find=find, avoid=avoid, hook=hook, verbose=verbose, show_instr=show_instr)
        if not self.sim.found:
            return None
        self.allsolst=self.sim.found
        self.state=self.sim.found[0]
        return self.state

    # show_instr is much slower
    def manual_explore(self, find=None, avoid=None, hook=None, verbose=False, show_instr=False):
        if type(find)==int:
            findaddr=find
            find=lambda st: st.solver.eval(st.regs.rip)==findaddr
        if type(avoid)==int:
            avoidaddr=avoid
            avoid=lambda st: st.solver.eval(st.regs.rip)==avoidaddr
        self.sim=self.p.factory.simgr(self.state)
        print(f'simgr: {s.sim}, active: {s.sim.active}, errored: {s.sim.errored}, deadneded: {s.sim.deadended}')
        while True:
            self.sim.step(num_inst=1)
            self.sim.move(from_stash='active', to_stash='found', filter_func=find)
            if avoid is not None:
                self.sim.move(from_stash='active', to_stash='deadend', filter_func=avoid)
            if len(self.sim.found) or not len(self.sim.active):
                if verbose:
                    print(f'simgr: {s.sim}, active: {s.sim.active}, errored: {s.sim.errored}, deadneded: {s.sim.deadended}')
                break
            self.state=self.sim.active[0]
            if verbose:
                if show_instr:
                    rip=self.eval(self.regs.rip)
                    instr=disasm(s.read_memory(rip,16,ctype=bytes),vma=rip,byte=0,offset=0).split('\n')[0]
                    print(f'simgr: {s.sim}, active: {s.sim.active}, errored: {s.sim.errored}, deadneded: {s.sim.deadended}, instruction: {instr}')
                else:
                    print(f'simgr: {s.sim}, active: {s.sim.active}, errored: {s.sim.errored}, deadneded: {s.sim.deadended}')
            if hook is not None:
                hook(self)

    def getretv(self, size=8, ctype=None):
        data=self.reg('rax',size)
        return self.eval(data,ctype)

    def require_retv(self, value=0, size=8):
        self.state.add_constraints(self.reg('rax',size) == value)

    def add_constraints(self, expr):
        self.state.add_constraints(expr)
        # self.state.solver.add(expr)

def solve(exe):
    p=Angr(exe)
    s=p.fuzzfunc(0x131a)
    password=s.newvar(16*8)
    addr=0xaaaaaaaa
    s.write_memory(addr, password)
    s.write_memory(addr+16, b'\x00')
    s.setreg('rdi', addr)
    s.explore(ret=1)
    return s.eval(password,str)

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337

envs=os.environ.copy()
envs['FLAG']='flag{TEST}'
r = remote(HOST, int(PORT))

for i in range(20):
    print('Solving round', i)
    r.recvuntil(b'Crackme: ')
    binary=base64.b64decode(r.readline().strip())
    # print(binary)
    with open('chal','wb') as f:
        f.write(binary)
    ans=solve('chal')
    r.sendlineafter(b'Password: ', ans.encode())

r.interactive()
