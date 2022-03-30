from .buffer_overflow import *
from .elf import *
from .format_string import *
from .libc import *
from .util import *
from .func_gen import gen_funcs, gen_func
from .crand import CRand

pack = p64 if context.bits == 64 else p32
unpack = u64 if context.bits == 64 else u32

r = None
p = None
s = lambda x: (r if r is not None else p).send(x)
sl = lambda x: (r if r is not None else p).sendline(x)
sla = lambda x, y: (r if r is not None else p).sendlineafter(x, y)

rl = lambda: (r if r is not None else p).recvline()
rlb = lambda: (r if r is not None else p).recvlineb()
ru = lambda x: (r if r is not None else p).recvuntil(x)
rcb = lambda x: (r if r is not None else p).recvb(x)

inter = lambda: (r if r is not None else p).interactive()
