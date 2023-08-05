from .buffer_overflow import *
from .elf import *
from .format_string import *
from .libc import *
from .util import *
from .func_gen import gen_funcs, gen_func
from .crand import CRand

del process
from .process import Process as process

from pwnlib.util.packing import pack as _pack
from pwnlib.util.packing import unpack as _unpack

__bad_chars = [b"\n", b" ", b"\t", b"\v", b"\f", b"\r"]


def check_bad_chars(x: bytes):
    for b in __bad_chars:
        if b in x:
            log.warn(f"{x} contains whitespace, which will interfere with scanf.")
            return


def p64(x: int) -> bytes:
    y = _pack(x, 64)
    check_bad_chars(y)
    return y


def p32(x: int) -> bytes:
    y = _pack(x, 32)
    check_bad_chars(y)
    return y


def u64(x: bytes) -> int:
    return _unpack(x, 64)


def u32(x: bytes) -> int:
    return _unpack(x, 32)


pack = p64 if context.bits == 64 else p32
unpack = u64 if context.bits == 64 else u32
