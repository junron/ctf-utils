from pwnlib.elf.corefile import Coredump
from pwnlib.util.cyclic import cyclic, cyclic_find
from pwnlib.util.packing import p64, p32


def get_padding_length(p, address_size=8):
    payload = cyclic(1000, n=address_size)
    p.sendline(payload)
    p.wait()
    core = Coredump("./core")
    rbp = core.rbp if address_size == 8 else core.ebp
    assert p64(rbp) in payload if address_size == 8 else p32(rbp) in payload
    rbp = p64(rbp) if address_size == 8 else p32(rbp)
    return cyclic_find(rbp, n=address_size) + address_size
