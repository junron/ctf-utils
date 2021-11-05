from pwn import *

from ctflib.pwn.util import get_pie_base


def get_section_address(elf, section_name):
    possible = [x for x in elf.sections if x.name == section_name]
    if not possible:
        raise Exception(f"{section_name} not found")
    addresses = [x for x in elf.search(possible[0].data())]
    if len(addresses) > 1:
        print("Warning: Multiple sections contain same data found")
    return addresses[0]


def debug(binary, addr, pre=None):
    if binary.pie:
        io = gdb.debug(binary.path, 'b _start', api=True, level="error")
        g = io.gdb
        pid = g.selected_inferior().pid
        text_base = get_pie_base(pid)
        g.continue_and_wait()
        if pre is not None:
            pre(io)
        g.execute("b *{}".format(hex(addr + text_base)))
        g.continue_and_wait()
        return io, g
    else:
        io = gdb.debug(binary.path, "b *{}".format(hex(addr)), api=True, level="error")
        g = io.gdb
        g.continue_and_wait()
        return io, g
