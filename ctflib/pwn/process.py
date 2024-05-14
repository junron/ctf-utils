from subprocess import PIPE, STDOUT

import pwnlib
from pwnlib import gdb
from pwnlib.timeout import Timeout
from pwnlib.tubes.process import PTY

from .util import get_pie_base


class Process(pwnlib.tubes.process.process):
    def __init__(self, argv=None,
                 shell=False,
                 executable=None,
                 cwd=None,
                 env=None,
                 stdin=PIPE,
                 stdout=PTY,
                 stderr=STDOUT,
                 close_fds=True,
                 preexec_fn=lambda: None,
                 raw=True,
                 aslr=None,
                 setuid=None,
                 where='local',
                 display=None,
                 alarm=None,
                 decompiler_ip=None,
                 *args,
                 **kwargs
                 ):
        super(Process, self).__init__(*args, **kwargs)
        self.Gdb = None
        self.decompiler_ip = decompiler_ip

    def breakpoint(self: pwnlib.tubes.process, address: int, Gdb: pwnlib.gdb.Gdb = None, block=False) -> pwnlib.gdb.Gdb:
        # probably PIE
        if address < 0x10000:
            pie_base = get_pie_base(self.pid)
            # Almost definitely PIE
            if pie_base > address:
                address += pie_base
        if Gdb is None:
            if self.Gdb:
                Gdb = self.Gdb
                Gdb.Breakpoint(f"*{hex(address)}")
            else:
                decompiler_attach_string = ""
                if self.decompiler_ip:
                    decompiler_attach_string = f"decompiler connect ida --host {self.decompiler_ip} --port 3662\n"
                pid, Gdb = gdb.attach(self, f"{decompiler_attach_string}break *{hex(address)}", api=True)
        else:
            Gdb.Breakpoint(f"*{hex(address)}")
        if block:
            Gdb.continue_and_wait()
        else:
            Gdb.continue_nowait()
        self.Gdb = Gdb
        return Gdb

    def brpt(self: pwnlib.tubes.process, address: int, Gdb: pwnlib.gdb.Gdb = None, block=False) -> pwnlib.gdb.Gdb:
        return self.breakpoint(address, Gdb, block)

    def deref_reg(self: pwnlib.tubes.process, reg: str, size: int, Gdb: pwnlib.gdb.Gdb = None) -> bytes:
        if Gdb is None:
            Gdb = self.Gdb
        addr = Gdb.parse_and_eval(reg).const_value()
        return self.leak(addr, size)

    def write_at_reg(self: pwnlib.tubes.process, reg: str, data: bytes, Gdb: pwnlib.gdb.Gdb = None) -> None:
        if Gdb is None:
            Gdb = self.Gdb
        addr = Gdb.parse_and_eval(reg).const_value()
        return self.writemem(addr, data)

    def send(self, data):
        # fix bug https://github.com/microsoft/python-type-stubs/issues/203
        if 1 == 1:
            super().send(data)

    def sendline(self, line=b''):
        # fix bug https://github.com/microsoft/python-type-stubs/issues/203
        if 1 == 1:
            super().sendline(line)

    def sendlineafter(self, delim, data, timeout=Timeout.default) -> bytes:
        # fix bug https://github.com/microsoft/python-type-stubs/issues/203
        if 1 == 1:
            return super().sendlineafter(delim, data, timeout)
