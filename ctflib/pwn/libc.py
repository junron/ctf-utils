import os
import urllib.request
from typing import List

import requests
from pwnlib.elf import ELF


def fetch_libc_ver(addr, func="_IO_puts", include_ret=False, raw=False):
    resp = requests.post("https://libc.rip/api/find", json={
        "symbols": {
            func: hex(addr)
        }
    }).json()
    if raw:
        return resp
    if include_ret:
        return [(x["id"], int(x["symbols"]["__libc_start_main_ret"], 16)) for x in resp]
    else:
        return [x["id"] for x in resp]


def fetch_libc_ret(addr):
    return fetch_libc_ver(addr, "__libc_start_main_ret", True)


def download_libc(version, download_location="/home/kali/Desktop/ctf-stuff/libc-cache"):
    if not os.path.isdir(download_location):
        download_location = "."
    out_file = f"{download_location}/{version}.so"
    if os.path.isfile(out_file):
        return out_file
    print("Downloading libc", version)
    url = f"https://libc.rip/download/{version}.so"
    urllib.request.urlretrieve(url, out_file)
    return out_file


def get_one_gadgets(elf: ELF) -> List[int]:
    output = os.popen(f"one_gadget -s echo {elf.path}").readlines()
    return [int(line) for line in output if "Try" not in line]
