import os
import string
from binascii import a2b_hex
from typing import Union, Callable, Tuple
import pwnlib.tubes.process
from pwnlib.context import context

SetupFunction = Callable[[], pwnlib.tubes.process.process]
SendFunction = Callable[[str|bytes], Tuple[str|bytes, pwnlib.tubes.process.process]]


def decode_to_ascii(input: Union[str, int, bytes]) -> bytes:
    if type(input) == int:
        input = hex(input)
    if type(input) == bytes:
        input = input.decode("utf-8")
    if input[:2] == "0x":
        input = input[2:]
    return a2b_hex(input)[::-1]


def get_pie_base(pid: int) -> int:
    binary_name = context.binary.path.split("/")[-1]
    data = [x for x in os.popen(f"pmap {pid}").readlines() if binary_name in x and x.startswith("0")]
    if data:
        return int(data[0].split(" ")[0], 16)


def get_libc_base(pid: int) -> int:
    data = [x for x in os.popen(f"pmap {pid}").readlines() if "libc" in x]
    if data:
        return int(data[0].split(" ")[0], 16)


def get_ld_base(pid: int) -> int:
    data = [x for x in os.popen(f"pmap {pid}").readlines() if "ld" in x]
    if data:
        return int(data[0].split(" ")[0], 16)


# Parses `connect_str`, which is in one of the following forms:
# <host>:<port>
# <host> <port>
# nc <host <port>
def remote(connect_str: str) -> pwnlib.tubes.remote:
    connect_str.strip()
    if connect_str.startswith("nc"):
        connect_str = connect_str[2:].strip()
    if ":" in connect_str:
        host, port = connect_str.split(":")
    else:
        host, port = connect_str.split()
    return pwnlib.tubes.remote.remote(host.strip(), int(port.strip()))

def find_nonascii(x:bytes, length:int):
    for i,a in enumerate(x):
        if a not in string.printable.encode():
            return x[i:i+length]

def find_leak(x:bytes, length:int):
    if b"\x7f" not in x:
        return find_nonascii(x, length)
    i = x.index(b"\x7f")
    return x[i-length+1:i+1]

def find_hex(x:bytes|str, length: int):
    if type(x) is str:
        x = x.encode()
    hexdigits = b"abcdefABCDEF0123456789"
    if b"0x" in x:
        i = x.index(b"0x")
        return int(x[i+2:i+length+2],16)
    else:
        i = 0
        while i < len(x)-length+1:
            for j in range(i, i+length):
                if x[j] not in hexdigits:
                    break
            else:
                return int(x[i:i+length],16)
            i += 1

def cyberthon_flag(p):
    p.sendline("cat /home/*/*.txt")
    x = p.clean()
    print(x)
    return x
