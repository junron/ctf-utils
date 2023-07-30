import os
import string
from binascii import a2b_hex
from typing import Union, Callable

import pwnlib.tubes.process
from pwnlib.context import context
from pwnlib.util.packing import unpack as _unpack

SetupFunction = Callable[[], pwnlib.tubes.process.process]
SendFunction = Callable[[pwnlib.tubes.process.process, str | bytes], str | bytes]


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


def find_nonascii(x: bytes, length: int):
    for i, a in enumerate(x):
        if a not in string.printable.encode():
            l = x[i:i + length]
            if len(l) != length:
                continue
            return l


def find_leak(x: bytes, length: int = 6) -> bytes | None:
    if b"\x7f" not in x:
        return find_nonascii(x, length)
    i = x.index(b"\x7f")
    l = x[i - length + 1:i + 1]
    if len(l) != length:
        return None
    return l


def find_leak64(x: bytes, length: int = 6) -> int | None:
    leak = find_leak(x, length)
    if leak is None:
        return leak
    return _unpack(leak + b"\0" * (8 - length), 64)


def find_hex(x: bytes, length: int | None = None) -> int | None:
    if type(x) is str:
        x = x.encode()
    hexdigits = b"abcdefABCDEF0123456789"
    if b"0x" in x:
        i = x.index(b"0x")
        x = x[i + 2:]
    i = 0
    hex_str = b""
    for i in range(len(x)):
        if x[i] not in hexdigits:
            break
        hex_str += bytes([x[i]])
        i += 1
        if i == length:
            break
    if length is not None and i < length:
        return None
    return int(hex_str, 16)


if __name__ == "__main__":
    assert find_hex(b"0x1337") == 0x1337
    assert find_hex(b"0x1337", 2) == 0x13
