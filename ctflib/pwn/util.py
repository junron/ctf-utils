import os
from binascii import a2b_hex
from typing import Union


def decode_to_ascii(input: Union[str, int, bytes]) -> bytes:
    if type(input) == int:
        input = hex(input)
    if type(input) == bytes:
        input = input.decode("utf-8")
    if input[:2] == "0x":
        input = input[2:]
    return a2b_hex(input)[::-1]


def get_pie_base(pid: int) -> int:
    return int(os.popen("pmap {}| awk '{{print $1}}'".format(pid)).readlines()[1], 16)
