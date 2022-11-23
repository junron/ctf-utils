from typing import List


def build_substitution_table(out: bytes, inp: bytes = bytes(range(256))) -> List[int]:
    o = [None for _ in range(max(inp) + 1)]
    for i, x in enumerate(out):
        o[inp[i]] = x
    assert invert_substitution(out, o) == inp
    return o


def invert_substitution(desired_out: bytes, sub_table: List[int]) -> bytes:
    return bytes([sub_table.index(x) for x in desired_out])


def build_mixer(out: bytes) -> List[int]:
    return [out.index(x) for x in range(len(out))]


def invert_mixer(desired_out: bytes, mix_table: List[int]) -> bytes:
    return bytes([desired_out[x] for x in mix_table])
