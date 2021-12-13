import textwrap
from typing import List

from pwn import *

from ctflib.pwn import SetupFunction


def write_source(func: str, filename: str):
    source = open(filename, "r").read()
    target = "'''\ngen_func\n'''"
    assert target in source, "Gen func target not found"
    source = source.replace(target, target + "\n" + func)
    open(filename, "w").write(source)


def gen_func(gen_str: str, setup: SetupFunction):
    log_level = context.log_level
    context.log_level = 'critical'
    p = setup()
    name = gen_str.split(".")[0]
    params = []
    code = ""
    for item in gen_str.split(".")[1:]:
        recv = p.clean().decode().strip().split("\n")[-1]
        recv = recv.replace('\'', '\\\'')
        code += f"p.recvuntil('{recv}')\n"
        try:
            int(item)
            code += f"p.sendline('{item}')\n"
            p.sendline(str(item))
        except ValueError:
            # Not constant
            if "'" not in item:
                param, type = item.split(":")
                val = None
                if "=" in type:
                    type, val = type.split("=")
                if type == "int":
                    code += f"p.sendline(str({param}))\n"
                else:
                    code += f"p.sendline({param})\n"
                params.append((param, type))
                if val is None:
                    if type == "int":
                        p.sendline("10")
                    else:
                        p.sendline("a")
                else:
                    p.sendline(val)
            else:
                code += f"p.sendline({item})\n"
                p.sendline(eval(item))
    code = textwrap.indent(code, "    ")
    context.log_level = log_level
    new_func = f"def {name}({', '.join(f'{p}: {t}' for p, t in params)}):\n{code}"
    return new_func

def gen_funcs(gen_strs: List[str], setup: SetupFunction, filename: str):
    funcs = []
    for gen_str in gen_strs:
        funcs.append(gen_func(gen_str, setup))
    write_source("\n\n".join(funcs), filename)
