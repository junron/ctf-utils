import textwrap
from ctflib.pwn import *
import re

QUIT_WORD = b"quit"
GET_STR = b"get_this"

e = ELF(sys.argv[1])
context.binary = e

p = process()


def can_be_int(x):
    try:
        int(x)
        return True
    except ValueError:
        return False


def remove_ansi(x: bytes):
    ansi_escape = re.compile(b'(\x9B|\x1B\[)[0-?]*[ -\\/]*[@-~]')
    return ansi_escape.sub(b'', x)


def make_ident(x: bytes):
    x = remove_ansi(x)
    x = re.sub(b"^\\W+", b"", x)
    x = re.sub(b"\\W+$", b"", x)
    x = re.sub(b"\\W", b"_", x).decode()
    return re.sub(r"^[^A-Za-z_]", "", x).lower()


def get_last_nonempty(lines: List[bytes]):
    lines = [line.strip() for line in lines if line.strip()]
    return lines[-1]


@dataclass
class InputPrompt:
    marker: bytes
    input: bytes
    input_type: str

    def make_arg_str(self):
        return f"{make_ident(self.marker)}: {self.input_type}"

    def make_input_code(self):
        name = make_ident(prompt.marker)
        if self.input_type == "int":
            return f"    p.sendlineafter({repr(prompt.marker)}, str({name}))\n"
        return f"    p.sendlineafter({repr(prompt.marker)}, {name})\n"


@dataclass
class OutputPrompt:
    marker: bytes


outputs = []
prompts: List[InputPrompt | OutputPrompt] = []

while True:
    out = p.clean()
    if GET_STR in out:
        prompts.append(OutputPrompt(out[:out.index(GET_STR)]))
    lines = out.split(b"\n")
    outputs.append(out)
    try:
        print(out.decode(), end="")
    except UnicodeDecodeError:
        print(out, end="")
    inp = input().encode()
    if inp.strip() == QUIT_WORD:
        break
    p.sendline(inp.strip())
    type = "int" if can_be_int(inp) else "bytes"
    prompts.append(InputPrompt(get_last_nonempty(lines), inp, type))

# Menu is the first marker that appears more than once
markers = [prompt.marker for prompt in prompts]
menu_marker = [marker for marker in markers if markers.count(marker) > 0][0]

# Get the second one to remove any unnecessary junk between menus
menu = [output for output in outputs if menu_marker in output][1]

menu = menu.split(menu_marker)[-2]

menu_options = {}

# Break raw prompts into menus
current_menu_option = None
for prompt in prompts:
    marker = prompt.marker
    if marker == menu_marker:
        menu_options[prompt.input] = []
        current_menu_option = prompt.input
    elif current_menu_option is not None:
        menu_options[current_menu_option].append(prompt)
    else:
        print("Not implemented yet")
        exit(-1)

out = ""

out += '"""'
out += remove_ansi(menu).decode()
out += '"""\n\n\n'

for marker, prompts in menu_options.items():
    args_str = ", ".join(["p"] + [prompt.make_arg_str() for prompt in prompts if isinstance(prompt, InputPrompt)])
    out += textwrap.dedent(
        f"""
        def action{make_ident(b'_' + marker)}({args_str}):
            p.sendafter({repr(menu_marker)}, {repr(marker)})
        """
    )

    has_result = False
    for prompt in prompts:
        if isinstance(prompt, InputPrompt):
            out += prompt.make_input_code()
        else:
            out += f"    p.recvuntil({repr(prompt.marker)})\n"
            out += f"    result = p.recvline()\n"
            has_result = True
    if has_result:
        out += f"    return result\n"

print()
print()
print()
print(out)
