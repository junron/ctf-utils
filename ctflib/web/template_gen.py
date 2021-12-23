import os
import textwrap

from ctflib.web import context
from ctflib.web.backend import AsyncBackend
from ctflib.web.recon import sus_files, basic_recon


def generate_template(url: str, name: str):
    template = textwrap.dedent(f"""
    from ctflib.web import *
    context.backend = AsyncBackend()
    context.url = "{url}"

    '''
    Sus files:
    """)
    context.backend = AsyncBackend()
    context.url = url
    for file in sus_files():
        template += f" - {file}\n"
    template += "'''\n\n"
    forms = basic_recon().forms
    empty = "''"
    for form in forms:
        template += f"form = {form}\n"
        template += f"form.attack({', '.join(x + '=' + empty for x in form.inputs)})\n"
    out = f"{name}.py"
    # Check if solve.py exists
    if os.path.exists(out):
        if input(f"{out} already exists. Overwrite? [y/N] ").strip().lower() != "y":
            exit()
    with open(out, "w") as f:
        f.write(template)
    print(f"Generated {out}")

