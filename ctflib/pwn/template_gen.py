import textwrap

from ctflib.pwn import *


def generate_template(remote_conn: str):
    # Detect ELF from current files
    elfs = []
    for file in os.listdir():
        # Check if file is an ELF
        if "ELF" in os.popen("file " + file).read():
            elfs.append(ELF(file, checksec=False))

    mainElf = None
    for elf in elfs:
        os.system("chmod +x " + elf.path)
        # Shared objects are probably not the main ELF
        if "so" in elf.path:
            print("Detected shared object: " + elf.path)
            continue
        if mainElf is not None:
            print("Warning: detected multiple ELFs", mainElf.path)
        mainElf = elf

    context.binary = mainElf
    elf_sec = ELFSec.get_sec(mainElf)
    template = textwrap.dedent(f"""
    from ctflib.pwn import *
    
    '''
    gen_func
    '''

    e = ELF("{mainElf.path}")
    context.binary = e

    def setup():
        p = e.process()
        # p = remote("{remote_conn}")
        return p

    '''
    Bits: {context.bits}

    Stack:
    Canary: {'Enabled' if elf_sec.canary else 'Disabled'}
    PIE: {'Enabled' if elf_sec.pie else 'Disabled'}
    Executable stack: {'Yes' if elf_sec.stack_exec else 'No'}

    Writable segments:
    GOT: {'Yes' if elf_sec.got_writable else 'No'}
    fini_array: {'Yes' if elf_sec.fini_array_writable else 'No'}
    '''
    
    '''
    gen_funcs([""], setup, __file__)
    '''

    if __name__ == '__main__':
        # offset = find_bof_offset(setup)
        p = setup()

        # libc_base = get_libc_base(p.pid)
        # e.address = get_pie_base(p.pid)


        # Happy pwning!

        p.interactive()
    """)
    # Check if solve.py exists
    if os.path.exists("solve.py"):
        if input("solve.py already exists. Overwrite? [y/N] ").strip().lower() != "y":
            exit()
    with open("solve.py", "w") as f:
        f.write(template)
    print("Generated solve.py")
