import textwrap

from ctflib.pwn import *
from ctflib.pwn.patcher import is_patchable, patch


def generate_template(remote_conn: str, decompiler_ip: str):
    # Detect ELF from current files
    elfs = []
    for file in os.listdir():
        # Check if file is an ELF
        if "ELF" in os.popen("file " + file).read():
            elfs.append(ELF(file, checksec=False))

    main_elf = None
    libc = None
    ld = None
    for elf in elfs:
        os.system("chmod +x " + elf.path)
        # Shared objects are probably not the main ELF
        if ".so" in elf.path:
            print("Detected shared object: " + elf.path)
            if "libc" in elf.path:
                libc = os.path.relpath(elf.path)
            elif "ld" in elf.path:
                ld = os.path.relpath(elf.path)
            continue
        # Ignore core files
        if os.path.basename(elf.path) == "core":
            continue
        if "patched" in os.path.basename(elf.path):
            main_elf = elf
            continue
        if main_elf is not None:
            print("Warning: detected multiple ELFs", main_elf.path)
        main_elf = elf

    context.binary = main_elf
    elf_sec = ELFSec.get_sec(main_elf)
    elf_name = os.path.relpath(main_elf.path)
    template = textwrap.dedent(f"""
    from ctflib.pwn import *

    e = ELF("{elf_name}")
    {'libc = ELF("' + libc + '", checksec=False)' if libc is not None else '# libc = ELF("", checksec=False)'}
    {'ld = ELF("' + ld + '", checksec=False)' if ld is not None else '# ld = ELF("", checksec=False)'}
    context.binary = e
    #context.terminal = ['tmux', 'splitw', '-h']

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

    def setup():
        p = process(decompiler_ip="{decompiler_ip}")
        # p = remote("{remote_conn}")
        return p
    
    rop = ROP(e)
    rop2 = ROP(e)

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
    if is_patchable(main_elf):
        if input(f"{elf_name} contains sleep or alarm functions. Patch away? [y/N]").strip().lower() == "y":
            patch(main_elf)
            print("Patched!")
    with open("solve.py", "w") as f:
        f.write(template)
    print("Generated solve.py")
