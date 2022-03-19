from pwnlib.elf import ELF


def patch_alarms(e: ELF, new_path=False) -> None:
    if "alarm" in e.sym:
        e.asm(e.sym.alarm, 'ret')
    e.save(e.path + (".new" if new_path else ""))
