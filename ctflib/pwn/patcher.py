from pwnlib.elf import ELF

FUNCTIONS_TO_DISABLE = ["alarm", "sleep", "usleep"]


def patch(e: ELF, new_path=False) -> None:
    """
    Patches binary to disable functions that would hinder functionality
    """
    for func in FUNCTIONS_TO_DISABLE:
        if func in e.sym:
            e.asm(e.sym[func], "ret")
    e.save(e.path + (".new" if new_path else ""))


def is_patchable(e: ELF) -> bool:
    """
    Returns True if the binary has functions that can be disabled
    """
    return any(func in e.sym for func in FUNCTIONS_TO_DISABLE)
