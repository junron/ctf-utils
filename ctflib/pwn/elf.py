def get_section_address(elf, section_name):
    possible = [x for x in elf.sections if x.name == section_name]
    if not possible:
        raise Exception(f"{section_name} not found")
    addresses = [x for x in elf.search(possible[0].data())]
    if len(addresses) > 1:
        print("Warning: Multiple sections contain same data found")
    return addresses[0]
