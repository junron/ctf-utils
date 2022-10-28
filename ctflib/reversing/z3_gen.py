import textwrap
import os

def sym_str_template(length: int):
    template = textwrap.dedent(f"""
    from z3 import *
    from ctflib.reversing import *
    inp = [BitVec(f"x{{i}}", 8) for i in range({length})]
    
    def func(i):
        return i
        
    target_output = b""
    out = func(inp)
    
    sl = Solver()
    
    def char(x):
        sl.add(x >= 0x21)
        sl.add(x <= 0x7e)
    
    for i,x in enumerate(out):
        sl.add(x == target_output[i])
        # char(x)
        
    if sl.check() == sat:
        m = sl.model()
        b = []
        for x in inp:
            k = m.eval(x).as_long()
            b.append(k)
        print(bytes(b))
    else:
        print("Unsat")
    """)
    # Check if solve.py exists
    if os.path.exists("solve.py"):
        if input("solve.py already exists. Overwrite? [y/N] ").strip().lower() != "y":
            exit()
    with open("solve.py", "w") as f:
        f.write(template)
    print("Generated solve.py")
