import os
from typing import Optional

from pwnlib.tubes.process import process
from pwnlib.util.fiddling import randoms


class CRand:
    def __init__(self):
        self.code = ""
        self.num_outs = 0
        self.name = ""
    
    # Set seed to string to use variable
    def srand(self, seed: Optional[int|str]=None):
        if seed is None:
            seed = "time(0)"
        self.code += f"srand({seed});\n"
        return self
        
    def rand(self, var: Optional[str]=None):
        if var is None:
            self.code += "printf(\"%d\\n\", rand());\n"
            self.num_outs += 1
        else:
            self.code += f"int {var} = rand();"
        return self
    
    def run(self):
        if len(self.name) == 0:
            code = """
            #include <stdio.h>
            #include <stdlib.h>
            #include <stdbool.h>
            #include <string.h>
            #include <time.h>
            #include <unistd.h>
            #include <sys/time.h>
            #include <sys/types.h>
            
            int main(){
            """ + self.code + "}"
            name = randoms(10)
            with open(f"/tmp/{name}.c", "w") as file:
                file.write(code)
            
            os.system(f"gcc /tmp/{name}.c -o /tmp/{name}")
            self.name = name
        p = process(f"/tmp/{self.name}")
        out = []
        for i in range(self.num_outs):
            out.append(int(p.recvline()))
        return out
