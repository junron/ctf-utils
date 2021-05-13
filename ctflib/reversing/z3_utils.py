import random

import z3


class Array:
    def __init__(self, elements, not_found=random.randint(0, 100), _type=None):
        self.elements = elements
        self.not_found = not_found
        self.cache = {}
        self.i = 0
        if _type is not None:
            self.type = _type
        else:
            t0 = type(elements[0])
            for x in elements:
                assert type(x) is t0, f"Element {x} must have type {t0} but has type {type(x)}"
            self.type = t0
        if self.type is str:
            self.not_found = self.__process("not_found" + str(not_found))

    def __process(self, x):
        if self.type is str:
            from z3 import StringVal
            return StringVal(x)
        return x

    def __getitem__(self, x):
        if type(x) is int:
            return self.elements[x]
        if x in self.cache:
            print("hit")
            return self.cache[x]
        from z3 import Or, If
        cond = self.get_cond(0, len(self.elements), x)
        cond = If(Or(x > len(self.elements), x < 0), self.not_found, cond)
        self.cache[x] = cond
        return cond

    def get_cond(self, i, j, x):
        from z3 import If
        arr = self.elements[i:j]
        if len(arr) == 0:
            return self.not_found
        elif len(arr) == 1:
            return self.__process(arr[0])
        mid = (j - i) // 2
        real_mid = mid + i
        return If(x == real_mid, self.__process(arr[mid]), If(x < real_mid, self.get_cond(i, real_mid, x), self.get_cond(real_mid, j, x)))

    def __next__(self):
        if self.i == len(self.elements):
            raise StopIteration()
        x = self.elements[self.i]
        self.i += 1
        return x

    def __iter__(self):
        self.i = 0
        return self

    def __len__(self):
        return len(self.elements)


def indexes(indexer, arr, x):
    def find_all(x, arr):
        out = []
        for i, _x in enumerate(arr):
            if x == _x:
                out.append(i)
        return out

    iss = find_all(x, arr)
    from z3 import Or
    cond = Or(False, False)
    for i in iss:
        cond = Or(cond, indexer == i)
    return cond


def exclude_solution(solver, inputs, outputs):
    from z3 import And, Not
    cond = And(True, True)
    for i, o in zip(inputs, outputs):
        cond = And(cond, i == o)
    solver.add(Not(cond))


def eval_model_ints(solver, inputs):
    if solver.check() == z3.sat:
        m = solver.model()
        return [m.eval(x).as_long().real for x in inputs]


def eval_all_solutions(solver, inputs, limit=-1):
    sols = []
    while solver.check() == z3.sat and len(sols) != limit:
        m = solver.model()
        sol = [m.eval(x).as_long().real for x in inputs]
        sols.append(sol)
        exclude_solution(solver, inputs, sol)
        yield sol
    if len(sols) == 0:
        print("No solution")
